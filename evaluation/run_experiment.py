"""سكربت التجربة الرئيسي / Main experiment runner (المرحلة 7).

    python evaluation/run_experiment.py --mode full --apps diva,insecurebankv2 --output results/
    python evaluation/run_experiment.py --mode full --apps diva --dry-run   # Mock كامل

الأوضاع: full | scorer_only | no_rag | no_feedback (أعلام الحالة — تقريرها في state).
لكل (وضع، تطبيق): يضمن كيانات القاعدة (مشروع/تطبيق/سياق/فحص)، يشغّل خط الأنابيب
عبر build_scan_graph، ويحفظ JSON خاماً في <output>/<mode>/<app_id>.json —
بلا أي مقاييس مشتقة (التحليل حصراً في analyze_results.py).

★ لا اختراع نتائج: إن لم تُملأ الحقيقة المرجعية ⇒ metrics = null مع سبب صريح.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import yaml  # noqa: E402

DATASET_PATH = PROJECT_ROOT / "evaluation" / "dataset" / "apps.yaml"
GT_DIR = PROJECT_ROOT / "evaluation" / "dataset" / "ground_truth"
APKS_DIR = PROJECT_ROOT / "data" / "apks"
DEFAULT_OUTPUT = PROJECT_ROOT / "results"

MODES = ("full", "scorer_only", "no_rag", "no_feedback")
MODE_FLAGS: dict[str, dict[str, bool]] = {
    "full": {},
    "scorer_only": {"scorer_only": True},
    "no_rag": {"disable_rag": True},
    "no_feedback": {"disable_feedback": True},
}


# ---------------------------------------------------------------------
# أدوات مساعدة
# ---------------------------------------------------------------------
def load_apps() -> list[dict[str, Any]]:
    """قراءة قائمة التطبيقات من dataset/apps.yaml."""
    payload = yaml.safe_load(DATASET_PATH.read_text(encoding="utf-8")) or {}
    return list(payload.get("apps") or [])


def select_apps(apps: list[dict[str, Any]], requested: Optional[str]) -> list[dict[str, Any]]:
    """انتقاء التطبيقات: --apps a,b أو الكل."""
    if not requested:
        return apps
    wanted = {token.strip() for token in requested.split(",") if token.strip()}
    known = {app["id"] for app in apps}
    unknown = wanted - known
    if unknown:
        raise SystemExit(f"✗ تطبيقات غير معروفة في apps.yaml: {sorted(unknown)}")
    return [app for app in apps if app["id"] in wanted]


def _apk_path_for(app: dict[str, Any]) -> tuple[str, bool]:
    """مسار APK المتوقع + هل الملف موجود فعلاً (وضع Mock لا يقرأ الملف)."""
    candidate = APKS_DIR / str(app.get("apk_file") or f"{app['id']}.apk")
    return (str(candidate), candidate.exists())


def _ensure_entities(app: dict[str, Any]) -> dict[str, int]:
    """يضمن مشروع/تطبيق/سياق/فحص للتطبيق — idempotent عبر sha256 اصطناعي ثابت."""
    from db.connection import get_session
    from db.models import AppContext
    from db.repositories import applications_repo, projects_repo, scans_repo
    from sqlalchemy import select

    projects = [p for p in projects_repo.list_all() if p["name"] == "evaluation"]
    project = projects[0] if projects else projects_repo.create(
        name="evaluation", description="مشروع تجربة القياس (المرحلة 7)"
    )

    sha256 = hashlib.sha256(f"eval:{app['id']}".encode()).hexdigest()
    application = applications_repo.get_by_sha256(sha256)
    if application is None:
        apk_path, _exists = _apk_path_for(app)
        application = applications_repo.create(
            project_id=project["id"],
            name=app["name"],
            sha256=sha256,
            file_path=apk_path,
            package_name=app.get("package_name"),
            version=None,
            file_size=None,
            app_category=app.get("category"),
        )

    context = app.get("context") or {}
    if context:
        with get_session() as session:
            row = session.scalar(
                select(AppContext).where(AppContext.application_id == application["id"])
            )
            if row is None:
                row = AppContext(application_id=application["id"])
                session.add(row)
            row.data_sensitivity = context.get("data_sensitivity")
            row.industry = context.get("industry")
            row.user_base_size = context.get("user_base_size")
            row.internet_facing = context.get("internet_facing")
            row.business_criticality = context.get("business_criticality")

    from db.models import SeverityRule

    with get_session() as session:
        rule = session.scalar(select(SeverityRule).where(SeverityRule.active.is_(True)))
        rule_version = rule.version if rule else None

    scan = scans_repo.create(
        application_id=application["id"], rule_version=rule_version, status="pending"
    )
    return {"project_id": project["id"], "application_id": application["id"], "scan_id": scan["id"]}


def load_ground_truth(app_id: str) -> dict[str, Any]:
    """حقيقة مرجعية إن وُجدت ومُملأة."""
    path = GT_DIR / f"{app_id}.json"
    if not path.exists():
        return {"filled": False, "vulnerabilities": [], "note": "ملف GT غير موجود"}
    payload = json.loads(path.read_text(encoding="utf-8"))
    filled = bool(payload.get("filled")) and bool(payload.get("vulnerabilities"))
    return {"filled": filled, "vulnerabilities": payload.get("vulnerabilities") or []}


def match_pairs(
    system_vulns: list[dict[str, Any]], gt_vulns: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """مطابقة النظام↔الخبير (CWE ثم العنوان المطبَّع) — قاعدة §4 في protocol.md."""
    import re

    def norm_title(text: str | None) -> str:
        return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()

    gt_used: set[int] = set()
    matched: list[dict[str, Any]] = []
    false_positives: list[dict[str, Any]] = []
    for vuln in system_vulns:
        chosen = None
        for index, gt in enumerate(gt_vulns):
            if index in gt_used:
                continue
            if vuln.get("cwe_id") and gt.get("cwe_id") and vuln["cwe_id"] == gt["cwe_id"]:
                chosen = index
                break
        if chosen is None:
            for index, gt in enumerate(gt_vulns):
                if index in gt_used:
                    continue
                if norm_title(vuln.get("title")) and norm_title(vuln.get("title")) == norm_title(
                    gt.get("title")
                ):
                    chosen = index
                    break
        if chosen is None:
            false_positives.append(vuln)
        else:
            gt_used.add(chosen)
            matched.append({"system": vuln, "ground_truth": gt_vulns[chosen]})
    false_negatives = [gt for index, gt in enumerate(gt_vulns) if index not in gt_used]
    return matched, false_positives, false_negatives


def run_single_app(app: dict[str, Any], mode: str, output_dir: Path) -> dict[str, Any]:
    """يشغّل خط الأنابيب لتطبيق واحد ويحفظ JSON الخام."""
    from agents.graph import ainvoke_pipeline, build_scan_graph
    from agents.state import ScanState

    entities = _ensure_entities(app)
    apk_path, apk_exists = _apk_path_for(app)
    state = ScanState(
        scan_id=f"exp_{mode}_{app['id']}",
        application_id=entities["application_id"],
        apk_path=apk_path,
        package_name=app.get("package_name") or "unknown.package",
        app_category=app.get("category") or "unknown",
        db_scan_id=entities["scan_id"],
        user_request=f"فحص تجربة القياس ({mode}) للتطبيق {app['name']}",
        **MODE_FLAGS[mode],
    )

    async def _run() -> dict[str, Any]:
        """بناء الرسم داخل حلقة الأحداث — AsyncSqliteSaver يشترط loop قائماً."""
        graph = build_scan_graph()
        return await ainvoke_pipeline(graph, state)

    started = time.monotonic()
    result = asyncio.run(_run())
    duration_ms = int((time.monotonic() - started) * 1000)

    vulnerabilities = list(result.get("vulnerabilities") or [])
    assessments = {a.get("dedup_fingerprint"): a for a in (result.get("assessments") or [])}

    vuln_rows: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        assessment = assessments.get(vuln.get("dedup_fingerprint")) or {}
        vuln_rows.append(
            {
                "title": vuln.get("title"),
                "cwe_id": vuln.get("cwe_id"),
                "masvs_category": vuln.get("masvs_category"),
                "discovered_by": vuln.get("discovered_by"),
                "is_confirmed": bool(vuln.get("is_confirmed")),
                "retrieved_patterns": vuln.get("retrieved_patterns") or [],
                "severity": assessment.get("final_severity")
                or assessment.get("severity"),
                "final_score": assessment.get("final_score"),
                "confidence_factor": assessment.get("confidence_factor"),
                "requires_human_review": assessment.get("requires_human_review"),
            }
        )

    ground_truth = load_ground_truth(app["id"])
    metrics: Optional[dict[str, Any]] = None
    notes: list[str] = []
    if not ground_truth["filled"]:
        notes.append(
            "الحقيقة المرجعية غير مُملأة — metrics=null (شغّل الإملاء اليدوي ثم analyze_results)"
        )
    else:
        from evaluation.metrics import (  # noqa: PLC0415 — استيراد كسول لتفادي ثقل scipy عند الوضع الجاف
            bootstrap_ci,
            confusion_matrix,
            gwet_ac1,
            percent_agreement,
            precision_recall_f1,
            weighted_cohens_kappa,
        )

        matched, false_positives, false_negatives = match_pairs(
            vulnerabilities, ground_truth["vulnerabilities"]
        )
        detection = precision_recall_f1(
            tp=len(matched), fp=len(false_positives), fn=len(false_negatives)
        )
        system_sev = [
            (assessments.get(row["system"].get("dedup_fingerprint")) or {}).get(
                "final_severity"
            )
            or (assessments.get(row["system"].get("dedup_fingerprint")) or {}).get("severity")
            for row in matched
        ]
        expert_sev = [row["ground_truth"].get("severity_expert") for row in matched]
        pairs = list(zip([s for s in system_sev], [e for e in expert_sev], strict=True))
        valid_pairs = [(a, b) for a, b in pairs if a in {"Critical", "High", "Medium", "Low"}
                       and b in {"Critical", "High", "Medium", "Low"}]
        if valid_pairs:
            left = [a for a, _ in valid_pairs]
            right = [b for _, b in valid_pairs]
            agreement = {
                "percent_agreement": percent_agreement(left, right),
                "weighted_kappa": weighted_cohens_kappa(left, right),
                "gwet_ac1": gwet_ac1(left, right),
                "confusion_matrix": confusion_matrix(left, right).tolist(),
                "categories": ["Low", "Medium", "High", "Critical"],
                "n_pairs": len(valid_pairs),
            }
            ci = {
                "weighted_kappa_ci95": bootstrap_ci(
                    valid_pairs, lambda sample: weighted_cohens_kappa(
                        [a for a, _ in sample], [b for _, b in sample]
                    )
                ),
                "gwet_ac1_ci95": bootstrap_ci(
                    valid_pairs,
                    lambda sample: gwet_ac1([a for a, _ in sample], [b for _, b in sample]),
                ),
                "percent_agreement_ci95": bootstrap_ci(
                    valid_pairs,
                    lambda sample: percent_agreement(
                        [a for a, _ in sample], [b for _, b in sample]
                    ),
                ),
            }
        else:
            agreement = {"note": "لا أزواج صالحة للمقارنة الفئوية"}
            ci = {}
        metrics = {
            "detection": detection,
            "agreement": agreement,
            "ci": ci,
            "matched_samples": len(matched),
            # الأزواج الخام (نظام، خبير) — تُجمَّع في analyze_results للاتفاق المجمّع
            "matched_pairs": [[a, b] for a, b in valid_pairs],
        }

    payload = {
        "app_id": app["id"],
        "app_name": app["name"],
        "mode": mode,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "application_id": entities["application_id"],
        "scan_id": entities["scan_id"],
        "apk_path": apk_path,
        "apk_file_present": apk_exists,
        "pipeline_stage": result.get("current_stage"),
        "duration_ms": duration_ms,
        "counts": {
            "vulnerabilities": len(vulnerabilities),
            "assessments": len(result.get("assessments") or []),
            "tool_calls": len(result.get("tools_executed") or []),
            "errors": len(result.get("errors") or []),
        },
        "ground_truth_filled": ground_truth["filled"],
        "metrics": metrics,
        "vulnerabilities": vuln_rows,
        "notes": notes,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{app['id']}.json"
    output_file.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


# ---------------------------------------------------------------------
# نقطة الدخول
# ---------------------------------------------------------------------
def main() -> None:
    """CLI التجربة — يعرض ملخصاً لكل تطبيق ويحفظ الخام."""
    parser = argparse.ArgumentParser(description="تجربة قياس النظام (Kappa/AC1/A-B)")
    parser.add_argument("--mode", choices=MODES, default="full")
    parser.add_argument("--apps", default=None, help="قائمة مفصولة بفواصل (افتراضي: الكل)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--dry-run", action="store_true", help="Mock كامل + مخرجات dry_run")
    args = parser.parse_args()

    if args.dry_run:
        os.environ["LLM_MOCK_MODE"] = "1"
        os.environ["MCP_MOCK_MODE"] = "1"
        os.environ["EMBEDDING_MOCK_MODE"] = "1"
        print("◉ DRY-RUN: Mock كامل (LLM/MCP/Embeddings) — سباكة فقط بلا نتائج حقيقية")

    apps = select_apps(load_apps(), args.apps)
    if not apps:
        raise SystemExit("✗ لا تطبيقات محددة")

    base_output = Path(args.output)
    # التشغيل الجاف في شجرة منفصلة لكل وضع: results/dry_run/<mode>/ (والحقيقي results/<mode>/)
    target_dir = base_output / "dry_run" / args.mode if args.dry_run else base_output / args.mode

    print(f"◉ الوضع: {'dry_run' if args.dry_run else args.mode} | التطبيقات: {[a['id'] for a in apps]}")
    summaries = []
    for app in apps:
        payload = run_single_app(app, args.mode, target_dir)
        counts = payload["counts"]
        metrics_text = "—" if payload["metrics"] is None else "محسوبة"
        print(
            f"  ✓ {app['id']:<24} stage={payload['pipeline_stage']:<8} "
            f"vulns={counts['vulnerabilities']:<3} assessments={counts['assessments']:<3} "
            f"errors={counts['errors']} metrics={metrics_text} "
            f"({payload['duration_ms']}ms)"
        )
        summaries.append(payload)

    print(f"\n✅ حُفظت النتائج الخام في: {target_dir} ({len(summaries)} ملف)")
    if not any(p["ground_truth_filled"] for p in summaries):
        print("⚠️  الحقيقة المرجعية غير مُملأة — المقاييس ستكون null حتى الإملاء اليدوي")
    print("التحليل: python evaluation/analyze_results.py --input results/")


if __name__ == "__main__":
    main()
