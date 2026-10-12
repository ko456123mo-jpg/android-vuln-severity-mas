"""اختبار تكامل الـ Pipeline الكامل — 4 وكلاء (المرحلة 4).

المسار: orchestrator → static/dynamic tools → extractor → scorer → reviewer → finalize
مع Mock IPC + Mock LLM + قاعدة اختبار معزولة، ويتحقق من:
    1. اكتمال المسار وانتاج 9 تقييمات لـ 9 ثغرات
    2. توزيع الفئات المحسوب يدوياً {Critical:2, High:5, Medium:2, Low:0}
    3. سلامة المعادلة على كل صف في assessments: |b×0.6+c×0.2+e×0.2 − final| < 0.01
    4. معايير requires_human_review الثلاثة (حتمياً — predicate-level)
    5. تسجيل scorer/reviewer في agent_logs
    6. idempotency: إعادة التشغيل لا تضاعف assessments (upsert_by_vuln)

ملاحظة الأرقام: قيم الفئات (severity) مثبتة بثقة لأنها مشتقة حتمياً من
معادلة v1.1 مع سياق مصرفي وبذور الأدوات — حُسِبت يدوياً وتطابق مخرجات المحرك.
الأرقام العشرية الدقيقة تُختبر بالتفاوت (≈ 0.02) تسامحاً مع أي تنعيم مستقبلي.
"""
from __future__ import annotations

import os

os.environ["MCP_MOCK_MODE"] = "1"
os.environ["LLM_MOCK_MODE"] = "1"

import asyncio  # noqa: E402
import json  # noqa: E402
import uuid  # noqa: E402

import pytest  # noqa: E402

from agents.graph import ainvoke_pipeline, build_scan_graph  # noqa: E402
from agents.state import ScanState  # noqa: E402
from core.scoring.bands import distance_to_band_edge  # noqa: E402
from db.connection import get_session  # noqa: E402
from db.models import AppContext, Vulnerability  # noqa: E402
from db.repositories import (  # noqa: E402
    applications_repo,
    assessments_repo,
    findings_repo,
    logs_repo,
    projects_repo,
    scans_repo,
)
from sqlalchemy import select  # noqa: E402

# التوزيع المتوقع المحسوب يدوياً لسياق مصرفي (HIGH/large/True/HIGH → context=10)
EXPECTED_SEVERITY_BY_CWE = {
    "CWE-321": "Critical",
    "CWE-327": "Critical",
    "CWE-926": "High",
    "CWE-312": "High",
    "CWE-295": "High",
    "CWE-287": "High",
    "CWE-319": "High",
    "CWE-919": "Medium",
    "CWE-532": "Medium",
}
EXPECTED_DISTRIBUTION = {"Critical": 2, "High": 5, "Medium": 2, "Low": 0}


def _make_entities() -> dict:
    project = projects_repo.create(name=f"full-{uuid.uuid4().hex[:6]}")
    app = applications_repo.create(
        project_id=project["id"],
        name="InsecureBank",
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        file_path="/data/apks/insecurebank.apk",
        package_name="com.insecurebank.app",
        version="2.1.0",
        app_category="banking",
    )
    # سياق مصرفي كامل — يغذي context_score عبر ScorerAgent
    with get_session() as session:
        session.add(
            AppContext(
                application_id=app["id"],
                data_sensitivity="HIGH",
                industry="banking",
                user_base_size="large",
                internet_facing=True,
                business_criticality="HIGH",
            )
        )
    scan = scans_repo.create_scan(application_id=app["id"])
    return {"project": project, "app": app, "scan": scan}


def _make_state(entities: dict) -> ScanState:
    return ScanState(
        scan_id=f"scan_{entities['scan']['id']:03d}_{uuid.uuid4().hex[:4]}",
        application_id=entities["app"]["id"],
        apk_path="/data/apks/insecurebank.apk",
        package_name="com.insecurebank.app",
        app_category="banking",
        user_request="",
        db_scan_id=entities["scan"]["id"],
    )


async def _run_full_pipeline(state: ScanState, checkpoints: str) -> dict:
    graph = build_scan_graph(checkpoints_path=checkpoints)
    return await ainvoke_pipeline(graph, state)


def _assessments_for_app(application_id: int) -> list[dict]:
    """كل تقييمات ثغرات التطبيق (بربط vulnerabilities.assessment)."""
    with get_session() as session:
        vulns = session.scalars(
            select(Vulnerability).where(Vulnerability.application_id == application_id)
        ).all()
        rows = []
        for vuln in vulns:
            record = assessments_repo.get_by_vuln(vuln.id)
            if record is not None:
                rows.append({**record, "cwe_id": vuln.cwe_id, "vuln_id": vuln.id})
        return rows


class TestFullFourAgentPipeline:
    """المسار الكامل مع التقييم والمراجعة."""

    def test_end_to_end_scoring_and_review(self, tmp_path):
        entities = _make_entities()
        state = _make_state(entities)
        result = asyncio.run(_run_full_pipeline(state, str(tmp_path / "cp_full.db")))

        # 1) اكتمال الحالة / State completion
        assert result["current_stage"] == "done"
        assert len(result["vulnerabilities"]) == 9
        assert len(result["assessments"]) == 9
        fps = {a["dedup_fingerprint"] for a in result["assessments"]}
        assert len(fps) == 9  # تقييم واحد لكل ثغرة

        # 2) توزيع الفئات / Severity distribution (hand-verified)
        stored = _assessments_for_app(entities["app"]["id"])
        assert len(stored) == 9
        per_cwe = {row["cwe_id"]: row["severity"] for row in stored}
        for cwe, expected in EXPECTED_SEVERITY_BY_CWE.items():
            assert per_cwe[cwe] == expected, f"{cwe}: {per_cwe[cwe]} != {expected}"
        distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for row in stored:
            distribution[row["severity"]] += 1
        assert distribution == EXPECTED_DISTRIBUTION

        # 3) سلامة المعادلة على كل صف / Formula integrity gate
        for row in stored:
            recomputed = (
                row["base_score"] * 0.6
                + row["context_score"] * 0.2
                + row["evidence_score"] * 0.2
            )
            assert abs(recomputed - row["final_score"]) < 0.01, (
                f"{row['cwe_id']}: {recomputed:.4f} != {row['final_score']}"
            )
            assert row["rule_version"] == "v1.1"
            assert row["assessed_by"] == "agent"
            # الأرقام ضمن المجالات التعاقدية
            assert 0.0 <= row["confidence_factor"] <= 1.0
            assert 1.0 <= row["final_score"] <= 10.0

        # 4) معايير التصعيد البشري / Human-review criteria (predicate-level)
        flagged = 0
        for row in stored:
            notes = json.loads(row["review_notes"] or "{}")
            conf = row["confidence_factor"]
            score = row["final_score"]
            engine_sev = notes.get("original_severity", row["severity"])
            predicate_required = (
                conf < 0.75
                or distance_to_band_edge(score) <= 0.5
                or (engine_sev == "Critical" and conf < 0.9)
            )
            assert notes.get("requires_human_review") == predicate_required, (
                f"{row['cwe_id']}: flag={notes.get('requires_human_review')} "
                f"لكن المعايير تقول {predicate_required}"
            )
            if predicate_required:
                flagged += 1
        assert flagged >= 3

        # لا تعديلات متوقعة على بيانات الـ mock (لا تناقضات) / no-op review
        for row in stored:
            notes = json.loads(row["review_notes"] or "{}")
            assert notes["reviewed_score"] == pytest.approx(row["final_score"], abs=1e-6)
            assert notes.get("adjustments", []) == []

        # 5) تدقيق الوكلاء / Agent audit logs
        logs = logs_repo.list_by_scan(entities["scan"]["id"])
        names = {l["agent_name"] for l in logs}
        assert {"orchestrator", "extractor", "scorer", "reviewer"} <= names
        scorer_calls = [l for l in logs if l["agent_name"] == "scorer" and l["action"] == "llm_call"]
        reviewer_calls = [l for l in logs if l["agent_name"] == "reviewer" and l["action"] == "llm_call"]
        assert len(scorer_calls) == 9   # استدعاء تفسير لكل ثغرة
        assert len(reviewer_calls) == 9
        assert all(l["status"] == "success" for l in logs)

        # 6) scan نهائي ناجح
        scan_row = scans_repo.get_by_id(entities["scan"]["id"])
        assert scan_row["status"] in {"success", "partial"}  # partial مسموح تحفظاً
        assert scan_row["status"] == "success"

    def test_rerun_idempotent_assessments(self, tmp_path):
        """إعادة تشغيل الـ pipeline لنفس التطبيق: لا مضاعفة للتقييمات."""
        entities = _make_entities()
        first = _make_state(entities)
        asyncio.run(_run_full_pipeline(first, str(tmp_path / "cp_a.db")))
        before = _assessments_for_app(entities["app"]["id"])

        scan2 = scans_repo.create_scan(application_id=entities["app"]["id"])
        second = ScanState(
            scan_id=f"scan_{scan2['id']:03d}_rerun",
            application_id=entities["app"]["id"],
            apk_path="/data/apks/insecurebank.apk",
            package_name="com.insecurebank.app",
            user_request="",
            db_scan_id=scan2["id"],
        )
        asyncio.run(_run_full_pipeline(second, str(tmp_path / "cp_b.db")))
        after = _assessments_for_app(entities["app"]["id"])

        assert len(before) == len(after) == 9
        assert {a["vuln_id"] for a in after} == {a["vuln_id"] for a in before}
        # upsert يحدّث القيم ذاتها (حتمية المحرك)
        for row_after in after:
            row_before = next(r for r in before if r["vuln_id"] == row_after["vuln_id"])
            assert row_after["final_score"] == pytest.approx(row_before["final_score"])
            assert row_after["severity"] == row_before["severity"]
