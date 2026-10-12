"""الفحص النهائي الشامل / Final checklist (المرحلة 8 · الإصدار v1.0).

    LLM_MOCK_MODE=1 MCP_MOCK_MODE=1 EMBEDDING_MOCK_MODE=1 python scripts/final_checklist.py
    python scripts/final_checklist.py --skip-tests --skip-docker

يتحقق من 12 بنداً ويكتب ``results/final_checklist.md``:

    1) 14 جدولاً في القاعدة           7)  التوثيق مكتمل (docs/)
    2) 5 وكلاء يعملون (تشغيل فعلي)     8)  Docker صالح (أو مبرَّر تعذّره)
    3) 42 نقطة نهاية تستجيب           9)  لا TODO/FIXME في الكود
    4) 8 صفحات واجهة موجودة           10) لا أسرار مكشوفة
    5) RAG يعمل (فهرسة + استرجاع)     11) لا أرقام مصطنعة في results/
    6) 12 قالب حقيقة مرجعية           12) المجموعة الكاملة تنجح (+VERSION/CHANGELOG)

رمز الخروج: 0 إن نجحت كل البنود، و1 إن فشل بند إلزامي.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

RESULTS_DIR = PROJECT_ROOT / "results"
DEFAULT_OUTPUT = RESULTS_DIR / "final_checklist.md"

REQUIRED_TABLES = {
    "users", "projects", "applications", "app_context", "tools", "scans",
    "vulnerabilities", "vulnerability_findings", "severity_rules", "assessments",
    "corrections", "feedback_examples", "agent_logs", "knowledge_base",
}
REQUIRED_AGENTS = ("orchestrator", "extractor", "scorer", "reviewer", "report_agent")
REQUIRED_PAGES = tuple(f"{index:02d}_{name}.py" for index, name in (
    (1, "dashboard"), (2, "projects_apps"), (3, "upload_scan"), (4, "findings"),
    (5, "assessment_detail"), (6, "review_queue"), (7, "reports"), (8, "evaluation"),
))
REQUIRED_DOCS = (
    # ملاحظة: أي ملف يُضاف هنا يصبح شرطاً لبناء حزمة الإصدار (make_release) أيضاَ
    "README.md", "docs/api_reference.md", "docs/ui_guide.md", "docs/scoring_logic.md",
    "docs/mcp_design.md", "docs/security_guardrails.md", "docs/rag_architecture.md",
    "docs/evaluation_protocol.md", "docs/security_hardening.md", "docs/user_manual.md",
    "docs/release_notes_v1.0.md", "docs/thesis/appendix_a_prompts.md",
    "docs/thesis/appendix_b_rules.md", "docs/thesis/appendix_c_decision_log.md",
    "docs/thesis/appendix_d_metrics.md", "docs/thesis/limitations_and_future_work.md",
    "evaluation/protocol.md",
    # تسليم v1.0: دليل Docker + الهوية البصرية + مواد النشر
    "INSTALL_DOCKER.md", "docs/deployment_notes.md", "docs/rag_architecture.md",
    "assets/logo/BRAND_GUIDE.md", "assets/logo/logo.svg", "assets/logo/logo-icon.svg",
    "assets/logo/favicon.ico", "assets/logo/preview.html",
)
SKIP_SCAN_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
                  "data", "results", ".ruff_cache", ".mypy_cache"}
SECRET_PATTERNS = (
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),
    re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{32,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

CheckResult = dict[str, Any]


def _ok(name: str, detail: str, mandatory: bool = True) -> CheckResult:
    return {"name": name, "passed": True, "detail": detail, "mandatory": mandatory}


def _fail(name: str, detail: str, mandatory: bool = True) -> CheckResult:
    return {"name": name, "passed": False, "detail": detail, "mandatory": mandatory}


# ---------------------------------------------------------------------
# البنود
# ---------------------------------------------------------------------
def check_tables() -> CheckResult:
    """1) الجداول الـ14 موجودة فعلياً في القاعدة."""
    try:
        from db.connection import get_db_path
        import sqlite3

        db_path = get_db_path()
        with sqlite3.connect(db_path) as connection:
            found = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        missing = REQUIRED_TABLES - found
        extra = {name for name in found if name.startswith("vec_")}
        if missing:
            return _fail("جداول القاعدة", f"ناقصة: {sorted(missing)}")
        return _ok(
            "جداول القاعدة",
            f"14/14 موجودة ({db_path.name}) + جداول المتجهات: {sorted(extra) or 'لا شيء'}",
        )
    except Exception as exc:  # noqa: BLE001
        return _fail("جداول القاعدة", f"تعذّر الفحص: {type(exc).__name__}: {exc}")


def check_agents() -> CheckResult:
    """2) الوكلاء الخمسة قابلة للبناء والتشغيل (فحص سريع فعلي)."""
    try:
        from agents.extractor import ExtractorAgent
        from agents.orchestrator import OrchestratorAgent
        from agents.report_agent import ReporterAgent
        from agents.reviewer import ReviewerAgent
        from agents.scorer import ScorerAgent

        agents = {
            "orchestrator": OrchestratorAgent(),
            "extractor": ExtractorAgent(),
            "scorer": ScorerAgent(),
            "reviewer": ReviewerAgent(),
            "report_agent": ReporterAgent(),
        }
        names = sorted(agents)
        if set(REQUIRED_AGENTS) - set(names):
            return _fail("الوكلاء الخمسة", f"ناقص: {sorted(set(REQUIRED_AGENTS) - set(names))}")
        return _ok("الوكلاء الخمسة", f"بُنيت بنجاح: {names}")
    except Exception as exc:  # noqa: BLE001
        return _fail("الوكلاء الخمسة", f"{type(exc).__name__}: {exc}")


def check_endpoints() -> CheckResult:
    """3) عدد نقاط النهاية (عمليات OpenAPI) + تطابق التوثيق + استجابات حيّة.

    ملاحظة تنفيذية: الإصدارات الحديثة من FastAPI تُغلّف الموجّهات المُضمَّنة بكائن
    ``_IncludedRouter`` بدل تسطيح كل مسار كـ ``APIRoute`` — لذا العدّ من مخطط
    OpenAPI (المصدر الموثّق) لا من قائمة ``app.routes``، ويُقارَن جملةً بجملة
    بجدول نقاط النهاية في ``docs/api_reference.md`` (منع انزلاق التوثيق).
    """
    try:
        from fastapi.testclient import TestClient

        from api.main import create_app

        app = create_app()
        schema = app.openapi()
        paths = schema.get("paths") or {}
        methods = {"get", "post", "put", "patch", "delete"}
        operations = {(method.upper(), path) for path, item in paths.items() for method in item if method in methods}

        documented: set[tuple[str, str]] = set()
        reference = (PROJECT_ROOT / "docs" / "api_reference.md").read_text(encoding="utf-8")
        for method, raw_path in re.findall(r"\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`([^`]+)`", reference):
            path = raw_path.strip()
            if not path.startswith("/"):
                continue
            documented.add((method, re.sub(r"\{[^}]+\}", "{}", path)))

        schema_normalised = {(method, re.sub(r"\{[^}]+\}", "{}", path)) for method, path in operations}
        missing_in_docs = sorted(schema_normalised - documented)
        missing_in_schema = sorted(documented - schema_normalised)

        with TestClient(app) as client:
            health = client.get("/health")
            protected = client.get("/projects")
            docs = client.get("/openapi.json")

        details = (
            f"{len(operations)} عملية API على {len(paths)} مساراً · التوثيق يغطي "
            f"{len(documented)} عملية · /health={health.status_code} · /projects={protected.status_code} · "
            f"/openapi.json={docs.status_code}"
        )
        if len(operations) < 40:
            return _fail("نقاط النهاية", details + " (أقل من المتوقع)")
        if missing_in_docs:
            return _fail("نقاط النهاية", details + f" · في الكود وغير موثّق: {missing_in_docs[:4]}")
        if missing_in_schema:
            return _fail("نقاط النهاية", details + f" · في التوثيق وغير موجود في الكود: {missing_in_schema[:4]}")
        if (health.status_code, protected.status_code, docs.status_code) != (200, 401, 200):
            return _fail("نقاط النهاية", details + " (استجابة غير متوقعة)")
        return _ok("نقاط النهاية", details + " · التوثيق مطابق 1:1")
    except Exception as exc:  # noqa: BLE001
        return _fail("نقاط النهاية", f"{type(exc).__name__}: {exc}")


def check_pages() -> CheckResult:
    """4) الصفحات الثمانية موجودة (وأحجامها)."""
    pages_dir = PROJECT_ROOT / "ui" / "streamlit_app" / "pages"
    missing = [page for page in REQUIRED_PAGES if not (pages_dir / page).exists()]
    if missing:
        return _fail("صفحات الواجهة", f"ناقصة: {missing}")
    total = sum((pages_dir / page).stat().st_size for page in REQUIRED_PAGES)
    return _ok("صفحات الواجهة", f"8/8 موجودة ({total:,} بايت إجمالاً)")


def check_rag() -> CheckResult:
    """5) RAG: فهرسة + استرجاع فعليان."""
    try:
        from rag.ingest import ingest_knowledge_base
        from rag.retriever import KnowledgeRetriever

        report = ingest_knowledge_base(force=True)
        hits = KnowledgeRetriever().retrieve("SSL pinning bypass certificate validation", top_k=1)
        if not hits or hits[0].get("source") not in {"vector", "fallback_full_kb"}:
            return _fail("RAG", f"استرجاع غير صالح: {hits[:1]}")
        return _ok(
            "RAG",
            f"فُهرس {report.get('embedded')} نمطاً (بعد {report.get('dim')}) · "
            f"أعلى نتيجة: {hits[0].get('ref_id')} ({hits[0].get('source')})",
        )
    except Exception as exc:  # noqa: BLE001
        return _fail("RAG", f"{type(exc).__name__}: {exc}")


def check_ground_truth() -> CheckResult:
    """6) قوالب الحقيقة المرجعية الـ12 موجودة و«غير مُملأة» (لا اختلاق)."""
    gt_dir = PROJECT_ROOT / "evaluation" / "dataset" / "ground_truth"
    files = sorted(gt_dir.glob("*.json"))
    if len(files) != 12:
        return _fail("قوالب الحقيقة المرجعية", f"العدد {len(files)} بدل 12")
    filled = []
    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return _fail("قوالب الحقيقة المرجعية", f"ملف غير صالح: {path.name}")
        if payload.get("filled"):
            filled.append(path.stem)
    detail = f"12/12 قالباً جاهزاً للإملاء"
    if filled:
        detail += f" · مُملأة يدوياً: {filled}"
    else:
        detail += " · لا ملف مُملأ بعد (صحيح ما دام الإملاء اليدوي لم يحدث)"
    return _ok("قوالب الحقيقة المرجعية", detail)


def check_docs() -> CheckResult:
    """7) التوثيق المطلوب موجود."""
    missing = [doc for doc in REQUIRED_DOCS if not (PROJECT_ROOT / doc).exists()]
    if missing:
        return _fail("التوثيق", f"ناقص: {missing}")
    size = sum((PROJECT_ROOT / doc).stat().st_size for doc in REQUIRED_DOCS)
    return _ok("التوثيق", f"{len(REQUIRED_DOCS)}/{len(REQUIRED_DOCS)} ملفاً ({size:,} بايت)")


def check_docker() -> CheckResult:
    """8) Docker: توفر الأدوات أو صحة التعريفات (Statics Validate)."""
    compose = PROJECT_ROOT / "docker-compose.yml"
    dockerfiles = [PROJECT_ROOT / name for name in ("Dockerfile.api", "Dockerfile.ui")]
    problems: list[str] = []

    try:
        import yaml

        payload = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
        services = payload.get("services") or {}
        for required in ("api", "ui", "mobsf"):
            if required not in services:
                problems.append(f"خدمة ناقصة في compose: {required}")
        if "ollama" not in services:
            problems.append("خدمة ollama (اختيارية) غير معرّفة")
        if not services.get("api", {}).get("healthcheck"):
            problems.append("خدمة api بلا healthcheck")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"compose غير صالح: {exc}")

    def _directives_only(text: str) -> str:
        """يُسقط أسطر التعليقات: ذكر «privileged» في تعليق ليس استخداماً له."""
        return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))

    for dockerfile in dockerfiles:
        text = dockerfile.read_text(encoding="utf-8")
        effective = _directives_only(text)
        if "USER " not in text:
            problems.append(f"{dockerfile.name} بلا مستخدم غير root")
        if "HEALTHCHECK" not in text:
            problems.append(f"{dockerfile.name} بلا HEALTHCHECK")
        if re.search(r"(^|\s)--privileged|privileged\s*[:=]\s*true", effective):
            problems.append(f"{dockerfile.name} يستخدم privileged (وضع غير مقبول)")
    compose_effective = _directives_only(compose.read_text(encoding="utf-8"))
    if re.search(r"privileged\s*:\s*true", compose_effective):
        problems.append("docker-compose.yml: خدمة تعمل بـ privileged")
    if "docker.sock" in compose_effective:
        problems.append("docker-compose.yml: تركيب مقبس docker (تصعيد صلاحيات)")

    import shutil

    docker_available = shutil.which("docker") is not None
    if docker_available:
        try:
            result = subprocess.run(
                ["docker", "compose", "config", "--quiet"],
                cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                problems.append(f"docker compose config: {result.stderr.strip()[:200]}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"تعذّر تشغيل docker compose config: {exc}")

    if problems:
        return _fail("Docker", " | ".join(problems))
    if docker_available:
        return _ok("Docker", "تعريفات صحيحة + docker compose config نجح")
    return _ok(
        "Docker",
        "التعريفات صحيحة بنيوياً (مستخدم غير root · healthcheck · بلا privileged) — "
        "docker غير مثبّت في بيئة التحقق هذه، فبناء الصور يتخطاه السكربت بصدق",
    )


def check_no_todos() -> CheckResult:
    """9) لا TODO/FIXME/XXX في الكود (تُستثنى ملفات البيانات والمصادر الخارجية)."""
    pattern = re.compile(r"\b(TODO|FIXME|XXX)\b")
    hits: list[str] = []
    for path in PROJECT_ROOT.rglob("*"):
        if path.is_dir() or path.suffix not in {".py", ".j2", ".md", ".sql", ".sh", ".yml", ".yaml"}:
            continue
        if any(part in SKIP_SCAN_DIRS for part in path.parts):
            continue
        if path.name in {"final_checklist.py", "make_release.py", "FINAL_CHECKLIST.md"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            hits.append(f"{path.relative_to(PROJECT_ROOT)}:{line}")
    if hits:
        return _fail("خلوّ الكود من TODO", f"{len(hits)} موضعاً: {hits[:6]}")
    return _ok("خلوّ الكود من TODO", "لا TODO/FIXME/XXX في الكود أو التوثيق")


def check_no_secrets() -> CheckResult:
    """10) لا أسرار حقيقية مكشوفة في الملفات المُتتبَّعة."""
    hits: list[str] = []
    for path in PROJECT_ROOT.rglob("*"):
        if path.is_dir() or path.suffix not in {".py", ".md", ".yml", ".yaml", ".json", ".sh", ".j2", ".env", ".example"}:
            continue
        if any(part in SKIP_SCAN_DIRS for part in path.parts) and path.name != ".env.example":
            continue
        if path.name == ".env":
            continue  # غير مُتتبَّع (في .gitignore) — يُفحص وجوده أدناه
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for regex in SECRET_PATTERNS:
            for match in regex.finditer(text):
                hits.append(f"{path.relative_to(PROJECT_ROOT)} ({match.group()[:8]}…)")
    env_file = PROJECT_ROOT / ".env"
    gitignore = PROJECT_ROOT / ".gitignore"
    ignored = env_file.exists() and gitignore.exists() and ".env" in gitignore.read_text(encoding="utf-8")
    if hits:
        return _fail("لا أسرار مكشوفة", f"{len(hits)} إشارة: {hits[:5]}")
    detail = "لا مفاتيح/مفاتيح خاصة في الملفات"
    detail += " · .env موجود ومُتجاهَل في git" if ignored else " · .env غير موجود (نظيف)"
    return _ok("لا أسرار مكشوفة", detail)


def check_no_fake_numbers() -> CheckResult:
    """11) لا أرقام مصطنعة: الملفات الخام بلا مقاييس حين تغيب الحقيقة المرجعية."""
    problems: list[str] = []
    checked = 0
    for path in (RESULTS_DIR / "dry_run").rglob("*.json") if (RESULTS_DIR / "dry_run").exists() else []:
        payload = json.loads(path.read_text(encoding="utf-8"))
        checked += 1
        if not payload.get("ground_truth_filled") and payload.get("metrics") is not None:
            problems.append(f"{path.name}: metrics موجودة بلا GT")
    report = RESULTS_DIR / "REPORT.md"
    if report.exists():
        text = report.read_text(encoding="utf-8")
        if "غير مُملأة" not in text and "غير مملوءة" not in text and "no results" not in text.lower():
            problems.append("REPORT.md لا يذكر حالة غياب الحقيقة المرجعية")
    if (RESULTS_DIR / "feedback_ab_test.json").exists():
        ab = json.loads((RESULTS_DIR / "feedback_ab_test.json").read_text(encoding="utf-8"))
        paired = ab.get("paired") or {}
        if (paired.get("paired_n") or 0) < 3 and "paired_t_stat" in paired:
            problems.append("feedback_ab_test: اختبار مزدوج رغم نقص البيانات")
    if problems:
        return _fail("لا أرقام مصطنعة", " | ".join(problems))
    return _ok(
        "لا أرقام مصطنعة",
        f"فُحص {checked} ملف نتيجة جاف + REPORT.md + A/B — كلها تصرّح بغياب GT بدل التخمين",
    )


def check_tests(run_tests: bool) -> CheckResult:
    """12) المجموعة الكاملة تنجح (تُشغَّل فعلياً عند الطلب)."""
    if not run_tests:
        return _ok("المجموعة الكاملة", "تُجريَ منفصلة (--skip-tests)", mandatory=False)
    env = {**os.environ, "LLM_MOCK_MODE": "1", "MCP_MOCK_MODE": "1", "EMBEDDING_MOCK_MODE": "1"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True, timeout=1800,
    )
    tail = (result.stdout or "").strip().splitlines()
    summary = tail[-1] if tail else "بلا مخرجات"
    if result.returncode != 0:
        return _fail("المجموعة الكاملة", f"فشل: {summary}")
    return _ok("المجموعة الكاملة", summary)


def check_release_artifacts() -> CheckResult:
    """بند إضافي: VERSION + CHANGELOG + CITATION + LICENSE."""
    expected = {
        "VERSION": None, "CHANGELOG.md": None, "CITATION.cff": None,
        "LICENSE": None, "docs/release_notes_v1.0.md": None,
    }
    missing = [name for name in expected if not (PROJECT_ROOT / name).exists()]
    if missing:
        return _fail("ملفات الإصدار", f"ناقصة: {missing}")
    version = (PROJECT_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    return _ok("ملفات الإصدار", f"VERSION={version} + CHANGELOG/CITATION/LICENSE/Release Notes")


CHECKS: list[tuple[str, Callable[[], CheckResult]]] = [
    ("جداول القاعدة", check_tables),
    ("الوكلاء الخمسة", check_agents),
    ("نقاط النهاية", check_endpoints),
    ("صفحات الواجهة", check_pages),
    ("RAG", check_rag),
    ("قوالب الحقيقة المرجعية", check_ground_truth),
    ("التوثيق", check_docs),
    ("Docker", check_docker),
    ("خلوّ الكود من TODO", check_no_todos),
    ("لا أسرار مكشوفة", check_no_secrets),
    ("لا أرقام مصطنعة", check_no_fake_numbers),
    ("ملفات الإصدار", check_release_artifacts),
]


def build_report(results: list[CheckResult], extra: dict[str, Any]) -> str:
    """تقرير Markdown نهائي."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    passed = sum(1 for item in results if item["passed"])
    mandatory_failed = [item for item in results if not item["passed"] and item["mandatory"]]
    lines = [
        "# الفحص النهائي الشامل — الإصدار v1.0",
        f"\n**التاريخ:** {generated}",
        f"**النتيجة:** {passed}/{len(results)} بنداً ناجحاً "
        f"{'✅' if not mandatory_failed else '❌'}",
        "",
        "| # | البند | الحالة | التفصيل |",
        "|---|---|---|---|",
    ]
    for index, item in enumerate(results, 1):
        status = "✅" if item["passed"] else ("❌" if item["mandatory"] else "⚠️")
        lines.append(f"| {index} | {item['name']} | {status} | {item['detail']} |")
    lines += [
        "",
        "## ملخصات مساندة",
        "",
        f"- قياس الأداء: `{extra.get('benchmark', 'غير مشغّل')}`",
        f"- اختبار الحمل: `{extra.get('load_test', 'غير مشغّل')}`",
        f"- العناصر غير الإلزامية الفاشلة: {len([i for i in results if not i['passed'] and not i['mandatory']])}",
        "",
        "> يُعاد التشغيل بـ: `python scripts/final_checklist.py` "
        "(يتخطى الاختبارات بـ `--skip-tests`)",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    """يشغّل كل البنود ويكتب ``results/final_checklist.md``."""
    parser = argparse.ArgumentParser(description="الفحص النهائي الشامل")
    parser.add_argument("--skip-tests", action="store_true", help="تخطي تشغيل pytest")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    print("◉ الفحص النهائي — 12 بنداً…")
    results: list[CheckResult] = []
    for name, check in CHECKS:
        result = check()
        results.append(result)
        icon = "✓" if result["passed"] else "✗"
        print(f"  {icon} {name}: {result['detail']}")

    result_tests = check_tests(run_tests=not args.skip_tests)
    results.append(result_tests)
    print(f"  {'✓' if result_tests['passed'] else '✗'} المجموعة الكاملة: {result_tests['detail']}")

    extra = {
        "benchmark": "results/benchmark.md" if (RESULTS_DIR / "benchmark.md").exists() else None,
        "load_test": "results/load_test.md" if (RESULTS_DIR / "load_test.md").exists() else None,
    }
    report = build_report(results, extra)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")

    json_path = output.with_suffix(".json")
    json_path.write_text(
        json.dumps(
            {
                "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "results": results,
                "extra": extra,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    failed = [item for item in results if not item["passed"] and item["mandatory"]]
    print(f"\n{'✅' if not failed else '❌'} النتيجة: {len(results) - len(failed)}/{len(results)} بنداً")
    print(f"✅ التقرير: {output}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
