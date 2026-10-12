"""قياس الأداء / Benchmark (المرحلة 8).

    LLM_MOCK_MODE=1 MCP_MOCK_MODE=1 EMBEDDING_MOCK_MODE=1 python scripts/benchmark.py
    python scripts/benchmark.py --scans 5 --json results/benchmark.json

يقيس  7 محاور ويُخرج ``results/benchmark.md`` + JSON خام:

    1) بدء التشغيل   — إنشاء المخطط + البذر (قاعدة مؤقتة معزولة)
    2) عمليات القاعدة — إدراج دفعي، استعلامات فحص، تجميعات
    3) أدوات MCP     — زمن كل أداة (وضع Mock)
    4) محرك التقييم  — إنتاجية ScoringEngine (ثغرة/ثانية)
    5) مراحل الوكلاء — Orchestrator → Tools → Extractor → Scorer → Reviewer → Reporter
    6) الخط الكامل   — ainvoke_pipeline (E2E) مع عدّاد الرموز التقديري
    7) استرجاع RAG   — زمن ingest/search

★ صدق القياس (موثق في التقرير نفسه):
    • الأرقام في وضع Mock هي **حدود دنيا** (بلا شبكة/نماذج حقيقية).
    • تقدير الرموز = عدد أحرف البرومبت ÷ 4 (تقريب شائع؛ ليس عدّاً حقيقياً).
    • القياس على قاعدة مؤقتة (`BENCHMARK_DATABASE_PATH`) — لا يمس data/app.db.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# قاعدة مؤقتة — تُضبط قبل أي استيراد لطبقة db (التهيئة كسولة على أول استخدام)
_BENCH_DB = Path(tempfile.mkdtemp(prefix="mas_bench_")) / "bench.db"
os.environ.setdefault("LLM_MOCK_MODE", "1")
os.environ.setdefault("MCP_MOCK_MODE", "1")
os.environ.setdefault("EMBEDDING_MOCK_MODE", "1")
os.environ["DATABASE_PATH"] = str(_BENCH_DB)

RESULTS_DIR = PROJECT_ROOT / "results"
DEFAULT_MD = RESULTS_DIR / "benchmark.md"
DEFAULT_JSON = RESULTS_DIR / "benchmark.json"


# ---------------------------------------------------------------------
# أدوات مساعدة
# ---------------------------------------------------------------------
def timed(func: Callable[[], Any], repeat: int = 1) -> dict[str, Any]:
    """تنفيذ دالة N مرات وقياس: آخر قيمة، المتوسط، الوسيط، الأدنى، الأعلى (ms)."""
    samples: list[float] = []
    value: Any = None
    for _ in range(max(1, repeat)):
        started = time.perf_counter()
        value = func()
        samples.append((time.perf_counter() - started) * 1000)
    return {
        "value": value,
        "runs": len(samples),
        "mean_ms": round(statistics.fmean(samples), 3),
        "median_ms": round(statistics.median(samples), 3),
        "min_ms": round(min(samples), 3),
        "max_ms": round(max(samples), 3),
    }


def _merge_state(state: Any, updates: dict[str, Any]) -> Any:
    """دمج تحديثات وكيل في حالة ScanState (يتجاهل المفاتيح غير المعرَّفة)."""
    from agents.state import ScanState

    clean = {k: v for k, v in updates.items() if k in ScanState.model_fields}
    return state.model_copy(update=clean)


def _new_scan_entities(app_id: str) -> dict[str, int]:
    """مشروع/تطبيق/فحص حقيقيون في القاعدة المؤقتة (كي يعمل persist/reporter)."""
    import hashlib

    from db.repositories import applications_repo, projects_repo, scans_repo

    project = projects_repo.create(name="benchmark", description="قياس الأداء (المرحلة 8)")
    application = applications_repo.create(
        project_id=project["id"],
        name=f"bench-{app_id}",
        sha256=hashlib.sha256(f"bench:{app_id}".encode()).hexdigest(),
        file_path=f"data/apks/{app_id}.apk",
        package_name="bench.package",
        app_category="utility",
    )
    scan = scans_repo.create(application_id=application["id"], status="pending")
    return {"project_id": project["id"], "application_id": application["id"], "scan_id": scan["id"]}


def _ensure_test_apk(app_id: str = "diva") -> str:
    """ملف APK وهمي صغير (Mock لا يقرأ محتواه، لكن بعض المسارات تتحقق من الوجود)."""
    apks_dir = PROJECT_ROOT / "data" / "apks"
    apks_dir.mkdir(parents=True, exist_ok=True)
    path = apks_dir / "benchmark_sample.apk"
    if not path.exists():
        path.write_bytes(b"PK\x03\x04" + b"benchmark-apk-placeholder" * 64)
    return str(path)


# ---------------------------------------------------------------------
# 1) بدء التشغيل
# ---------------------------------------------------------------------
def bench_startup() -> dict[str, Any]:
    """زمن تهيئة المخطط + البذر الكامل على قاعدة فارغة."""
    from db.connection import init_db
    from db.seed import (
        seed_knowledge_base,
        seed_severity_rules,
        seed_tools,
        seed_users,
    )

    steps: dict[str, Any] = {}
    steps["init_db"] = timed(lambda: init_db())
    steps["seed_users"] = timed(seed_users)
    steps["seed_tools"] = timed(seed_tools)
    steps["seed_severity_rules"] = timed(seed_severity_rules)
    steps["seed_knowledge_base"] = timed(seed_knowledge_base)
    steps["total_ms"] = round(sum(steps[k]["mean_ms"] for k in steps), 3)
    return steps


# ---------------------------------------------------------------------
# 2) عمليات القاعدة
# ---------------------------------------------------------------------
def bench_db_ops(entities: dict[str, int], rows: int = 100) -> dict[str, Any]:
    """إدراج دفعي + استعلامات القراءة الشائعة (ms)."""
    from db.connection import get_session
    from db.models import Assessment, Vulnerability
    from db.repositories import findings_repo
    from sqlalchemy import func, select

    def bulk_insert() -> int:
        with get_session() as session:
            for index in range(rows):
                session.add(
                    Vulnerability(
                        application_id=entities["application_id"],
                        title=f"bench-{index}",
                        masvs_category="MASVS-CRYPTO",
                        cwe_id="CWE-798",
                        dedup_fingerprint=f"bench{index:04d}",
                        status="open",
                    )
                )
            session.flush()
        return rows

    def bulk_assessments() -> int:
        with get_session() as session:
            vulns = session.scalars(
                select(Vulnerability).where(Vulnerability.title.like("bench-%")).limit(rows)
            ).all()
            for vuln in vulns:
                session.add(
                    Assessment(
                        vulnerability_id=vuln.id,
                        base_score=7.0,
                        context_score=5.0,
                        evidence_score=6.0,
                        confidence_factor=0.5,
                        final_score=6.2,
                        severity="Medium",
                        rule_version="v1.1",
                        assessed_by="agent",
                    )
                )
            session.flush()
        return rows

    def scan_select() -> int:
        with get_session() as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(Vulnerability)
                    .where(Vulnerability.application_id == entities["application_id"])
                )
                or 0
            )

    def aggregate() -> list[tuple[str, int]]:
        with get_session() as session:
            return [
                (str(sev), int(count))
                for sev, count in session.execute(
                    select(Assessment.severity, func.count())
                    .group_by(Assessment.severity)
                ).all()
            ]

    def findings_read() -> list[dict[str, Any]]:
        return findings_repo.list_vulns_by_app(entities["application_id"])

    return {
        "insert_100_vulns": timed(bulk_insert),
        "insert_100_assessments": timed(bulk_assessments),
        "count_by_application": timed(scan_select, repeat=10),
        "group_by_severity": timed(aggregate, repeat=10),
        "list_scan_vulnerabilities": timed(findings_read, repeat=10),
    }


# ---------------------------------------------------------------------
# 3) أدوات MCP (Mock)
# ---------------------------------------------------------------------
def bench_mcp_tools(sample_apk: str) -> dict[str, Any]:
    """زمن استدعاء كل أداة MCP في وضع Mock — بوسائط مطابقة لتوقيع كل أداة.

    الوسائط تُبنى من توقيع الدالة الفعلي (``inspect.signature``): أي معامل
    مطلوب لا نعرف له قيمة صالحة يُعلَن صراحةً بـ ``skipped`` — لا نخترع وسائط
    ولا نسجّل أخطاء ناتجة عن سوء استدعاء (كان يحدث في نسخة سابقة).
    """
    import inspect

    from agents.mcp_client import AgentMCPClient

    values: dict[str, Any] = {
        "apk_path": sample_apk,
        "apk_file": sample_apk,
        "timeout": 30,
        "keyword": "password",
        "max_results": 20,
        "class_name": "MainActivity",
        "scan_hash": "bench_scan_hash",
        "scan_id": "bench_scan_id",
        "package_name": "com.example.bench",
        "session_id": "bench_session",
        "script_name": "ssl_pinning_bypass",
        "duration": 5,
    }

    async def collect() -> dict[str, Any]:
        results: dict[str, Any] = {"tools": {}, "skipped": []}
        async with AgentMCPClient() as client:
            tools = await client.list_all_tools()
            results["tools_available"] = len(tools)
            for tool in tools:
                fn = client._registry.get(tool)  # noqa: SLF001 — قراءة فقط للقياس
                if fn is None:
                    results["skipped"].append(f"{tool} (بلا دالة مباشرة)")
                    continue
                signature = inspect.signature(fn)
                kwargs: dict[str, Any] = {}
                unknown: list[str] = []
                for name, parameter in signature.parameters.items():
                    if name in values:
                        kwargs[name] = values[name]
                    elif parameter.default is not inspect.Parameter.empty:
                        continue  # اختياري — نترك الافتراضي
                    else:
                        unknown.append(name)
                if unknown:
                    results["skipped"].append(f"{tool} (معاملات بلا قيمة: {unknown})")
                    continue
                started = time.perf_counter()
                try:
                    await client.call_tool(tool, **kwargs)
                except Exception as exc:  # noqa: BLE001 — يُسجَّل ولا يُسقط القياس
                    results["tools"][tool] = {"error": f"{type(exc).__name__}: {exc}"}
                    continue
                results["tools"][tool] = {
                    "mean_ms": round((time.perf_counter() - started) * 1000, 3),
                    "args": sorted(kwargs),
                }
        return results

    return asyncio.run(collect())


# ---------------------------------------------------------------------
# 4) محرك التقييم
# ---------------------------------------------------------------------
def bench_scoring(rows: int = 200) -> dict[str, Any]:
    """إنتاجية ScoringEngine على مجموعة ثغرات متنوعة."""
    from agents.scorer import load_active_rule_cached
    from core.scoring.engine import ScoringEngine

    rule = load_active_rule_cached()
    engine = ScoringEngine(rule)
    categories = [
        "MASVS-CRYPTO", "MASVS-NETWORK", "MASVS-STORAGE",
        "MASVS-AUTH", "MASVS-CODE", "MASVS-PLATFORM", "MASVS-RESILIENCE",
    ]
    context = {
        "data_sensitivity": "HIGH",
        "industry": "banking",
        "user_base_size": "large",
        "internet_facing": True,
        "business_criticality": "HIGH",
    }

    def one(index: int) -> dict[str, Any]:
        return engine.score(
            {
                "title": f"vuln-{index}",
                "masvs_category": categories[index % len(categories)],
                "sub_category": "general",
                "cwe_id": "CWE-798",
                "description": "desc",
                "discovered_by": ["mobsf", "jadx"],
                "evidence": "specific code trace",
            },
            app_context=context,
            tool_reliabilities={"mobsf": 0.9, "jadx": 0.85},
        )

    timing = timed(lambda: [one(i) for i in range(rows)])
    per_second = round(rows / (timing["mean_ms"] / 1000), 1) if timing["mean_ms"] else None
    return {"rows": rows, "timing": timing, "per_second": per_second}


# ---------------------------------------------------------------------
# 5) مراحل الوكلاء (تسلسل يدوي — نفس ترتيب الرسم البياني)
# ---------------------------------------------------------------------
def bench_agent_stages(sample_apk: str) -> dict[str, Any]:
    """قياس كل مرحلة على حالة واحدة (تسلسل يدوي بلا graph)."""
    from agents.extractor import ExtractorAgent
    from agents.orchestrator import OrchestratorAgent
    from agents.report_agent import ReporterAgent
    from agents.reviewer import ReviewerAgent
    from agents.scorer import ScorerAgent
    from agents.state import ScanState

    entities = _new_scan_entities("stages")
    state = ScanState(
        scan_id="bench_stages",
        application_id=entities["application_id"],
        apk_path=sample_apk,
        package_name="bench.package",
        app_category="utility",
        db_scan_id=entities["scan_id"],
        user_request="قياس أداء المراحل",
    )

    stages: dict[str, Any] = {}
    orchestrator = OrchestratorAgent()
    extractor = ExtractorAgent()
    scorer = ScorerAgent()
    reviewer = ReviewerAgent()
    reporter = ReporterAgent()

    async def run_all() -> None:
        nonlocal state

        async def step(name: str, coro_factory: Callable[[], Any]) -> None:
            nonlocal state
            started = time.perf_counter()
            updates = await coro_factory()
            stages[name] = {
                "mean_ms": round((time.perf_counter() - started) * 1000, 3),
                "updates": sorted(updates.keys()) if isinstance(updates, dict) else [],
            }
            if isinstance(updates, dict):
                state = _merge_state(state, updates)

        await step("orchestrator", lambda: orchestrator.run(state))
        await step("tools_static", lambda: orchestrator.execute_stage(state, "static"))
        await step("extractor", lambda: extractor.extract_static(state))
        await step("scorer", lambda: scorer.run(state))
        await step("reviewer", lambda: reviewer.run(state))
        await step("reporter", lambda: reporter.run(state))
        stages["vulnerabilities"] = len(state.vulnerabilities or [])
        stages["assessments"] = len(state.assessments or [])

    asyncio.run(run_all())
    return stages


# ---------------------------------------------------------------------
# 6) الخط الكامل + عدّاد الرموز التقديري
# ---------------------------------------------------------------------
def bench_full_pipeline(sample_apk: str, repeat: int = 2) -> dict[str, Any]:
    """زمن ainvoke_pipeline كاملاً + تقدير الأحرف/الرموز المُرسلة للنماذج."""
    from agents.base_agent import BaseAgent
    from agents.graph import ainvoke_pipeline, build_scan_graph
    from agents.state import ScanState

    prompt_chars = {"total": 0, "calls": 0}
    original_call = BaseAgent.call_llm
    original_structured = BaseAgent.call_llm_structured

    async def counting_call(self, prompt, *args, **kwargs):  # type: ignore[no-untyped-def]
        prompt_chars["total"] += len(str(prompt))
        prompt_chars["calls"] += 1
        return await original_call(self, prompt, *args, **kwargs)

    async def counting_structured(self, prompt, *args, **kwargs):  # type: ignore[no-untyped-def]
        prompt_chars["total"] += len(str(prompt))
        prompt_chars["calls"] += 1
        return await original_structured(self, prompt, *args, **kwargs)

    BaseAgent.call_llm = counting_call  # type: ignore[method-assign]
    BaseAgent.call_llm_structured = counting_structured  # type: ignore[method-assign]

    durations: list[float] = []
    last_result: dict[str, Any] = {}
    try:
        for index in range(max(1, repeat)):
            entities = _new_scan_entities(f"e2e{index}")
            state = ScanState(
                scan_id=f"bench_e2e_{index}",
                application_id=entities["application_id"],
                apk_path=sample_apk,
                package_name="bench.package",
                app_category="utility",
                db_scan_id=entities["scan_id"],
                user_request="قياس الخط الكامل",
            )

            async def run_once() -> dict[str, Any]:
                graph = build_scan_graph()
                return await ainvoke_pipeline(graph, state)

            started = time.perf_counter()
            last_result = asyncio.run(run_once())
            durations.append((time.perf_counter() - started) * 1000)
    finally:
        BaseAgent.call_llm = original_call  # type: ignore[method-assign]
        BaseAgent.call_llm_structured = original_structured  # type: ignore[method-assign]

    return {
        "runs": len(durations),
        "mean_ms": round(statistics.fmean(durations), 3),
        "min_ms": round(min(durations), 3),
        "max_ms": round(max(durations), 3),
        "stage": last_result.get("current_stage"),
        "vulnerabilities": len(last_result.get("vulnerabilities") or []),
        "assessments": len(last_result.get("assessments") or []),
        "errors": len(last_result.get("errors") or []),
        "prompt_calls": prompt_chars["calls"],
        "prompt_chars_total": prompt_chars["total"],
        "prompt_chars_per_run": round(prompt_chars["total"] / max(1, len(durations)), 1),
        "tokens_estimate_per_run": round(prompt_chars["total"] / max(1, len(durations)) / 4, 1),
    }


# ---------------------------------------------------------------------
# 7) RAG
# ---------------------------------------------------------------------
def bench_rag(queries: int = 20) -> dict[str, Any]:
    """زمن الفهرسة + الاسترجاع (Mock embeddings)."""
    from rag.ingest import ingest_knowledge_base
    from rag.retriever import KnowledgeRetriever

    ingest = timed(lambda: ingest_knowledge_base(force=True))
    retriever = KnowledgeRetriever()
    corpus = [
        "SSL pinning bypass certificate validation",
        "hardcoded encryption key in source code",
        "insecure data storage external files",
        "exported activity without permission",
        "weak authentication mechanism",
    ]

    def search_loop() -> int:
        hits = 0
        for index in range(queries):
            hits += len(retriever.retrieve(corpus[index % len(corpus)], top_k=3))
        return hits

    return {
        "ingest": ingest,
        "search": timed(search_loop, repeat=3),
        "queries_per_run": queries,
        "kb_rows": (ingest["value"] or {}).get("store_total"),
    }


# ---------------------------------------------------------------------
# التقرير
# ---------------------------------------------------------------------
def _row(name: str, timing: dict[str, Any]) -> str:
    """صف Markdown من قياس."""
    if "mean_ms" not in timing:
        return f"| {name} | — | — | — |"
    return (
        f"| {name} | {timing['mean_ms']} | {timing.get('median_ms', '—')} | "
        f"{timing.get('min_ms', '—')} / {timing.get('max_ms', '—')} |"
    )


def build_report(data: dict[str, Any]) -> str:
    """تقرير Markdown لكل المحاور — بلا أي رقم غير مقيس."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    startup = data["startup"]
    db_ops = data["db_ops"]
    stages = data["agent_stages"]
    pipeline = data["pipeline"]
    rag = data["rag"]

    lines = [
        "# تقرير قياس الأداء (Benchmark) — الإصدار v1.0",
        f"\n**تاريخ التوليد:** {generated}",
        f"**الوضع:** Mock كامل (LLM/MCP/Embeddings) — قاعدة مؤقتة `{data['db_path']}`",
        "",
        "> **صدق القياس:** كل رقم أدناه مقيس فعلياً في هذا التشغيل. أرقام وضع Mock هي "
        "**حدود دنيا** (لا شبكة ولا نماذج حقيقية)، وتقدير الرموز = أحرف البرومبت ÷ 4.",
        "",
        "## 1) بدء التشغيل (قاعدة فارغة)",
        "",
        "| الخطوة | المتوسط (ms) | الوسيط (ms) | الأدنى / الأعلى |",
        "|---|---|---|---|",
    ]
    for key, value in startup.items():
        if key == "total_ms":
            continue
        lines.append(_row(key, value))
    lines += [f"\n**الإجمالي:** {startup['total_ms']} ms", ""]

    lines += [
        "## 2) عمليات قاعدة البيانات",
        "",
        "| العملية | المتوسط (ms) | الوسيط (ms) | الأدنى / الأعلى |",
        "|---|---|---|---|",
    ]
    for key, value in db_ops.items():
        lines.append(_row(key, value))
    lines.append("")

    mcp = data["mcp_tools"]
    tool_rows = mcp.get("tools", {}) if isinstance(mcp, dict) else {}
    lines += [
        "## 3) أدوات MCP (Mock)",
        "",
        f"عدد الأدوات في السجل: **{mcp.get('tools_available', '؟')}** · "
        f"مقيسة: **{len(tool_rows)}** · متخطّاة: **{len(mcp.get('skipped', []))}**",
        "",
        "| الأداة | المتوسط (ms) | الوسائط |",
        "|---|---|---|",
    ]
    for tool, value in tool_rows.items():
        if "error" in value:
            lines.append(f"| {tool} | خطأ: {value['error']} | — |")
        else:
            args = "، ".join(value.get("args", [])) or "—"
            lines.append(f"| {tool} | {value['mean_ms']} | {args} |")
    if mcp.get("skipped"):
        lines += ["", "**متخطّاة (موثّقة، لا تُحتسب):** " + " · ".join(mcp["skipped"]), ""]
    lines.append("")

    scoring = data["scoring"]
    lines += [
        "## 4) محرك التقييم (ScoringEngine)",
        "",
        f"- {scoring['rows']} ثغرة: **{scoring['timing']['mean_ms']} ms** "
        f"(وسيط {scoring['timing']['median_ms']} ms)",
        f"- الإنتاجية: **{scoring['per_second']} ثغرة/ثانية**",
        "",
        "## 5) مراحل الوكلاء (تسلسل يدوي بنفس ترتيب الرسم)",
        "",
        "| المرحلة | الزمن (ms) |",
        "|---|---|",
    ]
    for key, value in stages.items():
        if isinstance(value, dict) and "mean_ms" in value:
            lines.append(f"| {key} | {value['mean_ms']} |")
    lines += [
        "",
        f"**النتيجة:** {stages.get('vulnerabilities')} ثغرة و{stages.get('assessments')} تقييماً "
        "من مراحل القياس.",
        "",
        "## 6) الخط الكامل (E2E)",
        "",
        "| القياس | القيمة |",
        "|---|---|",
        f"| عدد التشغيلات | {pipeline['runs']} |",
        f"| المتوسط | {pipeline['mean_ms']} ms |",
        f"| الأدنى / الأعلى | {pipeline['min_ms']} / {pipeline['max_ms']} ms |",
        f"| مرحلة الختام | {pipeline.get('stage')} |",
        f"| ثغرات / تقييمات / أخطاء | {pipeline.get('vulnerabilities')} / "
        f"{pipeline.get('assessments')} / {pipeline.get('errors')} |",
        f"| استدعاءات النماذج | {pipeline['prompt_calls']} |",
        f"| أحرف البرومبت لكل تشغيل | {pipeline['prompt_chars_per_run']:,} |",
        f"| رموز تقديرية لكل تشغيل (أحرف÷4) | {pipeline['tokens_estimate_per_run']:,} |",
        "",
        "## 7) استرجاع RAG",
        "",
        "| القياس | القيمة |",
        "|---|---|",
        f"| فهرسة كاملة (8 أنماط) | {rag['ingest']['mean_ms']} ms |",
        f"| {rag['queries_per_run']} استعلاماً | {rag['search']['mean_ms']} ms "
        f"(≈{round(rag['search']['mean_ms'] / rag['queries_per_run'], 3)} ms/استعلام) |",
        f"| صفوف المخزن | {rag.get('kb_rows')} |",
        "",
        "## 8) حدود المنهجية",
        "",
        "- القياس على **Mock**: زمن النماذج/الأدوات الحقيقية يضاف فوق هذه الأرقام "
        "(يُوثَّق تشغيل حقيقي عند توفّر المفاتيح/APK).",
        "- زمن الاسترجاع على 8 صفوف فقط؛ مع قاعدة أكبر يُعاد القياس "
        "(`python scripts/benchmark.py`).",
        "- تقدير الرموز تقريبي (÷4) ولا يمثل فاتورة مزوّد حقيقي.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    """تشغيل كل محاور القياس وكتابة التقارير."""
    parser = argparse.ArgumentParser(description="قياس أداء النظام")
    parser.add_argument("--rows", type=int, default=100, help="صفوف عمليات القاعدة")
    parser.add_argument("--scoring-rows", type=int, default=200, help="ثغرات محرك التقييم")
    parser.add_argument("--pipeline-runs", type=int, default=2, help="تشغيلات E2E")
    parser.add_argument("--output", default=str(DEFAULT_MD))
    parser.add_argument("--json", default=str(DEFAULT_JSON))
    args = parser.parse_args()

    print("◉ قياس الأداء — قاعدة مؤقتة:", _BENCH_DB)
    sample_apk = _ensure_test_apk()
    startup = bench_startup()          # المخطط أولاً — الكيانات بعده
    entities = _new_scan_entities("ops")

    data: dict[str, Any] = {
        "db_path": str(_BENCH_DB),
        "sample_apk": sample_apk,
        "startup": startup,
        "db_ops": bench_db_ops(entities, rows=args.rows),
        "mcp_tools": bench_mcp_tools(sample_apk),
        "scoring": bench_scoring(rows=args.scoring_rows),
        "agent_stages": bench_agent_stages(sample_apk),
        "pipeline": bench_full_pipeline(sample_apk, repeat=args.pipeline_runs),
        "rag": bench_rag(),
    }

    report = build_report(data)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")

    json_path = Path(args.json)
    json_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
    )

    print(f"  ✓ بدء التشغيل: {data['startup']['total_ms']} ms")
    print(f"  ✓ محرك التقييم: {data['scoring']['per_second']} ثغرة/ثانية")
    print(f"  ✓ الخط الكامل: {data['pipeline']['mean_ms']} ms "
          f"(رموز تقديرية/تشغيل: {data['pipeline']['tokens_estimate_per_run']})")
    print(f"  ✓ RAG: فهرسة {data['rag']['ingest']['mean_ms']} ms | "
          f"استعلام {round(data['rag']['search']['mean_ms'] / data['rag']['queries_per_run'], 3)} ms")
    print(f"✅ التقرير: {output_path}")
    print(f"✅ JSON:    {json_path}")


if __name__ == "__main__":
    main()
