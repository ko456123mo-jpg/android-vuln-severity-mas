"""LangGraph StateGraph — آلة حالة الفحص متعدد الوكلاء.

التدفق / Flow:
    orchestrator ──(static؟)──▶ run_static_tools ──▶ extractor_static
        │(dynamic only)              │
        ▼                            ▼ (الخطة تتضمن dynamic؟)
    run_dynamic_tools ◀──────────────┘
        │
        ▼
    extractor_dynamic ──▶ scorer ──▶ reviewer ──▶ reporter ──▶ finalize ──▶ END

    (المسار الساكن-فقط: extractor_static ─▶ scorer؛ وكلاهما يلتقيان عند scorer)

المرحلة 4: Scorer يحسب الأرقام حتمياً عبر ScoringEngine (LLM للتفسير فقط)،
وReviewer يعدّل عبر REVIEW_RULES الصريحة وحدها — لا أرقام من LLM تُخزَّن أبداً.
المرحلة 5: Reporter يولّد تقريرَي الفحص (Technical EN / Executive AR)
بثلاث صيغ داخل data/reports/<scan_id>/ — فشل التقارير لا يسقط الفحص.

Checkpointing: AsyncSqliteSaver على ./data/checkpoints.db (استئناف + HITL لاحقاً)
مع ainvoke يجب تمرير config={"configurable": {"thread_id": scan_id}}.
العقد تعيد تحديثات جزئية؛ الاندماجات الثقيلة (dedup) تتم داخل الوكلاء.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, StateGraph

from agents.extractor import ExtractorAgent
from agents.orchestrator import OrchestratorAgent
from agents.report_agent import ReporterAgent
from agents.reviewer import ReviewerAgent
from agents.scorer import ScorerAgent
from agents.state import ScanState
from mcp_servers.common import PROJECT_ROOT

DEFAULT_CHECKPOINTS = PROJECT_ROOT / "data" / "checkpoints.db"


async def ainvoke_pipeline(graph: Any, state: ScanState) -> dict[str, Any]:
    """تشغيل Pipeline الفحص مع إغلاق نظيف لاتصال الـ checkpointer.

    بديل موصى به عن graph.ainvoke المباشر: يمرر thread_id تلقائياً ويغلق
    اتصال aiosqlite بعد الانتهاء (تجنّب تحذيرات Event loop is closed).
    تعيد الحالة النهائية كـ dict.
    """
    try:
        return await graph.ainvoke(
            state.model_dump(), config={"configurable": {"thread_id": state.scan_id}}
        )
    finally:
        saver = getattr(graph, "checkpointer", None)
        conn = getattr(saver, "conn", None) if saver is not None else None
        if conn is not None:
            try:
                await conn.close()
            except Exception:
                pass  # الإغلاق شفاف — لا يعطّل نتيجة ناجحة

# الأدوات الساكنة/الديناميكية المعرّفة في الكتالوج
_STATIC_TOOLS = {"jadx", "mobsf", "apktool"}
_DYNAMIC_TOOLS = {"frida", "objection"}


def build_scan_graph(
    checkpoints_path: str | Path | None = None,
    orchestrator: OrchestratorAgent | None = None,
    extractor: ExtractorAgent | None = None,
    scorer: ScorerAgent | None = None,
    reviewer: ReviewerAgent | None = None,
    reporter: ReporterAgent | None = None,
    with_checkpoint: bool = True,
):
    """بناء وتجميع مخطط الفحص — يعيد CompiledGraph جاهزاً لـ ainvoke.

    Args:
        checkpoints_path: مسار قاعدة checkpoints (افتراضي data/checkpoints.db).
        orchestrator/extractor/scorer/reviewer/reporter: حقن وكلاء مخصصين
            (للاختبارات)، وإلا يُبنى بالاعتمادات الافتراضية (MockLLM مع Mock).
        with_checkpoint: تعطيل الـ checkpointing للاختبارات الخفيفة.
    """
    orch = orchestrator or OrchestratorAgent()
    ext = extractor or ExtractorAgent()
    scr = scorer or ScorerAgent()
    rev = reviewer or ReviewerAgent()
    rep = reporter or ReporterAgent()

    # ------------------------------------------------------------------
    # العقد / Nodes
    # ------------------------------------------------------------------
    async def orchestrator_node(state: ScanState) -> dict[str, Any]:
        return await orch.run(state)

    async def run_static_tools_node(state: ScanState) -> dict[str, Any]:
        return await orch.execute_stage(state, "static")

    async def run_dynamic_tools_node(state: ScanState) -> dict[str, Any]:
        return await orch.execute_stage(state, "dynamic")

    async def extractor_static_node(state: ScanState) -> dict[str, Any]:
        return await ext.extract_static(state)

    async def extractor_dynamic_node(state: ScanState) -> dict[str, Any]:
        return await ext.extract_dynamic(state)

    async def scorer_node(state: ScanState) -> dict[str, Any]:
        return await scr.run(state)

    async def reviewer_node(state: ScanState) -> dict[str, Any]:
        # وضع التجربة scorer_only (المرحلة 7): تخطي المراجعة الآلية بالكامل
        # (تبقى كل التقييمات pending — لا قرار مراجعة بلا وكيل مراجعة)
        if getattr(state, "scorer_only", False):
            return {"current_stage": "review"}
        return await rev.run(state)

    async def persist_scores_node(state: ScanState) -> dict[str, Any]:
        """حفظ الثغرات+التقييمات قبل التقارير (upsert idempotent).

        ضروري لأن reporter يقرأ القاعدة: بدون هذه الخطوة تعمل التقارير على
        بيانات فارغة في الفحص الأول. findings تبقى حفصةً في finalize حصراً
        (إنشاء السطور غير idempotent — مرة واحدة فقط كي لا تتضاعف).
        """
        errors: list[str] = []
        if state.db_scan_id is not None:
            try:
                _persist_scores(state, errors)
            except Exception as exc:
                errors.append(f"persist_scores failed: {exc}")
        return {"errors": list(state.errors) + errors} if errors else {}

    async def reporter_node(state: ScanState) -> dict[str, Any]:
        return await rep.run(state)

    async def finalize_node(state: ScanState) -> dict[str, Any]:
        return _finalize(state)

    # ------------------------------------------------------------------
    # الموجّهات / Routers
    # ------------------------------------------------------------------
    def route_after_orchestrator(state: ScanState) -> str:
        sequence = state.scan_plan.get("tools_sequence") or []
        tools = {a.get("tool") for a in sequence}
        if tools & _DYNAMIC_TOOLS and not tools & _STATIC_TOOLS:
            return "run_dynamic_tools"
        if tools & _STATIC_TOOLS:
            return "run_static_tools"
        return "finalize"  # خطة فارغة — فشل مسجَّل، نختم مبكراً

    def route_after_static_extraction(state: ScanState) -> str:
        sequence = state.scan_plan.get("tools_sequence") or []
        tools = {a.get("tool") for a in sequence}
        if tools & _DYNAMIC_TOOLS:
            return "run_dynamic_tools"
        return "scorer"  # فحص ساكن فقط → مباشرة إلى التقييم

    # ------------------------------------------------------------------
    # البناء / Build
    # ------------------------------------------------------------------
    builder = StateGraph(ScanState)
    builder.add_node("orchestrator", orchestrator_node)
    builder.add_node("run_static_tools", run_static_tools_node)
    builder.add_node("run_dynamic_tools", run_dynamic_tools_node)
    builder.add_node("extractor_static", extractor_static_node)
    builder.add_node("extractor_dynamic", extractor_dynamic_node)
    builder.add_node("scorer", scorer_node)
    builder.add_node("reviewer", reviewer_node)
    builder.add_node("persist_scores", persist_scores_node)
    builder.add_node("reporter", reporter_node)
    builder.add_node("finalize", finalize_node)

    builder.set_entry_point("orchestrator")
    builder.add_conditional_edges(
        "orchestrator",
        route_after_orchestrator,
        {
            "run_static_tools": "run_static_tools",
            "run_dynamic_tools": "run_dynamic_tools",
            "finalize": "finalize",
        },
    )
    builder.add_edge("run_static_tools", "extractor_static")
    builder.add_conditional_edges(
        "extractor_static",
        route_after_static_extraction,
        {"run_dynamic_tools": "run_dynamic_tools", "scorer": "scorer"},
    )
    builder.add_edge("run_dynamic_tools", "extractor_dynamic")
    builder.add_edge("extractor_dynamic", "scorer")
    builder.add_edge("scorer", "reviewer")
    builder.add_edge("reviewer", "persist_scores")
    builder.add_edge("persist_scores", "reporter")
    builder.add_edge("reporter", "finalize")
    builder.add_edge("finalize", END)

    if not with_checkpoint:
        return builder.compile()

    path = Path(checkpoints_path) if checkpoints_path else DEFAULT_CHECKPOINTS
    path.parent.mkdir(parents=True, exist_ok=True)
    # AsyncSqliteSaver ضروري مع ainvoke — SqliteSaver المتزامن لا يدعمه.
    # aiosqlite.connect كسول (لا coroutine) و setup() يُستدعى تلقائياً عند الحاجة.
    conn = aiosqlite.connect(str(path))
    memory = AsyncSqliteSaver(conn)
    return builder.compile(checkpointer=memory)


# ---------------------------------------------------------------------
# عقدة الختام — حفظ النتائج في قاعدة البيانات / Finalize (DB persistence)
# ---------------------------------------------------------------------
def _finalize(state: ScanState) -> dict[str, Any]:
    """حفظ vulnerabilities + findings، تحديث حالة الـ scan، وإغلاق الحالة."""
    finished = datetime.now(timezone.utc).replace(tzinfo=None)
    duration_ms = int(
        ((finished - state.started_at).total_seconds()) * 1000
    ) if state.started_at else 0
    errors: list[str] = []

    if state.db_scan_id is not None:
        try:
            _persist_results(state, duration_ms, errors)
        except Exception as exc:
            errors.append(f"finalize DB persist failed: {exc}")

    all_errors = list(state.errors) + errors
    has_errors = bool(all_errors)
    return {
        "current_stage": "done" if not (has_errors and not state.vulnerabilities) else "failed",
        "finished_at": finished,
        "total_duration_ms": duration_ms,
        # لا يُستبدل الحقل: إرجاع قائمة فارغة هنا يمحو كل أخطاء المراحل السابقة
        "errors": all_errors,
    }


def _persist_results(state: ScanState, duration_ms: int, errors: list[str]) -> None:
    """كتابة النتائج النهائية وحالة الفحص — كل الأقسام idempotent (المرحلة 5).

    الثغرات/الأدلة/التقييمات قد تكون حُفظت أصلاً في persist_scores (قبل
    التقارير)؛ تكرارها هنا آمن: get-or-create بالبصمة، ثلاثية الأدلة، و
    upsert التقييمات. الثابت الوحيد هنا: حالة الفحص + التكاليف.
    """
    from sqlalchemy import select

    from db.connection import get_session
    from db.models import Tool
    from db.repositories import scans_repo

    with get_session() as session:
        tool_ids = {t.name: t.id for t in session.scalars(select(Tool)).all()}

    fp_to_vuln_id = _persist_vulnerabilities(state, errors)
    _persist_findings(state, fp_to_vuln_id, tool_ids, errors)
    _persist_assessments(state, fp_to_vuln_id, errors)

    final_status = "success" if not state.errors else "partial"
    scans_repo.update_status(
        state.db_scan_id,
        final_status,
        total_tokens=state.total_tokens,
        total_duration_ms=duration_ms,
    )
    scans_repo.update_tools_used(state.db_scan_id, state.tools_executed)


def _persist_scores(state: ScanState, errors: list[str]) -> None:
    """حفظ النتائج قبل التقارير: الثغرات + الأدلة + التقييمات + الأدوات.

    كل العمليات idempotent (create_vulnerability فريد بالبصمة، create_finding
    فريد بالثلاثية، upsert_by_vuln للتقييمات) — تشغيلها لاحقاً في finalize
    لا يضاعف شيئاً. الهدف: أن تُبنى التقارير على بيانات كاملة في أول فحص.
    """
    from sqlalchemy import select

    from db.connection import get_session
    from db.models import Tool
    from db.repositories import scans_repo

    with get_session() as session:
        tool_ids = {t.name: t.id for t in session.scalars(select(Tool)).all()}

    fp_to_vuln_id = _persist_vulnerabilities(state, errors)
    _persist_findings(state, fp_to_vuln_id, tool_ids, errors)
    _persist_assessments(state, fp_to_vuln_id, errors)
    scans_repo.update_tools_used(state.db_scan_id, state.tools_executed)


def _persist_vulnerabilities(
    state: ScanState, errors: list[str]
) -> dict[str, int]:
    """إدراج الثغرات (get-or-create بالبصمة) — يعيد fp → vuln_id."""
    from db.repositories import findings_repo

    fp_to_vuln_id: dict[str, int] = {}
    for vuln in state.vulnerabilities:
        record = findings_repo.create_vulnerability(
            application_id=state.application_id,
            title=vuln.get("title", "Untitled")[:255],
            description=vuln.get("description", ""),
            masvs_category=vuln.get("masvs_category"),
            cwe_id=vuln.get("cwe_id"),
            dedup_fingerprint=vuln.get("dedup_fingerprint", ""),
        )
        if not record:
            errors.append(f"skip vuln (no fingerprint): {vuln.get('title')}")
            continue
        fp_to_vuln_id[vuln.get("dedup_fingerprint", "")] = record["id"]
    return fp_to_vuln_id


def _persist_findings(
    state: ScanState,
    fp_to_vuln_id: dict[str, int],
    tool_ids: dict[str, int],
    errors: list[str],
) -> int:
    """إدراج أدلة كل أداة (idempotent بالثلاثية — انظر findings_repo)."""
    from db.repositories import findings_repo

    written = 0
    for vuln in state.vulnerabilities:
        vuln_id = fp_to_vuln_id.get(vuln.get("dedup_fingerprint", ""))
        if vuln_id is None:
            continue
        for tool, evidence in (vuln.get("evidence_by_tool") or {}).items():
            tool_id = tool_ids.get(tool)
            if tool_id is None:
                errors.append(f"unknown tool in DB for finding: {tool}")
                continue
            findings_repo.create_finding(
                vulnerability_id=vuln_id,
                scan_id=state.db_scan_id,
                tool_id=tool_id,
                location=vuln.get("location") or str(evidence)[:300],
                evidence_type="dynamic" if tool in _DYNAMIC_TOOLS else "static",
                artifact_ref=state.raw_artifacts.get(tool),
            )
            written += 1
    return written


def _persist_assessments(
    state: ScanState, fp_to_vuln_id: dict[str, int], errors: list[str]
) -> None:
    """حفظ تقييمات المرحلة 4 — upsert idempotent لكل ثغرة.

    القرارات الموثقة (docs/scoring_logic.md):
      • severity المخزّنة = فئة ما بعد المراجعة (final_severity من Reviewer).
      • final_score يبقى دائماً قيمة ScoringEngine (سلامة المعادلة).
      • تفاصيل المراجعة كاملة (original/reviewed/adjustments/flags) تُخزَّن
        نصاً JSON في review_notes لعدم وجود أعمدة مخصصة لها.
    """
    import json as _json

    from db.repositories import assessments_repo

    for assessment in state.assessments:
        vuln_id = fp_to_vuln_id.get(assessment.get("dedup_fingerprint", ""))
        if vuln_id is None:
            errors.append(
                f"assessment without persisted vuln: {assessment.get('vulnerability_title')}"
            )
            continue
        review_payload = {
            "original_score": assessment.get("original_score"),
            "reviewed_score": assessment.get("reviewed_score"),
            "original_severity": assessment.get("original_severity"),
            "adjustments": assessment.get("adjustments", []),
            "requires_human_review": assessment.get("requires_human_review", False),
            "human_review_reasons": assessment.get("human_review_reasons", []),
            "review_notes": assessment.get("review_notes", ""),
            "llm_reasoning": assessment.get("reasoning", ""),
        }
        assessments_repo.upsert_by_vuln(
            vulnerability_id=vuln_id,
            base_score=assessment.get("base_score"),
            context_score=assessment.get("context_score"),
            evidence_score=assessment.get("evidence_score"),
            confidence_factor=assessment.get("confidence_factor"),
            final_score=assessment.get("final_score"),
            severity=assessment.get("severity"),
            rationale=assessment.get("rationale"),
            rule_version=assessment.get("rule_version"),
            assessed_by="agent",
            review_status=assessment.get("review_status", "pending"),
            review_notes=_json.dumps(review_payload, ensure_ascii=False),
        )
