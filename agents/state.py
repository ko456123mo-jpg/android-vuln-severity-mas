"""ScanState — حالة الفحص المتدفقة بين الوكلاء عبر LangGraph (Pydantic v2).

ملاحظة تصميمية / Design note:
    كل الحقول المجمّعة (tools_executed, vulnerabilities, raw_artifacts, errors)
    من نوع «استبدال كامل» (وليست reducers بـ operator.add) — لأن الدمج بين
    مرحلتي static و dynamic يتطلب قراءة القيمة الحالية ودمجها يدوياً
    (dedup_fingerprint)، فكل عقدة تعيد القيمة مدمجة بالكامل.
    All collection fields use full-replace semantics to allow manual dedup merges.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

ScanStage = Literal[
    "init", "static_scan", "extraction", "scoring", "review", "report", "done", "failed"
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScanState(BaseModel):
    """الحالة الكاملة لفحص واحد (Pydantic state لـ StateGraph)."""

    # ── المعرفات / Identifiers ───────────────────────────────────────
    scan_id: str = Field(min_length=1, description="معرّف منطقي للفحص (thread_id)")
    application_id: int = Field(description="applications.id في قاعدة البيانات")
    apk_path: str = Field(min_length=1)
    package_name: str = "unknown.package"
    app_category: str = "unknown"

    # ── حالة التنفيذ / Progress ─────────────────────────────────────
    current_stage: ScanStage = "init"
    tools_executed: list[str] = []
    errors: list[str] = []

    # ── المخرجات الخام / Raw outputs ────────────────────────────────
    raw_artifacts: dict[str, str] = {}  # tool_name -> artifact_ref

    # ── الثغرات المستخرجة / Extracted vulnerabilities ───────────────
    vulnerabilities: list[dict[str, Any]] = []

    # ── التقييمات (المرحلة 5) / Assessments (Phase 5) ───────────────
    assessments: list[dict[str, Any]] = []

    # ── التقارير (المرحلة 5) / Reports (Phase 5) ────────────────────
    reports_generated: bool = False
    technical_report_path: Optional[str] = None
    executive_report_path: Optional[str] = None
    pending_reviews_count: int = 0

    # ── الميتاداتا / Metadata ───────────────────────────────────────
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None
    total_tokens: int = 0
    total_duration_ms: int = 0

    # ── حقول تشغيلية موسّعة / Orchestration extension fields ───────
    # (لا تكسر التوقيع الأصلي — لها قيم افتراضية)
    user_request: str = ""  # طلب المستخدم النصي؛ الافتراضي = فحص شامل
    scan_type: str = ""  # static | dynamic | comprehensive (بعد التخطيط)
    scan_plan: dict[str, Any] = {}  # خطة Orchestrator المُتحقق منها
    db_scan_id: Optional[int] = None  # scans.id الفعلي في قاعدة البيانات

    # ── أعلام التجربة (المرحلة 7) / Experiment flags (Phase 7) ──────
    # تُستخدم حصراً بأوضاع run_experiment.py (full/scorer_only/no_rag/no_feedback)
    # ولا تغيّر السلوك الافتراضي (كلها False) — قرار موثق في protocol.md
    disable_rag: bool = False  # تجاوز RAG في الاستخراج (كتلة KB كاملة — سلوك المرحلة 3)
    disable_feedback: bool = False  # تجاوز أمثلة Few-Shot في Scorer
    scorer_only: bool = False  # تخطي Reviewer (لا قرار مراجعة آلي — كلها pending)
