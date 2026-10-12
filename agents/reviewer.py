"""ReviewerAgent — وكيل المراجعة: تعديلات محكومة بقواعد صريحة فقط.

عقد صارم (موثق في docs/scoring_logic.md):
    ★ أي تعديل على final_score يمر حصراً عبر REVIEW_RULES الثمانية الثابتة —
      الـ LLM لا يملك صلاحية تغيير الأرقام؛ مهمته شرح القرار وتحرير الملاحظات.
    ★ requires_human_review يُحسب حتمياً وفق 3 معايير دقيقة:
        1) confidence_factor < 0.75 (عتبة المراجعة)
        2) |final_score − أقرب حد فئة| ≤ 0.5 (منطقة حدّية)
        3) severity == Critical و confidence_factor < 0.9 (الحرجة تتطلب ثقة عالية)
    ★ النتيجة البنيوية للمراجعة تُغرس في <computed_review> بالبرومبت، فيعيدها
      MockLLM كما هي؛ والأرقام المخزّنة دائماً من حسابات هذا الملف، لا من الـ LLM.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agents.base_agent import BaseAgent
from agents.llm_client import PROMPTS_DIR
from agents.state import ScanState
from core.guardrails.output_validator import ReviewerOutput
from core.scoring.bands import classify_severity, distance_to_band_edge
from db.connection import get_session
from db.models import SeverityRule
from sqlalchemy import select

_jinja = Environment(
    loader=FileSystemLoader(PROMPTS_DIR), autoescape=select_autoescape(disabled_extensions=("j2",))
)

# عتبات افتراضية (تُستبدل من severity_rules.thresholds.confidence عند توفرها)
DEFAULT_CONF_REVIEW_THRESHOLD = 0.75
DEFAULT_CONF_CRITICAL_MIN = 0.90
BOUNDARY_EDGE_TOLERANCE = 0.5
SCORE_MIN, SCORE_MAX = 1.0, 10.0


# =====================================================================
# قواعد المراجعة الثمانية / The 8 explicit review rules
# =====================================================================
# كل قاعدة: predicate يعمل على التقييم + تعديل ثابت + سبب عربي موثق.
# لا يجوز إضافة قواعد ضمنية — أي حكم جديد = عنصر جديد هنا مع سبب مكتوب.
def _sev(a: dict[str, Any]) -> str:
    return str(a.get("severity") or "")


REVIEW_RULES: list[dict[str, Any]] = [
    {
        "id": "R1-weak-evidence-critical",
        "type": "evidence_downgrade",
        "adjustment": -1.5,
        "reason": "أدلة ضعيفة (evidence<5) لا تكفي لاعتماد فئة Critical",
        "predicate": lambda a: _sev(a) == "Critical" and float(a.get("evidence_score") or 0) < 5.0,
    },
    {
        "id": "R2-strong-evidence-low",
        "type": "evidence_upgrade",
        "adjustment": +1.5,
        "reason": "أدلة قوية جداً (evidence>8) تتعارض مع فئة Low",
        "predicate": lambda a: _sev(a) == "Low" and float(a.get("evidence_score") or 0) > 8.0,
    },
    {
        "id": "R3-high-context-low",
        "type": "context_upgrade",
        "adjustment": +1.0,
        "reason": "سياق التطبيق شديد الحساسية (context>8) يستبعد فئة Low",
        "predicate": lambda a: float(a.get("context_score") or 0) > 8.0 and _sev(a) == "Low",
    },
    {
        "id": "R4-low-context-critical",
        "type": "context_downgrade",
        "adjustment": -1.0,
        "reason": "سياق منخفض الحساسية (context<4) لا يسوّغ فئة Critical",
        "predicate": lambda a: float(a.get("context_score") or 0) < 4.0 and _sev(a) == "Critical",
    },
    {
        "id": "R5-crypto-medium-floor",
        "type": "category_upgrade",
        "adjustment": +1.0,
        "reason": "ثغرات MASVS-CRYPTO تصنيف Medium مُحجَّم تقليدياً (+1.0 كحد أدنى عادل)",
        "predicate": lambda a: str(a.get("masvs_category") or "").upper().startswith("MASVS-CRYPTO")
        and _sev(a) == "Medium",
    },
    {
        "id": "R6-code-quality-critical-cap",
        "type": "category_downgrade",
        "adjustment": -1.0,
        "reason": "مشكلات MASVS-CODE (جودة الكود) نادراً ما تستحق Critical",
        "predicate": lambda a: str(a.get("masvs_category") or "").upper().startswith("MASVS-CODE")
        and _sev(a) == "Critical",
    },
    {
        "id": "R7-low-confidence-critical",
        "type": "confidence_downgrade",
        "adjustment": -1.0,
        "reason": "ثقة منخفضة (conf<0.4) لا تدعم اعتماد Critical دون تثبّت",
        "predicate": lambda a: float(a.get("confidence_factor") or 0) < 0.4 and _sev(a) == "Critical",
    },
    {
        "id": "R8-high-confidence-low",
        "type": "confidence_upgrade",
        "adjustment": +0.5,
        "reason": "ثقة عالية جداً (conf>0.9) على فئة Low تستدعي رفعاً طفيفاً",
        "predicate": lambda a: float(a.get("confidence_factor") or 0) > 0.9 and _sev(a) == "Low",
    },
]


def apply_review_rules(assessment: dict[str, Any]) -> dict[str, Any]:
    """تطبيق REVIEW_RULES على التقييم — يعيد نتيجة المراجعة الحتمية.

    Returns:
        {"original_score", "reviewed_score", "original_severity",
         "final_severity", "adjustments": [{type, amount, reason}]}
    """
    original_score = float(assessment.get("final_score") or 0.0)
    original_severity = _sev(assessment)
    adjustments: list[dict[str, Any]] = []
    reviewed = original_score
    for rule in REVIEW_RULES:
        predicate: Callable[[dict[str, Any]], bool] = rule["predicate"]
        if predicate(assessment):
            reviewed += float(rule["adjustment"])
            adjustments.append(
                {
                    "type": rule["type"],
                    "amount": rule["adjustment"],
                    "reason": rule["reason"],
                    "rule_id": rule["id"],
                }
            )
    reviewed = round(max(SCORE_MIN, min(SCORE_MAX, reviewed)), 4)
    final_severity = classify_severity(reviewed) if adjustments else original_severity
    return {
        "original_score": original_score,
        "reviewed_score": reviewed,
        "original_severity": original_severity,
        "final_severity": final_severity,
        "adjustments": adjustments,
    }


def needs_human_review(
    assessment: dict[str, Any],
    conf_review_threshold: float = DEFAULT_CONF_REVIEW_THRESHOLD,
    conf_critical_min: float = DEFAULT_CONF_CRITICAL_MIN,
) -> tuple[bool, list[str]]:
    """المعايير الثلاثة الدقيقة للتصعيد البشري — يعيد (flag, reasons)."""
    reasons: list[str] = []
    conf = float(assessment.get("confidence_factor") or 0.0)
    score = float(assessment.get("final_score") or 0.0)

    if conf < conf_review_threshold:
        reasons.append(f"الثقة {conf:.2f} < عتبة المراجعة {conf_review_threshold}")
    edge_distance = distance_to_band_edge(score)
    if edge_distance <= BOUNDARY_EDGE_TOLERANCE:
        reasons.append(f"منطقة حدّية: |score − حد الفئة| = {edge_distance:.2f} ≤ {BOUNDARY_EDGE_TOLERANCE}")
    if _sev(assessment) == "Critical" and conf < conf_critical_min:
        reasons.append(f"فئة Critical مع ثقة {conf:.2f} < {conf_critical_min}")
    return (bool(reasons), reasons)


class ReviewerAgent(BaseAgent):
    """يراجع تقييمات Scorer تعديلاً محكوماً بالقواعد فقط."""

    def __init__(self, llm: Any = None, **kwargs: Any) -> None:
        super().__init__(name="reviewer", llm=llm, **kwargs)

    # ------------------------------------------------------------------
    async def run(self, state: ScanState) -> dict[str, Any]:
        thresholds = self._load_thresholds()
        conf_review = float(
            thresholds.get("review", thresholds.get("review_threshold", DEFAULT_CONF_REVIEW_THRESHOLD))
        )
        conf_critical = float(thresholds.get("critical_min", DEFAULT_CONF_CRITICAL_MIN))

        reviewed_assessments: list[dict[str, Any]] = []
        scan_db_id = state.db_scan_id

        for assessment in state.assessments:
            review = apply_review_rules(assessment)
            flag, reasons = needs_human_review(
                assessment, conf_review, conf_critical
            )
            review["requires_human_review"] = flag
            review["human_review_reasons"] = reasons

            # ملاحظات LLM تفسيرية فقط — الأرقام كلها محسوبة هنا
            review["review_notes"] = await self._llm_review_notes(
                assessment=assessment, computed_review=review, scan_id=scan_db_id
            )

            merged = dict(assessment)
            merged.update(review)
            # severity المخزّنة = ما بعد المراجعة (final_score يبقى قيمة المحرك)
            merged["severity"] = review["final_severity"]
            merged["review_status"] = "pending" if flag else "approved"
            reviewed_assessments.append(merged)

        return {
            "assessments": reviewed_assessments,
            "current_stage": "review",
        }

    # ------------------------------------------------------------------
    # ملاحظات LLM / LLM-authored notes (numbers locked)
    # ------------------------------------------------------------------
    async def _llm_review_notes(
        self,
        assessment: dict[str, Any],
        computed_review: dict[str, Any],
        scan_id: int | None,
    ) -> str:
        """برومبت reviewer.j2 — <computed_review> يحمل القرار الحتمي كاملاً."""
        prompt = _jinja.get_template("reviewer.j2").render(
            assessment_json=json.dumps(assessment, ensure_ascii=False, indent=2)[:3000],
            review_rules_text=self._rules_text(),
            computed_review_json=json.dumps(computed_review, ensure_ascii=False, indent=2),
        )
        try:
            output = await self.call_llm_structured(
                prompt, ReviewerOutput, scan_id=scan_id, max_retries=1
            )
            return output.review_notes or self._deterministic_notes(computed_review)
        except Exception:
            return self._deterministic_notes(computed_review)

    # ------------------------------------------------------------------
    # أدوات مساعدة / Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _rules_text() -> str:
        rows = []
        for i, rule in enumerate(REVIEW_RULES, 1):
            rows.append(f"{i}. [{rule['id']}] تعديل {rule['adjustment']:+.1f} — {rule['reason']}")
        return "\n".join(rows)

    @staticmethod
    def _deterministic_notes(review: dict[str, Any]) -> str:
        """ملاحظات حتمية عند تعذر اللجوء للـ LLM."""
        if not review["adjustments"]:
            base = "لا تعديلات: لم تنطبق أي قاعدة مراجعة."
        else:
            parts = [f"- {adj['reason']} ({adj['amount']:+.1f})" for adj in review["adjustments"]]
            base = "التعديلات المطبقة:\n" + "\n".join(parts)
        if review["requires_human_review"]:
            base += "\n⚠️ يتطلب مراجعة بشرية: " + "؛ ".join(review["human_review_reasons"])
        return base

    @staticmethod
    def _load_thresholds() -> dict[str, Any]:
        """قراءة thresholds.confidence من القاعدة النشطة (v1.1+)."""
        try:
            with get_session() as session:
                rule = session.scalar(
                    select(SeverityRule).where(SeverityRule.active.is_(True))
                )
                if rule is not None:
                    return dict((rule.thresholds or {}).get("confidence") or {})
        except Exception:
            pass
        return {}
