"""Output Validator — التحقق من مخرجات LLM عبر Pydantic + حلقة إصلاح.

يُستخدم مستقلاً عن BaseAgent عندما تصل سلسلة نصية خام ونريد التحقق منها،
مع إعادة إرسال الخطأ للنموذج حتى ينجح (retry-with-error) أو الاستنزاف.
"""
from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any, Literal, Optional, TypeVar

from pydantic import BaseModel, Field, ValidationError

SchemaT = TypeVar("SchemaT", bound=BaseModel)

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


# =====================================================================
# مخططات مخرجات الوكلاء / Agent output contracts
# =====================================================================
class ConfidenceBreakdown(BaseModel):
    tool_count_score: float = Field(ge=0.0, le=1.0)
    evidence_quality_score: Any  # تسمية مستوى ("specific"...)
    tool_reliability_avg: float = Field(ge=0.0, le=1.0)
    reproducibility_score: Any  # تسمية ("twice"...)


class ScorerOutput(BaseModel):
    """عقد مخرجات وكيل التقييم (scorer.j2)."""

    base_score: float = Field(ge=0.0, le=10.0)
    context_score: float = Field(ge=0.0, le=10.0)
    confidence_factor: float = Field(ge=0.0, le=1.0)
    evidence_score: float = Field(ge=0.0, le=10.0)
    final_score: float = Field(ge=0.0, le=10.0)
    severity: Literal["Critical", "High", "Medium", "Low"]
    confidence_breakdown: ConfidenceBreakdown
    reasoning: str = ""


class ReviewAdjustment(BaseModel):
    type: str
    amount: float
    reason: str = ""


class ReviewerOutput(BaseModel):
    """عقد مخرجات وكيل المراجعة (reviewer.j2)."""

    original_score: float = Field(ge=0.0, le=10.0)
    reviewed_score: float = Field(ge=0.0, le=10.0)
    original_severity: str
    final_severity: Literal["Critical", "High", "Medium", "Low"]
    adjustments: list[ReviewAdjustment] = []
    review_notes: str = ""
    requires_human_review: bool


class ExecutiveSummary(BaseModel):
    vulnerability_id: int
    title_ar: str = Field(min_length=3)
    impact_ar: str = ""
    action_ar: str = ""
    timeline_ar: str = ""


class ReportOutput(BaseModel):
    """عقد مخرجات وكيل التقارير (report_agent.j2)."""

    executive_summaries: list[ExecutiveSummary] = []
    overall_risk: Literal["منخفض", "متوسط", "مرتفع", "حرج"]


# =====================================================================
# محلل ومُصلح / Parser + repair loop
# =====================================================================
def extract_json(text: str) -> Any:
    """استخراج JSON من نص (يدعم code fences والكتلة المتوازنة)."""
    fence = _JSON_BLOCK.search(text)
    if fence:
        return json.loads(fence.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError(f"لم يُعثر على JSON في النص: {text[:160]!r}")


class OutputValidationError(ValueError):
    """فشل التحقق بعد استنزاف محاولات الإصلاح."""


async def validate_with_repair(
    output: str,
    schema: type[SchemaT],
    llm_caller: Callable[[str], Awaitable[str]] | None = None,
    max_retries: int = 3,
    base_prompt: str = "",
) -> SchemaT:
    """تحليل JSON ثم التحقق Pydantic — مع حلقة إصلاح عبر LLM.

    ① حاول parse+validate للنص الأصلي.
    ② عند الفشل ووجود llm_caller: أرسل خطأ التحقق وأطلب JSON مصححاً.
    ③ كرر حتى max_retries ثم ارفع OutputValidationError.

    Args:
        output: النص الخام أو جملة البرومبت للمحاولة الأولى.
        schema: نموذج Pydantic المستهدف.
        llm_caller: دالة async(prompt) -> str (بدونها: محاولة واحدة فقط).
        max_retries: عدد محاولات الإصلاح عبر LLM بعد الأولى.
        base_prompt: سياق يُسبق طلبات الإصلاح (اختياري).
    """
    current = output
    last_error = "لم تبدأ المحاولة"
    for attempt in range(max_retries + 1):
        try:
            payload = current if isinstance(current, (dict, list)) else extract_json(current)
            return schema.model_validate(payload)
        except (ValueError, ValidationError) as exc:
            last_error = str(exc)[:400]
            if llm_caller is None or attempt >= max_retries:
                break
            repair_prompt = (
                f"{base_prompt}\n\n"
                f"⚠️ الناتج السابق لم يجتز التحقق في المحاولة {attempt + 1}:\n{last_error}\n"
                f"أعد JSON صالحاً يطابق المخطط المطلوب فقط، بلا أي نص إضافي."
                if base_prompt
                else (
                    f"⚠️ validation failed (attempt {attempt + 1}): {last_error}\n"
                    f"أعد JSON صالحاً فقط بلا نص إضافي."
                )
            )
            current = await llm_caller(repair_prompt)
    raise OutputValidationError(
        f"فشل التحقق بعد {max_retries + 1} محاولة: {last_error}"
    )
