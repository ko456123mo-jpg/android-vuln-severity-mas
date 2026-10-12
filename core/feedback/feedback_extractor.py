"""مستخرج أمثلة Few-Shot من التصحيحات البشرية.

عندما يصحح المراجع البشري تقييماً، يُنتَج تلقائياً مثال منظم يُحقن لاحقاً
في برومبتات Scorer/Reviewer (تحسين مستمر بلا إعادة تدريب).
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Assessment, Correction, FeedbackExample, Vulnerability


def build_prompt_payload(
    correction: dict[str, Any], assessment: dict[str, Any], vulnerability: dict[str, Any]
) -> dict[str, Any]:
    """بناء الحمولة المنظمة للمثال (تُخزَّن JSON في feedback_examples)."""
    return {
        "vuln_pattern": vulnerability.get("title", ""),
        "masvs_category": vulnerability.get("masvs_category"),
        "cwe_id": vulnerability.get("cwe_id"),
        "context_summary": _summarize_rationale(assessment.get("rationale") or ""),
        "original_severity": correction.get("original_severity"),
        "original_score": correction.get("original_score"),
        "corrected_severity": correction.get("corrected_severity"),
        "corrected_score": correction.get("corrected_score"),
        "reason": correction.get("reason", ""),
    }


def _summarize_rationale(rationale: str) -> str:
    """خلاصة قصيرة من سياق التقييم (أول سطرين من الـ rationale الحتمي)."""
    lines = [line for line in rationale.splitlines() if line.strip()][:2]
    return " / ".join(lines)[:300]


def extract_feedback_example(
    correction: dict[str, Any], assessment: dict[str, Any], vulnerability: dict[str, Any]
) -> dict[str, Any]:
    """يستخرج مثال Few-Shot كامل من تصحيح بشري — جاهز للإدراج."""
    payload = build_prompt_payload(correction, assessment, vulnerability)
    return {
        "correction_id": correction["id"],
        "example_type": "severity_correction",
        "prompt_payload": payload,
        "active": True,
    }


def select_fewshot_examples(masvs_category: str, limit: int = 5) -> list[dict[str, Any]]:
    """يختار أمثلة Few-Shot مناسبة لتقييم ثغرة جديدة.

    المعايير: نفس فئة MASVS + active=True + الأحدث أولاً + العود نصياً على
    prompt_payload حتى يلتصق بالبرومبت مباشرة.
    """
    with get_session() as session:
        stmt = (
            select(FeedbackExample, Vulnerability)
            .join(Correction, FeedbackExample.correction_id == Correction.id)
            .join(Assessment, Correction.assessment_id == Assessment.id)
            .join(Vulnerability, Assessment.vulnerability_id == Vulnerability.id)
            .where(Vulnerability.masvs_category == masvs_category)
            .where(FeedbackExample.active.is_(True))
            .order_by(FeedbackExample.id.desc())
            .limit(limit)
        )
        rows = session.execute(stmt).all()
    return [
        {
            "example_id": example.id,
            "example_type": example.example_type,
            "prompt_payload": example.prompt_payload,
        }
        for example, _vuln in rows
    ]
