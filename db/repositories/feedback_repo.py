"""حلقة التغذية الراجعة / Feedback repository (corrections + examples)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Correction, FeedbackExample
from db.repositories import row_to_dict


def create_correction(
    assessment_id: int,
    reviewer_id: int,
    original_severity: str | None = None,
    corrected_severity: str | None = None,
    original_score: float | None = None,
    corrected_score: float | None = None,
    reason: str = "",
) -> dict[str, Any]:
    """تسجيل تصحيح بشري على تقييم (حلقة HITL)."""
    with get_session() as session:
        correction = Correction(
            assessment_id=assessment_id,
            reviewer_id=reviewer_id,
            original_severity=original_severity,
            corrected_severity=corrected_severity,
            original_score=original_score,
            corrected_score=corrected_score,
            reason=reason,
        )
        session.add(correction)
        session.flush()
        session.refresh(correction)
        return row_to_dict(correction)


def create_feedback(
    correction_id: int,
    example_type: str = "few_shot",
    prompt_payload: dict[str, Any] | None = None,
    embedding: bytes | None = None,
    active: bool = True,
) -> dict[str, Any]:
    """تحويل تصحيح إلى مثال few-shot يُحقن لاحقاً في برومبتات الوكلاء."""
    with get_session() as session:
        example = FeedbackExample(
            correction_id=correction_id,
            example_type=example_type,
            prompt_payload=prompt_payload,
            embedding=embedding,
            active=active,
        )
        session.add(example)
        session.flush()
        session.refresh(example)
        return row_to_dict(example)


def get_active_examples(example_type: str | None = None) -> list[dict[str, Any]]:
    """سرد الأمثلة النشطة (لحقنها في برومبت Scorer/Reviewer)."""
    with get_session() as session:
        stmt = select(FeedbackExample).where(FeedbackExample.active.is_(True))
        if example_type:
            stmt = stmt.where(FeedbackExample.example_type == example_type)
        examples = session.scalars(stmt.order_by(FeedbackExample.id.desc())).all()
        return [row_to_dict(e) for e in examples]
