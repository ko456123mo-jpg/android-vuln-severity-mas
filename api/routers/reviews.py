"""موجّه المراجعة البشرية / Human review queue API (المرحلة 5).

واجهة برمجية كاملة قبل بناء واجهة Streamlit (المرحلة 7):
    GET  /reviews/pending                 قائمة التقييمات المعلّقة
    GET  /reviews/{assessment_id}         تفاصيل تقييم + تاريخ التصحيحات
    POST /reviews/{assessment_id}/correct إرسال تصحيح بشري (HITL)
    GET  /reviews/stats                   إحصائيات القائمة
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api import authz
from api.deps import get_current_user
from core.feedback import CorrectionManager

router = APIRouter(prefix="/reviews", tags=["reviews"])


class CorrectionInput(BaseModel):
    """حمولة تصحيح بشري — corrected_score منفصل ولا يمس final_score أبداً."""

    corrected_severity: Literal["Critical", "High", "Medium", "Low"]
    corrected_score: float = Field(ge=0.0, le=10.0)
    reason: str = Field(min_length=3, max_length=2000)


@router.get("/pending")
async def list_pending_reviews(
    limit: int = 50,
    severity: Optional[str] = None,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """سرد التقييمات المعلّقة مرتبةً بخطورتها — حلقة المراجعة: admin/reviewer."""
    authz.require_reviewer(current_user)
    return CorrectionManager().list_pending_reviews(limit=limit, severity=severity)


def _ensure_correction_rights(assessment_id: int, user: dict[str, Any]) -> None:
    """حقّ التصحيح: admin/reviewer، أو مالك سلسلة التقييم (وإلا 403/404)."""
    if authz.is_reviewer(user):
        return
    authz.ensure_assessment_id_access(assessment_id, user)


@router.post("/{assessment_id}/correct")
async def submit_correction(
    assessment_id: int,
    correction: CorrectionInput,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """إرسال تصحيح بشري — يحدَّث التقييم ويُولَّد feedback_example تلقائياً."""
    _ensure_correction_rights(assessment_id, current_user)
    try:
        correction_id = CorrectionManager().submit_correction(
            assessment_id=assessment_id,
            reviewer_id=current_user["id"],
            corrected_severity=correction.corrected_severity,
            corrected_score=correction.corrected_score,
            reason=correction.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404 if "غير موجود" in str(exc) else 422, detail=str(exc)) from exc
    return {
        "correction_id": correction_id,
        "assessment_id": assessment_id,
        "reviewer": current_user["username"],
        "status": "approved",
    }


@router.get("/stats")
async def get_review_stats(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """إحصائيات قائمة المراجعة (pending/approved/rejected + تتبع التصحيحات)."""
    authz.require_reviewer(current_user)
    return CorrectionManager().get_review_queue_stats()


@router.get("/{assessment_id}")
async def get_assessment_details(
    assessment_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """تفاصيل التقييم للمراجعة (درجاته + الثغرة + التصحيحات السابقة)."""
    _ensure_correction_rights(assessment_id, current_user)
    details = CorrectionManager().get_assessment_details(assessment_id)
    if details is None:
        raise HTTPException(status_code=404, detail=f"assessment {assessment_id} غير موجود")
    return details


