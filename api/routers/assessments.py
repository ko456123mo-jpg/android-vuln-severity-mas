"""موجّه التقييمات / Assessments API (المرحلة 6).

    GET /assessments        سرد (فلترة بالخطورة/حالة المراجعة) مع بيانات الثغرة
    GET /assessments/stats  توزيع الخطورة + حالات المراجعة + متوسط الدرجة
    GET /assessments/{id}   تفاصيل كاملة + تاريخ التصحيحات البشرية

تنبيه ترتيب المسارات: /stats مُعلَن قبل /{assessment_id} حتى لا يلتقطه
محوّل المسار الصحيح.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import case, func, select

from api import authz
from api.deps import get_current_user
from api.schemas import AssessmentDetailOut
from db.connection import get_session
from db.models import Application, Assessment, Correction, User, Vulnerability
from db.repositories import assessments_repo

router = APIRouter(prefix="/assessments", tags=["assessments"])

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


# ── مخططات ───────────────────────────────────────────────────────────
class AssessmentListItem(AssessmentDetailOut):
    """تقييم + بيانات الثغرة والتطبيق (لجدول الواجهة)."""

    vuln_title: Optional[str] = None
    cwe_id: Optional[str] = None
    masvs_category: Optional[str] = None
    application_id: Optional[int] = None
    application_name: Optional[str] = None


class AssessmentStatsOut(BaseModel):
    """إحصاءات التقييمات الكلية."""

    total: int = 0
    severity_distribution: dict[str, int] = {}
    review_status_counts: dict[str, int] = {}
    avg_final_score: Optional[float] = None
    max_final_score: Optional[float] = None
    min_final_score: Optional[float] = None


class CorrectionOut(BaseModel):
    """تصحيح بشري سابق."""

    id: int
    reviewer_id: int
    reviewer_username: Optional[str] = None
    original_severity: Optional[str] = None
    corrected_severity: Optional[str] = None
    original_score: Optional[float] = None
    corrected_score: Optional[float] = None
    reason: str
    corrected_at: Optional[datetime] = None


class AssessmentFullOut(AssessmentDetailOut):
    """تقييم كامل + ثغرته + تاريخ التصحيحات."""

    vuln_title: Optional[str] = None
    cwe_id: Optional[str] = None
    masvs_category: Optional[str] = None
    application_id: Optional[int] = None
    application_name: Optional[str] = None
    corrections: list[CorrectionOut] = []


# ── مساعدات ──────────────────────────────────────────────────────────
def _vuln_meta(vuln_ids: list[int]) -> dict[int, dict[str, Any]]:
    """بيانات الثغرات (عنوان/cwe/masvs/التطبيق) لدمجها مع التقييمات."""
    if not vuln_ids:
        return {}
    with get_session() as session:
        rows = session.execute(
            select(
                Vulnerability.id,
                Vulnerability.title,
                Vulnerability.cwe_id,
                Vulnerability.masvs_category,
                Vulnerability.application_id,
                Application.name,
            )
            .join(Application, Application.id == Vulnerability.application_id)
            .where(Vulnerability.id.in_(vuln_ids))
        ).all()
    return {
        int(vid): {
            "vuln_title": title,
            "cwe_id": cwe,
            "masvs_category": masvs,
            "application_id": app_id,
            "application_name": app_name,
        }
        for vid, title, cwe, masvs, app_id, app_name in rows
    }


# ── المسارات ─────────────────────────────────────────────────────────
@router.get("", response_model=list[AssessmentListItem])
async def list_assessments(
    severity: Optional[Literal["Critical", "High", "Medium", "Low"]] = None,
    review_status: Optional[Literal["pending", "approved", "rejected"]] = None,
    limit: int = 200,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[AssessmentListItem]:
    """سرد التقييمات مع فلترة الخطورة/حالة المراجعة (قائمة فرز: admin/reviewer)."""
    authz.require_reviewer(current_user)
    rows = assessments_repo.list_filtered(
        severity=severity, review_status=review_status, limit=limit
    )
    meta = _vuln_meta([r["vulnerability_id"] for r in rows])
    return [
        AssessmentListItem(
            **{k: v for k, v in r.items() if k in AssessmentDetailOut.model_fields},
            **meta.get(r["vulnerability_id"], {}),
        )
        for r in rows
    ]


@router.get("/stats", response_model=AssessmentStatsOut)
async def assessment_stats(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> AssessmentStatsOut:
    """إحصاءات كلية: توزيع الخطورة وحالات المراجعة (admin/reviewer فقط)."""
    authz.require_reviewer(current_user)
    with get_session() as session:
        severity_rows = session.execute(
            select(Assessment.severity, func.count().label("n"))
            .group_by(Assessment.severity)
        ).all()
        status_rows = session.execute(
            select(Assessment.review_status, func.count().label("n"))
            .group_by(Assessment.review_status)
        ).all()
        agg = session.execute(
            select(
                func.count(Assessment.id),
                func.avg(Assessment.final_score),
                func.max(Assessment.final_score),
                func.min(Assessment.final_score),
            )
        ).one()

    severity_distribution = {s: int(n or 0) for s, n in severity_rows if s is not None}
    return AssessmentStatsOut(
        total=int(agg[0] or 0),
        severity_distribution={
            s: severity_distribution.get(s, 0) for s in _SEVERITY_ORDER
        },
        review_status_counts={s: int(n or 0) for s, n in status_rows if s is not None},
        avg_final_score=round(float(agg[1]), 4) if agg[1] is not None else None,
        max_final_score=round(float(agg[2]), 4) if agg[2] is not None else None,
        min_final_score=round(float(agg[3]), 4) if agg[3] is not None else None,
    )


@router.get("/{assessment_id}", response_model=AssessmentFullOut)
async def get_assessment(
    assessment_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> AssessmentFullOut:
    """تفاصيل تقييم + ثغرته + كل التصحيحات البشرية السابقة عليه."""
    assessment = assessments_repo.get_by_id(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail=f"assessment {assessment_id} غير موجود")
    if not authz.is_reviewer(current_user):  # reviewer يمر؛ غيره يجب أن يكون المالك
        authz.ensure_assessment_access(assessment, current_user)

    meta = _vuln_meta([assessment["vulnerability_id"]]).get(
        assessment["vulnerability_id"], {}
    )
    with get_session() as session:
        correction_rows = session.execute(
            select(Correction, User.username)
            .outerjoin(User, User.id == Correction.reviewer_id)
            .where(Correction.assessment_id == assessment_id)
            .order_by(Correction.corrected_at.desc(), Correction.id.desc())
        ).all()

    corrections = [
        CorrectionOut(
            **{
                k: v
                for k, v in row_c.__dict__.items()
                if k in CorrectionOut.model_fields and not k.startswith("_")
            },
            reviewer_username=username,
        )
        for row_c, username in correction_rows
    ]
    return AssessmentFullOut(
        **{k: v for k, v in assessment.items() if k in AssessmentDetailOut.model_fields},
        **meta,
        corrections=corrections,
    )
