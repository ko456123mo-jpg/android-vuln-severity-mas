"""موجّه الثغرات / Findings API (المرحلة 6).

    GET /findings/{vuln_id}             تفاصيل الثغرة (+ سياق تطبيقها وتقييمها)
    GET /findings/{vuln_id}/evidence    الأدلة (vulnerability_findings) بكل مصدر
    GET /findings/{vuln_id}/assessment  التقييم الكامل بمعادلة الدرجة
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from sqlalchemy import select

from api import authz
from api.deps import get_current_user
from api.schemas import AssessmentDetailOut, EvidenceBrief
from db.connection import get_session
from db.models import Tool
from db.repositories import applications_repo, assessments_repo, findings_repo

router = APIRouter(prefix="/findings", tags=["findings"])


# ── مخططات ───────────────────────────────────────────────────────────
class VulnerabilityOut(BaseModel):
    """ثغرة مسجَّلة."""

    id: int
    application_id: int
    title: str
    description: Optional[str] = None
    masvs_category: Optional[str] = None
    cwe_id: Optional[str] = None
    status: str = "open"
    discovered_at: Optional[datetime] = None


class VulnerabilityDetailOut(VulnerabilityOut):
    """ثغرة + تطبيقها + أدلتها وتقييمها."""

    application_name: Optional[str] = None
    package_name: Optional[str] = None
    evidence: EvidenceBrief = EvidenceBrief()
    assessment: Optional[AssessmentDetailOut] = None


class FindingEvidenceOut(BaseModel):
    """دليل واحد (صف vulnerability_findings) مع بيانات أداته."""

    id: int
    vulnerability_id: int
    scan_id: int
    tool_id: int
    tool_name: Optional[str] = None
    tool_category: Optional[str] = None
    tool_reliability: Optional[float] = None
    location: Optional[str] = None
    evidence_type: Optional[str] = None
    artifact_ref: Optional[str] = None
    created_at: Optional[datetime] = None


# ── مساعدات ──────────────────────────────────────────────────────────
def _tool_meta() -> dict[int, dict[str, Any]]:
    """خريطة tools.id → بيانات الأداة."""
    with get_session() as session:
        return {
            t.id: {"name": t.name, "category": t.category, "reliability": t.reliability_score}
            for t in session.scalars(select(Tool)).all()
        }


def _ensure_vuln(vuln_id: int, user: dict[str, Any]) -> dict[str, Any]:
    """جلب ثغرة أو 404، وفرض الملكية (403) عبر سلسلة تطبيقها/مشروعها."""
    vuln = findings_repo.get_vulnerability(vuln_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"vulnerability {vuln_id} غير موجود")
    authz.ensure_vulnerability_access(vuln, user)
    return vuln


# ── المسارات ─────────────────────────────────────────────────────────
@router.get("/{vuln_id}", response_model=VulnerabilityDetailOut)
async def get_vulnerability(
    vuln_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> VulnerabilityDetailOut:
    """تفاصيل ثغرة + تطبيقها + ملخص أدلتها + تقييمها."""
    vuln = _ensure_vuln(vuln_id, current_user)
    app_row = applications_repo.get_by_id(vuln["application_id"]) or {}
    evidence_rows = findings_repo.list_by_vuln(vuln_id)
    tools = _tool_meta()
    assessment = assessments_repo.get_by_vuln(vuln_id)
    return VulnerabilityDetailOut(
        **{k: v for k, v in vuln.items() if k in VulnerabilityOut.model_fields},
        application_name=app_row.get("name"),
        package_name=app_row.get("package_name"),
        evidence=EvidenceBrief(
            findings_count=len(evidence_rows),
            tools=[tools.get(f["tool_id"], {}).get("name", "unknown") for f in evidence_rows],
        ),
        assessment=AssessmentDetailOut(**assessment) if assessment else None,
    )


@router.get("/{vuln_id}/evidence", response_model=list[FindingEvidenceOut])
async def get_vulnerability_evidence(
    vuln_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> list[FindingEvidenceOut]:
    """كل الأدلة المرتبطة بالثغرة (static/dynamic) مع موثوقية كل أداة."""
    _ensure_vuln(vuln_id, current_user)
    tools = _tool_meta()
    results: list[FindingEvidenceOut] = []
    for row in findings_repo.list_by_vuln(vuln_id):
        meta = tools.get(row["tool_id"], {})
        results.append(
            FindingEvidenceOut(
                **{k: v for k, v in row.items() if k in FindingEvidenceOut.model_fields},
                tool_name=meta.get("name"),
                tool_category=meta.get("category"),
                tool_reliability=meta.get("reliability"),
            )
        )
    return results


@router.get("/{vuln_id}/assessment", response_model=AssessmentDetailOut)
async def get_vulnerability_assessment(
    vuln_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> AssessmentDetailOut:
    """التقييم الكامل (المكوّنات + final_score + rationale)."""
    _ensure_vuln(vuln_id, current_user)
    assessment = assessments_repo.get_by_vuln(vuln_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail=f"لا يوجد تقييم للثغرة {vuln_id}")
    return AssessmentDetailOut(**assessment)
