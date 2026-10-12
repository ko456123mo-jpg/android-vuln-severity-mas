"""CRUD التقييمات / Assessments repository."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Assessment
from db.repositories import row_to_dict


def create(
    vulnerability_id: int,
    base_score: float | None = None,
    context_score: float | None = None,
    evidence_score: float | None = None,
    confidence_factor: float | None = None,
    final_score: float | None = None,
    severity: str | None = None,
    rationale: str | None = None,
    rule_version: str | None = None,
    assessed_by: str = "agent",
) -> dict[str, Any]:
    """تسجيل تقييم لثغرة (تقييم واحد لكل ثغرة — UNIQUE)."""
    with get_session() as session:
        assessment = Assessment(
            vulnerability_id=vulnerability_id,
            base_score=base_score,
            context_score=context_score,
            evidence_score=evidence_score,
            confidence_factor=confidence_factor,
            final_score=final_score,
            severity=severity,
            rationale=rationale,
            rule_version=rule_version,
            assessed_by=assessed_by,
            review_status="pending",
        )
        session.add(assessment)
        session.flush()
        session.refresh(assessment)
        return row_to_dict(assessment)


def upsert_by_vuln(
    vulnerability_id: int,
    base_score: float | None = None,
    context_score: float | None = None,
    evidence_score: float | None = None,
    confidence_factor: float | None = None,
    final_score: float | None = None,
    severity: str | None = None,
    rationale: str | None = None,
    rule_version: str | None = None,
    assessed_by: str = "agent",
    review_status: str | None = None,
    reviewed_by: int | None = None,
    review_notes: str | None = None,
) -> dict[str, Any]:
    """إدراج/تحديث تقييم الثغرة (idem-potent لأجل إعادة تشغيل الـ pipeline).

    تقييم واحد لكل ثغرة (UNIQUE vulnerability_id): إن وُجد حُدّثت حقوله،
    وإلا أُنشئ سجل جديد. لا تمس مراجعة بشرية سابقة ما لم تُمرَّر قيم
    review_* صراحةً.
    """
    with get_session() as session:
        assessment = session.scalar(
            select(Assessment).where(Assessment.vulnerability_id == vulnerability_id)
        )
        if assessment is None:
            assessment = Assessment(vulnerability_id=vulnerability_id, review_status="pending")
            session.add(assessment)
        assessment.base_score = base_score
        assessment.context_score = context_score
        assessment.evidence_score = evidence_score
        assessment.confidence_factor = confidence_factor
        assessment.final_score = final_score
        assessment.severity = severity
        assessment.rationale = rationale
        assessment.rule_version = rule_version
        assessment.assessed_by = assessed_by
        if review_status is not None:
            assessment.review_status = review_status
        if reviewed_by is not None:
            assessment.reviewed_by = reviewed_by
        if review_notes is not None:
            assessment.review_notes = review_notes
        session.flush()
        session.refresh(assessment)
        return row_to_dict(assessment)


def get_by_vuln(vulnerability_id: int) -> dict[str, Any] | None:
    """جلب تقييم ثغرة معيّنة."""
    with get_session() as session:
        assessment = session.scalar(
            select(Assessment).where(Assessment.vulnerability_id == vulnerability_id)
        )
        return row_to_dict(assessment) if assessment else None


def update_review(
    assessment_id: int,
    review_status: str,
    reviewed_by: int,
    review_notes: str | None = None,
) -> dict[str, Any] | None:
    """تحديث نتيجة المراجعة البشرية (approved/rejected)."""
    with get_session() as session:
        assessment = session.get(Assessment, assessment_id)
        if assessment is None:
            return None
        assessment.review_status = review_status
        assessment.reviewed_by = reviewed_by
        if review_notes is not None:
            assessment.review_notes = review_notes
        session.flush()
        session.refresh(assessment)
        return row_to_dict(assessment)


def list_by_severity(severity: str) -> list[dict[str, Any]]:
    """سرد التقييمات حسب فئة الخطورة (Critical/High/Medium/Low)."""
    with get_session() as session:
        assessments = session.scalars(
            select(Assessment)
            .where(Assessment.severity == severity)
            .order_by(Assessment.final_score.desc())
        ).all()
        return [row_to_dict(a) for a in assessments]


# ---------------------------------------------------------------------
# إضافات المرحلة 6 (API): قراءات مساندة للواجهة
# ---------------------------------------------------------------------
def get_by_id(assessment_id: int) -> dict[str, Any] | None:
    """جلب تقييم بمعرّفه."""
    with get_session() as session:
        assessment = session.get(Assessment, assessment_id)
        return row_to_dict(assessment) if assessment else None


def list_by_vuln_ids(vuln_ids: list[int]) -> list[dict[str, Any]]:
    """سرد تقييمات مجموعة ثغرات (لتغذية /scans/{id}/assessments)."""
    if not vuln_ids:
        return []
    with get_session() as session:
        assessments = session.scalars(
            select(Assessment).where(Assessment.vulnerability_id.in_(vuln_ids))
        ).all()
        return [row_to_dict(a) for a in assessments]


def list_filtered(
    severity: str | None = None,
    review_status: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """سرد مُفلتَر (خطورة/حالة مراجعة) — ترتيب تنازلي بـ final_score."""
    with get_session() as session:
        stmt = select(Assessment)
        if severity:
            stmt = stmt.where(Assessment.severity == severity)
        if review_status:
            stmt = stmt.where(Assessment.review_status == review_status)
        assessments = session.scalars(
            stmt.order_by(Assessment.final_score.desc()).limit(limit)
        ).all()
        return [row_to_dict(a) for a in assessments]
