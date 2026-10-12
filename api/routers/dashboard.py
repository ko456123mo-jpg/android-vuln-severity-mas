"""موجّه لوحة المعلومات / Dashboard API (المرحلة 6).

    GET /dashboard/summary         مؤشرات الأداء العامة (KPIs)
    GET /dashboard/severity_chart  توزيع الخطورة (للرسم الدائري)
    GET /dashboard/recent_scans    آخر 10 فحوص
    GET /dashboard/top_vulns       أعلى 10 ثغرات بالدرجة النهائية
    GET /dashboard/trends          اتجاهات زمنية (7/30 يوم)

كل الاستعلامات تجميعية للقراءة فقط (SELECT — بلا كتابة مباشرة).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from api.deps import require_admin
from db.connection import get_session
from db.models import (
    Application,
    Assessment,
    Correction,
    FeedbackExample,
    Project,
    Scan,
    Vulnerability,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


# ── مخططات ───────────────────────────────────────────────────────────
class SummaryOut(BaseModel):
    """KPIs عامة للنظام."""

    total_projects: int = 0
    total_applications: int = 0
    total_scans: int = 0
    running_scans: int = 0
    total_vulnerabilities: int = 0
    total_assessments: int = 0
    pending_reviews: int = 0
    total_corrections: int = 0
    active_feedback_examples: int = 0
    avg_final_score: Optional[float] = None


class SeverityBucket(BaseModel):
    """شق واحد من رسم توزيع الخطورة."""

    severity: str
    count: int


class RecentScanOut(BaseModel):
    """صف فحص حديث."""

    scan_id: int
    application_id: int
    application_name: Optional[str] = None
    package_name: Optional[str] = None
    project_name: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    total_duration_ms: int = 0
    error_message: Optional[str] = None


class TopVulnOut(BaseModel):
    """ثغرة في قائمة الأعلى خطورة."""

    vulnerability_id: int
    title: str
    cwe_id: Optional[str] = None
    masvs_category: Optional[str] = None
    severity: Optional[str] = None
    final_score: Optional[float] = None
    application_name: Optional[str] = None


class DayCount(BaseModel):
    """قيمة يومية في الاتجاهات الزمنية."""

    date: str
    count: int


class TrendsOut(BaseModel):
    """اتجاهات زمنية للفحوص والثغرات."""

    days: int
    scans: list[DayCount] = []
    vulnerabilities: list[DayCount] = []


# ── المسارات ─────────────────────────────────────────────────────────
@router.get("/summary", response_model=SummaryOut)
async def dashboard_summary(
    _admin: dict[str, Any] = Depends(require_admin),
) -> SummaryOut:
    """مؤشرات الأداء: عدادات الكيانات + متوسط الدرجة النهائية."""
    with get_session() as session:
        counts = {
            "total_projects": session.scalar(
                select(func.count()).select_from(Project).where(Project.status == "active")
            ),
            "total_applications": session.scalar(select(func.count()).select_from(Application)),
            "total_scans": session.scalar(select(func.count()).select_from(Scan)),
            "running_scans": session.scalar(
                select(func.count()).select_from(Scan).where(Scan.status == "running")
            ),
            "total_vulnerabilities": session.scalar(
                select(func.count()).select_from(Vulnerability)
            ),
            "total_assessments": session.scalar(select(func.count()).select_from(Assessment)),
            "pending_reviews": session.scalar(
                select(func.count())
                .select_from(Assessment)
                .where(Assessment.review_status == "pending")
            ),
            "total_corrections": session.scalar(select(func.count()).select_from(Correction)),
            "active_feedback_examples": session.scalar(
                select(func.count())
                .select_from(FeedbackExample)
                .where(FeedbackExample.active.is_(True))
            ),
            "avg_final_score": session.scalar(select(func.avg(Assessment.final_score))),
        }
    avg = counts.pop("avg_final_score")
    return SummaryOut(
        **{k: int(v or 0) for k, v in counts.items()},
        avg_final_score=round(float(avg), 4) if avg is not None else None,
    )


@router.get("/severity_chart", response_model=list[SeverityBucket])
async def severity_chart(
    _admin: dict[str, Any] = Depends(require_admin),
) -> list[SeverityBucket]:
    """توزيع الخطورة بترتيب ثابت Critical→Low (قيم صفرية للفئات الغائبة)."""
    with get_session() as session:
        rows = session.execute(
            select(Assessment.severity, func.count().label("n")).group_by(Assessment.severity)
        ).all()
    counts = {s: int(n or 0) for s, n in rows if s is not None}
    return [SeverityBucket(severity=s, count=counts.get(s, 0)) for s in _SEVERITY_ORDER]


@router.get("/recent_scans", response_model=list[RecentScanOut])
async def recent_scans(
    limit: int = 10,
    _admin: dict[str, Any] = Depends(require_admin),
) -> list[RecentScanOut]:
    """آخر الفحوص مع أسماء التطبيق/المشروع."""
    with get_session() as session:
        rows = session.execute(
            select(Scan, Application.name, Application.package_name, Project.name)
            .join(Application, Application.id == Scan.application_id)
            .outerjoin(Project, Project.id == Application.project_id)
            .order_by(Scan.id.desc())
            .limit(limit)
        ).all()
    return [
        RecentScanOut(
            scan_id=scan.id,
            application_id=scan.application_id,
            application_name=app_name,
            package_name=package_name,
            project_name=project_name,
            status=scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            total_duration_ms=scan.total_duration_ms or 0,
            error_message=scan.error_message,
        )
        for scan, app_name, package_name, project_name in rows
    ]


@router.get("/top_vulns", response_model=list[TopVulnOut])
async def top_vulns(
    limit: int = 10,
    _admin: dict[str, Any] = Depends(require_admin),
) -> list[TopVulnOut]:
    """أعلى الثغرات بدرجة final_score (المصدر: جدول التقييمات)."""
    with get_session() as session:
        rows = session.execute(
            select(
                Vulnerability.id,
                Vulnerability.title,
                Vulnerability.cwe_id,
                Vulnerability.masvs_category,
                Assessment.severity,
                Assessment.final_score,
                Application.name,
            )
            .join(Assessment, Assessment.vulnerability_id == Vulnerability.id)
            .join(Application, Application.id == Vulnerability.application_id)
            .order_by(Assessment.final_score.desc())
            .limit(limit)
        ).all()
    return [
        TopVulnOut(
            vulnerability_id=int(vid),
            title=title,
            cwe_id=cwe,
            masvs_category=masvs,
            severity=severity,
            final_score=round(float(score), 4) if score is not None else None,
            application_name=app_name,
        )
        for vid, title, cwe, masvs, severity, score, app_name in rows
    ]


@router.get("/trends", response_model=TrendsOut)
async def trends(
    days: int = Query(default=7, ge=1, le=365),
    _admin: dict[str, Any] = Depends(require_admin),
) -> TrendsOut:
    """اتجاهات يومية: فحوص بدأت وثغرات اكتُشفت خلال النافذة الزمنية."""
    with get_session() as session:
        scan_rows = session.execute(
            select(func.date(Scan.started_at).label("d"), func.count())
            .where(Scan.started_at.is_not(None))
            .group_by("d")
            .order_by("d")
        ).all()
        vuln_rows = session.execute(
            select(func.date(Vulnerability.discovered_at).label("d"), func.count())
            .group_by("d")
            .order_by("d")
        ).all()

    def _tail(rows: list[Any]) -> list[DayCount]:
        return [DayCount(date=str(d), count=int(n or 0)) for d, n in rows][-days:]

    return TrendsOut(days=days, scans=_tail(scan_rows), vulnerabilities=_tail(vuln_rows))
