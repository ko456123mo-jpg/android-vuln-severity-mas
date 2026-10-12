"""CRUD جلسات الفحص / Scans repository."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Scan
from db.repositories import row_to_dict

_FINAL_STATUSES = {"success", "failed", "partial"}


def _utcnow() -> datetime:
    """وقت UTC بلا tz (يتوافق مع SQLite CURRENT_TIMESTAMP)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def create(
    application_id: int,
    tools_used: list[str] | None = None,
    rule_version: str | None = None,
    status: str = "pending",
) -> dict[str, Any]:
    """إنشاء جلسة فحص جديدة."""
    with get_session() as session:
        scan = Scan(
            application_id=application_id,
            tools_used=tools_used,
            rule_version=rule_version,
            status=status,
        )
        session.add(scan)
        session.flush()
        session.refresh(scan)
        return row_to_dict(scan)


# اسم بديل متوافق مع مواصفات الوكلاء / alias per agent spec (Phase 3)
create_scan = create


def update_tools_used(scan_id: int, tools_used: list[str]) -> dict[str, Any] | None:
    """تسجيل الأدوات المنفذة فعلياً للفحص."""
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        scan.tools_used = tools_used
        session.flush()
        session.refresh(scan)
        return row_to_dict(scan)


def get_by_id(scan_id: int) -> dict[str, Any] | None:
    """جلب فحص بالمعرّف."""
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        return row_to_dict(scan) if scan else None


def update_status(
    scan_id: int,
    status: str,
    error_message: str | None = None,
    total_tokens: int | None = None,
    total_duration_ms: int | None = None,
) -> dict[str, Any] | None:
    """تحديث حالة الفحص — يضبط started_at/finished_at تلقائياً.

    - 'running' → started_at = الآن
    - success/failed/partial → finished_at = الآن
    """
    with get_session() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return None
        scan.status = status
        if status == "running" and scan.started_at is None:
            scan.started_at = _utcnow()
        if status in _FINAL_STATUSES:
            scan.finished_at = _utcnow()
        if error_message is not None:
            scan.error_message = error_message
        if total_tokens is not None:
            scan.total_tokens = total_tokens
        if total_duration_ms is not None:
            scan.total_duration_ms = total_duration_ms
        session.flush()
        session.refresh(scan)
        return row_to_dict(scan)


def list_by_app(application_id: int) -> list[dict[str, Any]]:
    """سرد فحوص تطبيق معيّن (الأحدث أولاً)."""
    with get_session() as session:
        scans = session.scalars(
            select(Scan).where(Scan.application_id == application_id).order_by(Scan.id.desc())
        ).all()
        return [row_to_dict(s) for s in scans]


# ---------------------------------------------------------------------
# إضافات المرحلة 6 (API): سرد مُفلتَر للواجهة
# ---------------------------------------------------------------------
def list_all(
    application_id: int | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """سرد الفحوص مع فلترة اختيارية (تطبيق/حالة) — الأحدث أولاً."""
    with get_session() as session:
        stmt = select(Scan)
        if application_id is not None:
            stmt = stmt.where(Scan.application_id == application_id)
        if status:
            stmt = stmt.where(Scan.status == status)
        scans = session.scalars(stmt.order_by(Scan.id.desc()).limit(limit)).all()
        return [row_to_dict(s) for s in scans]
