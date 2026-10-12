"""CRUD التطبيقات / Applications repository."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Application
from db.repositories import row_to_dict


def create(
    project_id: int,
    name: str,
    sha256: str,
    file_path: str,
    package_name: str | None = None,
    version: str | None = None,
    file_size: int | None = None,
    app_category: str | None = None,
) -> dict[str, Any]:
    """تسجيل تطبيق (APK) جديد — sha256 فريد لمنع التكرار."""
    with get_session() as session:
        app = Application(
            project_id=project_id,
            name=name,
            sha256=sha256,
            file_path=file_path,
            package_name=package_name,
            version=version,
            file_size=file_size,
            app_category=app_category,
        )
        session.add(app)
        session.flush()
        session.refresh(app)
        return row_to_dict(app)


def get_by_id(application_id: int) -> dict[str, Any] | None:
    """جلب تطبيق بالمعرّف."""
    with get_session() as session:
        app = session.get(Application, application_id)
        return row_to_dict(app) if app else None


def get_by_sha256(sha256: str) -> dict[str, Any] | None:
    """جلب تطبيق ببصمة SHA-256 (للكشف عن الرفع المكرر)."""
    with get_session() as session:
        app = session.scalar(select(Application).where(Application.sha256 == sha256))
        return row_to_dict(app) if app else None


def list_by_project(project_id: int) -> list[dict[str, Any]]:
    """سرد تطبيقات مشروع معيّن."""
    with get_session() as session:
        apps = session.scalars(
            select(Application)
            .where(Application.project_id == project_id)
            .order_by(Application.uploaded_at.desc())
        ).all()
        return [row_to_dict(a) for a in apps]


# ---------------------------------------------------------------------
# إضافات المرحلة 6 (API): سرد عام + حذف آمن
# ---------------------------------------------------------------------
def list_all(limit: int = 200) -> list[dict[str, Any]]:
    """سرد كل التطبيقات (الأحدث أولاً) — لعرض لوحة التحكم."""
    with get_session() as session:
        apps = session.scalars(
            select(Application).order_by(Application.id.desc()).limit(limit)
        ).all()
        return [row_to_dict(a) for a in apps]


def delete(application_id: int) -> bool:
    """حذف تطبيق — False إذا لم يوجد. المسؤول عن قيود FK هو طبقة الـ router."""
    with get_session() as session:
        app = session.get(Application, application_id)
        if app is None:
            return False
        session.delete(app)
        return True
