"""CRUD المشاريع / Projects repository (create/get/list/update/delete)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.connection import get_session
from db.models import Project
from db.repositories import row_to_dict


def create(
    name: str,
    description: str | None = None,
    owner_id: int | None = None,
    status: str = "active",
) -> dict[str, Any]:
    """إنشاء مشروع جديد وإرجاعه كـ dict."""
    with get_session() as session:
        project = Project(name=name, description=description, owner_id=owner_id, status=status)
        session.add(project)
        session.flush()
        session.refresh(project)
        return row_to_dict(project)


def get_by_id(project_id: int) -> dict[str, Any] | None:
    """جلب مشروع بالمعرّف أو None."""
    with get_session() as session:
        project = session.get(Project, project_id)
        return row_to_dict(project) if project else None


def list_all(status: str | None = None) -> list[dict[str, Any]]:
    """سرد كل المشاريع (مع فلترة اختيارية بالحالة)."""
    with get_session() as session:
        stmt = select(Project)
        if status:
            stmt = stmt.where(Project.status == status)
        projects = session.scalars(stmt.order_by(Project.created_at.desc())).all()
        return [row_to_dict(p) for p in projects]


def update(project_id: int, **fields: Any) -> dict[str, Any] | None:
    """تحديث حقول مشروع (يتجاهل id والحقول غير الموجودة)."""
    with get_session() as session:
        project = session.get(Project, project_id)
        if project is None:
            return None
        for key, value in fields.items():
            if key != "id" and hasattr(project, key):
                setattr(project, key, value)
        session.flush()
        session.refresh(project)
        return row_to_dict(project)


def delete(project_id: int) -> bool:
    """حذف مشروع — True إذا حُذف، False إذا لم يوجد."""
    with get_session() as session:
        project = session.get(Project, project_id)
        if project is None:
            return False
        session.delete(project)
        return True
