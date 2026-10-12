"""موجّه المشاريع / Projects API (المرحلة 6).

    GET    /projects        سرد (فلترة بالملاك/الحالة، الافتراضي نشِطة فقط)
    POST   /projects        إنشاء (المالك = المستخدم الحالي)
    GET    /projects/{id}   تفاصيل + إحصاءات (تطبيقات/فحوص/ثغرات)
    PUT    /projects/{id}   تعديل حقول
    DELETE /projects/{id}   حذف ناعم (status='archived')
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from api import authz
from api.deps import get_current_user
from db.connection import get_session
from db.models import Application, Project, Scan, User, Vulnerability
from db.repositories import projects_repo

router = APIRouter(prefix="/projects", tags=["projects"])


# ── مخططات ───────────────────────────────────────────────────────────
class ProjectCreate(BaseModel):
    """إنشاء مشروع."""

    name: str = Field(min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)


class ProjectUpdate(BaseModel):
    """تعديل جزئي — الحقول المُمرَّرة فقط تُحدَّث."""

    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    status: Optional[Literal["active", "archived"]] = None


class ProjectStats(BaseModel):
    """إحصاءات تراكمية للمشروع."""

    applications: int = 0
    scans: int = 0
    vulnerabilities: int = 0


class ProjectOut(BaseModel):
    """مشروع + إحصاءاته."""

    id: int
    name: str
    description: Optional[str] = None
    owner_id: Optional[int] = None
    owner_username: Optional[str] = None
    status: str
    created_at: Optional[datetime] = None
    stats: ProjectStats = Field(default_factory=ProjectStats)


class DeleteOut(BaseModel):
    """نتيجة الحذف."""

    id: int
    deleted: bool
    mode: str


# ── قراءات تجميعية (SELECT فقط — التعارض مع repos غير مطلوب) ────────
def _stats_map() -> dict[int, dict[str, int]]:
    """إحصاءات كل مشروع باستعلامين تجميعيين (apps/ scans/ vulns)."""
    with get_session() as session:
        apps = dict(
            session.execute(
                select(Application.project_id, func.count(Application.id)).group_by(
                    Application.project_id
                )
            ).all()
        )
        scans = dict(
            session.execute(
                select(Application.project_id, func.count(Scan.id))
                .join(Scan, Scan.application_id == Application.id)
                .group_by(Application.project_id)
            ).all()
        )
        vulns = dict(
            session.execute(
                select(Application.project_id, func.count(Vulnerability.id))
                .join(Vulnerability, Vulnerability.application_id == Application.id)
                .group_by(Application.project_id)
            ).all()
        )
    return {
        pid: {
            "applications": int(apps.get(pid, 0)),
            "scans": int(scans.get(pid, 0)),
            "vulnerabilities": int(vulns.get(pid, 0)),
        }
        for pid in set(apps) | set(scans) | set(vulns)
    }


def _owner_map(owner_ids: list[int]) -> dict[int, str]:
    """أسماء الملاك لعرضها في الواجهة."""
    if not owner_ids:
        return {}
    with get_session() as session:
        rows = session.execute(
            select(User.id, User.username).where(User.id.in_(owner_ids))
        ).all()
    return {int(uid): uname for uid, uname in rows}


def _to_out(
    project: dict[str, Any],
    stats: dict[int, dict[str, int]],
    owners: dict[int, str],
) -> ProjectOut:
    """تحويل صف مشروع + إحصاءاته لمخطط الاستجابة."""
    return ProjectOut(
        **{k: v for k, v in project.items() if k in ProjectOut.model_fields and k != "stats"},
        owner_username=owners.get(project.get("owner_id") or -1),
        stats=ProjectStats(**(stats.get(project["id"]) or {})),
    )


def _fetch_project_stats(project_id: int) -> ProjectStats:
    """إحصاءات مشروع واحد."""
    return (ProjectStats(**(_stats_map().get(project_id) or {})))


# ── المسارات ─────────────────────────────────────────────────────────
@router.get("", response_model=list[ProjectOut])
async def list_projects(
    owner_id: Optional[int] = None,
    status: Optional[Literal["active", "archived"]] = None,
    include_archived: bool = False,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[ProjectOut]:
    """سرد المشاريع — النشِطة افتراضياً، ومحصورة بمشاريع المستخدم لغير admin."""
    effective_status = status or (None if include_archived else "active")
    projects = projects_repo.list_all(status=effective_status)
    projects = authz.filter_owned_projects(projects, current_user)
    if owner_id is not None:
        projects = [p for p in projects if p.get("owner_id") == owner_id]
    stats = _stats_map()
    owners = _owner_map([p["owner_id"] for p in projects if p.get("owner_id")])
    return [_to_out(p, stats, owners) for p in projects]


@router.post("", response_model=ProjectOut, status_code=201)
async def create_project(
    payload: ProjectCreate,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ProjectOut:
    """إنشاء مشروع جديد يملكه المستخدم الحالي."""
    project = projects_repo.create(
        name=payload.name, description=payload.description, owner_id=current_user["id"]
    )
    return _to_out(project, {}, {current_user["id"]: current_user["username"]})


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> ProjectOut:
    """تفاصيل مشروع + إحصاءاته (مالك أو admin)."""
    project = projects_repo.get_by_id(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail=f"project {project_id} غير موجود")
    authz.ensure_project_access(project, current_user)
    owners = _owner_map([project["owner_id"]] if project.get("owner_id") else [])
    return _to_out(project, {project_id: _fetch_project_stats(project_id).model_dump()}, owners)


@router.put("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: int,
    payload: ProjectUpdate,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ProjectOut:
    """تعديل حقول مشروع (المُمرَّر فقط) — مالك أو admin."""
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=422, detail="لا حقول للتحديث")
    authz.ensure_project_id_access(project_id, current_user)
    project = projects_repo.update(project_id, **fields)
    if project is None:
        raise HTTPException(status_code=404, detail=f"project {project_id} غير موجود")
    owners = _owner_map([project["owner_id"]] if project.get("owner_id") else [])
    return _to_out(project, {project_id: _fetch_project_stats(project_id).model_dump()}, owners)


@router.delete("/{project_id}", response_model=DeleteOut)
async def delete_project(
    project_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> DeleteOut:
    """حذف ناعم: status='archived' — البيانات التابعة تبقى سليمة."""
    if projects_repo.get_by_id(project_id) is None:
        raise HTTPException(status_code=404, detail=f"project {project_id} غير موجود")
    authz.ensure_project_id_access(project_id, current_user)
    projects_repo.update(project_id, status="archived")
    return DeleteOut(id=project_id, deleted=True, mode="soft")
