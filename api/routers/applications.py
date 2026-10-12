"""موجّه التطبيقات / Applications API (المرحلة 6).

    GET    /applications              سرد (فلترة بالمشروع)
    POST   /applications/upload       رفع APK (multipart) + SHA-256 + منع التكرار
    GET    /applications/{id}         تفاصيل + app_context + إحصاءات
    PUT    /applications/{id}/context تحديث سياق التطبيق (+ context_score)
    GET    /applications/{id}/scans   فحوص التطبيق
    DELETE /applications/{id}         حذف (يُرفض 409 إن وُجدت فحوص)

قرارات موثقة (docs/api_reference.md): لا يُحلَّل APK هنا — package_name/version
تُمرَّر اختيارياً ضمن النموذج (التحليل الفعلي مهمة أدوات MCP في المرحلة 3)؛
تُخزَّن النسخة في data/apks/<sha256>.apk ويُمنع الرفع المكرر (409/200 مع السجل القائم).
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from api import authz
from api.deps import get_current_user
from api.schemas import ScanOut
from core.scoring.context_score import calculate_context_score
from db.connection import get_session
from db.models import AppContext, Scan, SeverityRule, Vulnerability
from db.repositories import applications_repo, projects_repo, scans_repo
from mcp_servers.common import PROJECT_ROOT

router = APIRouter(prefix="/applications", tags=["applications"])

MAX_APK_BYTES = 300 * 1024 * 1024  # سقف رفع موثق: 300MB
APKS_DIR = PROJECT_ROOT / "data" / "apks"


# ── مخططات ───────────────────────────────────────────────────────────
class AppContextOut(BaseModel):
    """سياق التطبيق التشغيلي (يغذي context_score في المعادلة)."""

    data_sensitivity: Optional[str] = None
    industry: Optional[str] = None
    user_base_size: Optional[str] = None
    internet_facing: Optional[bool] = None
    business_criticality: Optional[str] = None
    compliance_requirements: Optional[str] = None
    context_score: Optional[float] = None
    updated_at: Optional[datetime] = None


class ApplicationStats(BaseModel):
    """إحصاءات التطبيق."""

    scans: int = 0
    vulnerabilities: int = 0


class ApplicationOut(BaseModel):
    """تطبيق (APK) مسجَّل."""

    id: int
    project_id: int
    name: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    sha256: str
    file_path: str
    file_size: Optional[int] = None
    app_category: Optional[str] = None
    uploaded_at: Optional[datetime] = None


class ApplicationDetail(ApplicationOut):
    """تطبيق + سياقه + إحصاءاته."""

    app_context: Optional[AppContextOut] = None
    stats: ApplicationStats = Field(default_factory=ApplicationStats)


class UploadResult(BaseModel):
    """نتيجة الرفع — deduplicated=True تعني إعادة نسخة موجودة."""

    created: bool
    deduplicated: bool
    application: ApplicationOut


class AppContextInput(BaseModel):
    """تحديث سياق التطبيق — القيم مقيَّدة بقواعد فحص القاعدة."""

    data_sensitivity: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = None
    industry: Optional[Literal["banking", "health", "commerce", "game", "utility"]] = None
    user_base_size: Optional[Literal["small", "medium", "large"]] = None
    internet_facing: Optional[bool] = None
    business_criticality: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = None
    compliance_requirements: Optional[str] = Field(default=None, max_length=2000)


class DeleteOut(BaseModel):
    """نتيجة حذف تطبيق."""

    id: int
    deleted: bool
    files_removed: int


# ── مساعدات ──────────────────────────────────────────────────────────
def _context_out(application_id: int) -> Optional[AppContextOut]:
    """قراءة app_context إن وُجد."""
    with get_session() as session:
        ctx = session.scalar(
            select(AppContext).where(AppContext.application_id == application_id)
        )
        if ctx is None:
            return None
        return AppContextOut(
            data_sensitivity=ctx.data_sensitivity,
            industry=ctx.industry,
            user_base_size=ctx.user_base_size,
            internet_facing=ctx.internet_facing,
            business_criticality=ctx.business_criticality,
            compliance_requirements=ctx.compliance_requirements,
            context_score=ctx.context_score,
            updated_at=ctx.updated_at,
        )


def _app_stats(application_id: int) -> ApplicationStats:
    """عدد الفحوص والثغرات لتطبيق."""
    with get_session() as session:
        scans = session.scalar(
            select(func.count()).select_from(Scan).where(Scan.application_id == application_id)
        )
        vulns = session.scalar(
            select(func.count()).select_from(Vulnerability).where(
                Vulnerability.application_id == application_id
            )
        )
    return ApplicationStats(scans=int(scans or 0), vulnerabilities=int(vulns or 0))


def _active_rule_context_params() -> dict[str, Any]:
    """context_params من قاعدة الخطورة النشطة (لتقييم السياق في الواجهة)."""
    with get_session() as session:
        rule = session.scalar(select(SeverityRule).where(SeverityRule.active.is_(True)))
        return dict(rule.context_params or {}) if rule else {}


# ── المسارات ─────────────────────────────────────────────────────────
@router.get("", response_model=list[ApplicationOut])
async def list_applications(
    project_id: Optional[int] = None,
    limit: int = 200,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[ApplicationOut]:
    """سرد التطبيقات — فلترة اختيارية بالمشروع، ومحصورة بمشاريع المستخدم."""
    if project_id is not None:
        authz.ensure_project_id_access(project_id, current_user)
        apps = applications_repo.list_by_project(project_id)
    else:
        apps = applications_repo.list_all(limit=limit)
        allowed = authz.owned_application_ids(current_user)
        if allowed is not None:  # admin: بلا تقييد
            apps = [a for a in apps if a["id"] in set(allowed)]
    return [ApplicationOut(**a) for a in apps[:limit]]


@router.post("/upload", response_model=UploadResult)
async def upload_apk(
    response: Response,
    project_id: int = Form(...),
    file: UploadFile = File(...),
    name: Optional[str] = Form(default=None),
    package_name: Optional[str] = Form(default=None),
    version: Optional[str] = Form(default=None),
    app_category: Optional[str] = Form(default=None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> UploadResult:
    """رفع APK: تحقق + SHA-256 + تخزين data/apks/<sha256>.apk + منع تكرار داخل المشروع."""
    authz.ensure_project_id_access(project_id, current_user)
    filename = file.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="الملف يجب أن يكون بصيغة .apk")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="الملف فارغ")
    if len(content) > MAX_APK_BYTES:
        raise HTTPException(status_code=413, detail=f"حجم الملف يتجاوز {MAX_APK_BYTES} بايت")

    sha256 = hashlib.sha256(content).hexdigest()
    existing = applications_repo.get_by_sha256(sha256)
    if existing is not None:
        if int(existing["project_id"]) == int(project_id):  # تكرار حقيقي داخل المشروع
            response.status_code = 200
            return UploadResult(
                created=False, deduplicated=True, application=ApplicationOut(**existing)
            )
        # البصمة فريدة على مستوى النظام (قيد UNIQUE في المخطط): لا نُرجع صف
        # مشروع آخر (كان تسريباً بمنع تكرار المحتوى)، ونرسل 409 موحّدة بلا
        # أي تفاصيل عن المالك أو التطبيق.
        raise HTTPException(
            status_code=409,
            detail=(
                "بصمة APK مسجَّلة مسبقاً على مستوى النظام — لا يمكن تسجيل نفس "
                "الملف في مشروع آخر؛ ارفع نسخة مختلفة أو استخدم السجل القائم"
            ),
        )

    APKS_DIR.mkdir(parents=True, exist_ok=True)
    apk_path = APKS_DIR / f"{sha256}.apk"
    apk_path.write_bytes(content)

    created = applications_repo.create(
        project_id=project_id,
        name=name or Path(filename).stem,
        sha256=sha256,
        file_path=str(apk_path),
        package_name=package_name,
        version=version,
        file_size=len(content),
        app_category=app_category,
    )
    response.status_code = 201
    return UploadResult(created=True, deduplicated=False, application=ApplicationOut(**created))


@router.get("/{application_id}", response_model=ApplicationDetail)
async def get_application(
    application_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> ApplicationDetail:
    """تفاصيل تطبيق + app_context + إحصاءات (مالك أو admin)."""
    app_row = applications_repo.get_by_id(application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail=f"application {application_id} غير موجود")
    authz.ensure_application_access(app_row, current_user)
    return ApplicationDetail(
        **app_row,
        app_context=_context_out(application_id),
        stats=_app_stats(application_id),
    )


@router.put("/{application_id}/context", response_model=AppContextOut)
async def update_app_context(
    application_id: int,
    payload: AppContextInput,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> AppContextOut:
    """إدراج/تحديث سياق التطبيق وإعادة حساب context_score بالقاعدة النشطة."""
    app_row = applications_repo.get_by_id(application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail=f"application {application_id} غير موجود")
    authz.ensure_application_access(app_row, current_user)
    fields = payload.model_dump(exclude_unset=True)

    with get_session() as session:
        ctx = session.scalar(
            select(AppContext).where(AppContext.application_id == application_id)
        )
        if ctx is None:
            ctx = AppContext(application_id=application_id)
            session.add(ctx)
        for key, value in fields.items():
            setattr(ctx, key, value)
        ctx.context_score = calculate_context_score(
            {
                "data_sensitivity": ctx.data_sensitivity,
                "industry": ctx.industry,
                "user_base_size": ctx.user_base_size,
                "internet_facing": ctx.internet_facing,
                "business_criticality": ctx.business_criticality,
                "compliance_requirements": ctx.compliance_requirements,
            },
            _active_rule_context_params(),
        )
        session.flush()

    result = _context_out(application_id)
    if result is None:  # لا يمكن أن يحدث — لكن عقد الرد صريح
        raise HTTPException(status_code=500, detail="فشل تحديث سياق التطبيق")
    return result


@router.get("/{application_id}/scans", response_model=list[ScanOut])
async def list_application_scans(
    application_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> list[ScanOut]:
    """فحوص تطبيق (الأحدث أولاً) — مالك أو admin."""
    app_row = applications_repo.get_by_id(application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail=f"application {application_id} غير موجود")
    authz.ensure_application_access(app_row, current_user)
    return [ScanOut(**s) for s in scans_repo.list_by_app(application_id)]


@router.delete("/{application_id}", response_model=DeleteOut)
async def delete_application(
    application_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> DeleteOut:
    """حذف التطبيق وملفه — يُرفض (409) إذا وُجدت فحوص مرتبطة."""
    app_row = applications_repo.get_by_id(application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail=f"application {application_id} غير موجود")
    authz.ensure_application_access(app_row, current_user)
    if scans_repo.list_by_app(application_id):
        raise HTTPException(
            status_code=409,
            detail="لا يمكن حذف تطبيق له فحوص مسجَّلة — احذف الفحوص أولاً",
        )
    files_removed = 0
    path = Path(app_row["file_path"])
    if path.exists():
        path.unlink()
        files_removed = 1
    applications_repo.delete(application_id)
    return DeleteOut(id=application_id, deleted=True, files_removed=files_removed)
