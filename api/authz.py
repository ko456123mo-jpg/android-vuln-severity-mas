"""تفويض الملكية / Ownership-based authorization (المرحلة 8).

قبل هذه الطبقة كان كل مسار محمياً بالمصادقة فقط: أي مستخدم مُصادَق يستطيع
قراءة/تعديل/حذف أي مشروع وتطبيق وفحص وتقرير (IDOR). هنا يُفرض التفويض على
سلسلة الملكية الكاملة:

    project ← application ← scan ← vulnerability ← assessment ← correction

السياسة (قرار موثّق في docs/security_hardening.md و appendix_c):
    1. **admin**: وصول كامل (تشغيل/تشخيص النظام).
    2. **owner**: المستخدم يصل إلى الموارد التي تنتهي سلسلتها إلى مشروع
       ``projects.owner_id == user.id`` (قراءةً وكتابةً وتصحيحاً).
    3. **reviewer**: يصل إلى حلقة المراجعة البشرية (``/reviews/*``) بغض النظر
       عن الملكية — هذا دوره الوظيفي (مراجعة عيّنات عبر المشاريع)، ويُحرَس
       بـ ``require_reviewer`` لا بالملكية.
    4. **analyst** (الافتراضي عند التسجيل): لا يرى إلا مشاريعه.
    5. مورد موجود بلا مالك (``owner_id IS NULL`` — بيانات أدوات/سكربتات
       تجريبية) أو مورد يتيم السلسلة: يُرفض لغير admin (**fail-closed**).

رموز الأخطاء:
    • 404 — المورد غير موجود (سلوك ما قبل المرحلة 8، بلا تغيير).
    • 403 — المورد موجود لكنه ليس للمستخدم. لا إخفاء للوجود: التطبيق أحادي
      المستأجر بمعرّفات تسلسلية أصلاً، والقرار موثّق بدل إخفائه.

الدوال تأخذ صفوفاً مُجلَبة مسبقاً حيث أمكن (بلا استعلام إضافي)، أو معرّفاً
حيث لا يحمل المسار صفاً (فتُجلَبه وتتحقق في خطوة واحدة عبر join واحد).
"""
from __future__ import annotations

from typing import Any, Mapping

from fastapi import HTTPException
from sqlalchemy import select

from db.connection import get_session
from db.models import Application, Assessment, Project, Scan, Vulnerability

FORBIDDEN_MESSAGE = "لا تملك صلاحية الوصول إلى هذا المورد"
REVIEWER_ROLES = frozenset({"admin", "reviewer"})

# علامة داخلية: الصف غير موجود (تُميَّز عن موجود-بلا-مالك)
_MISSING = object()


# =====================================================================
# أساسيات
# =====================================================================
def is_admin(user: Mapping[str, Any]) -> bool:
    """هل المستخدم مدير نظام؟ (يملك كل الموارد)."""
    return str(user.get("role", "")).lower() == "admin"


def is_reviewer(user: Mapping[str, Any]) -> bool:
    """هل يملك دور المراجعة البشرية؟ (admin أو reviewer)."""
    return str(user.get("role", "")).lower() in REVIEWER_ROLES


def _forbidden(kind: str, resource_id: Any) -> HTTPException:
    """403 موحّد لمورد موجود لا يملكه المستخدم (بلا تفاصيل داخلية)."""
    return HTTPException(
        status_code=403, detail=f"المورد {kind}#{resource_id}: {FORBIDDEN_MESSAGE}"
    )


def _not_found(kind: str, resource_id: Any | None = None) -> HTTPException:
    """404 موحّد لمورد غير موجود."""
    detail = f"{kind} {resource_id} غير موجود" if resource_id is not None else f"{kind} غير موجود"
    return HTTPException(status_code=404, detail=detail)


def require_reviewer(user: Mapping[str, Any]) -> None:
    """حراسة مسارات حلقة المراجعة: admin أو reviewer فقط (وإلا 403)."""
    if not is_reviewer(user):
        raise HTTPException(
            status_code=403,
            detail=(
                f"الدور '{user.get('role')}' غير مخوّل بحلقة المراجعة — "
                "المطلوب: admin/reviewer"
            ),
        )


def _check_owner(owner_id: Any, user: Mapping[str, Any], kind: str, resource_id: Any) -> None:
    """القاعدة الموحّدة: admin يمر؛ غيره يجب أن يكون owner_id == المستخدم."""
    if is_admin(user):
        return
    if owner_id is _MISSING:
        raise _not_found(kind, resource_id)
    if owner_id is None or owner_id != user.get("id"):
        raise _forbidden(kind, resource_id)


# =====================================================================
# تسلسل الملكية: استعلام واحد لكل مستوى (join حتى projects.owner_id)
# =====================================================================
def _owner_id(from_model: Any, joins: list[tuple[Any, Any]], where: Any) -> Any:
    """ينفّذ select(Project.owner_id) عبر سلسلة joins — يعيد المالك أو _MISSING."""
    statement = select(Project.owner_id).select_from(from_model)
    for target, on_clause in joins:
        statement = statement.join(target, on_clause)
    with get_session() as session:
        row = session.execute(statement.where(where)).first()
    return _MISSING if row is None else row[0]


def owner_id_of_application(application_id: int) -> Any:
    """مالك تطبيق (عبر مشروعه) — أو _MISSING إن لم يكن موجوداً."""
    return _owner_id(
        Application,
        [(Project, Application.project_id == Project.id)],
        Application.id == application_id,
    )


def owner_id_of_scan(scan_id: int) -> Any:
    """مالك فحص (عبر تطبيقه ثم مشروعه)."""
    return _owner_id(
        Scan,
        [
            (Application, Scan.application_id == Application.id),
            (Project, Application.project_id == Project.id),
        ],
        Scan.id == scan_id,
    )


def owner_id_of_vulnerability(vulnerability_id: int) -> Any:
    """مالك ثغرة (عبر تطبيقها ثم مشروعه)."""
    return _owner_id(
        Vulnerability,
        [
            (Application, Vulnerability.application_id == Application.id),
            (Project, Application.project_id == Project.id),
        ],
        Vulnerability.id == vulnerability_id,
    )


def owner_id_of_assessment(assessment_id: int) -> Any:
    """مالك تقييم (عبر ثغرته ← تطبيقها ← مشروعه)."""
    return _owner_id(
        Assessment,
        [
            (Vulnerability, Assessment.vulnerability_id == Vulnerability.id),
            (Application, Vulnerability.application_id == Application.id),
            (Project, Application.project_id == Project.id),
        ],
        Assessment.id == assessment_id,
    )


# =====================================================================
# الحراس على مستوى المعرّف (عندما لا يكون الصف بحوزة المسار)
# =====================================================================
def ensure_project_id_access(project_id: int, user: Mapping[str, Any]) -> None:
    """404 إن لم يوجد المشروع، 403 إن وُجد ولم يكن للمستخدم."""
    with get_session() as session:
        row = session.execute(
            select(Project.owner_id).where(Project.id == project_id)
        ).first()
    _check_owner(_MISSING if row is None else row[0], user, "project", project_id)


def ensure_application_id_access(application_id: int, user: Mapping[str, Any]) -> None:
    """حراسة تطبيق بمعرّفه (404/403)."""
    _check_owner(owner_id_of_application(application_id), user, "application", application_id)


def ensure_scan_id_access(scan_id: int, user: Mapping[str, Any]) -> None:
    """حراسة فحص بمعرّفه (404/403)."""
    _check_owner(owner_id_of_scan(scan_id), user, "scan", scan_id)


def ensure_vulnerability_id_access(vulnerability_id: int, user: Mapping[str, Any]) -> None:
    """حراسة ثغرة بمعرّفها (404/403)."""
    _check_owner(
        owner_id_of_vulnerability(vulnerability_id), user, "vulnerability", vulnerability_id
    )


def ensure_assessment_id_access(assessment_id: int, user: Mapping[str, Any]) -> None:
    """حراسة تقييم بمعرّفه (404/403) — مسارات المراجعة تُستثنى بـ require_reviewer."""
    _check_owner(owner_id_of_assessment(assessment_id), user, "assessment", assessment_id)


# =====================================================================
# الحراس على مستوى الصفوف المُجلَبة مسبقاً
# =====================================================================
def ensure_project_access(project: Mapping[str, Any] | None, user: Mapping[str, Any]) -> None:
    """حراسة صف مشروع (None ⇒ 404، غيره ⇒ فحص المالك)."""
    if project is None:
        raise _not_found("project")
    _check_owner(project.get("owner_id"), user, "project", project.get("id"))


def ensure_application_access(
    application: Mapping[str, Any] | None, user: Mapping[str, Any]
) -> None:
    """حراسة صف تطبيق (None ⇒ 404، وإلا عبر سلسلة الملكية)."""
    if application is None:
        raise _not_found("application")
    _check_owner(
        owner_id_of_application(int(application["id"])), user, "application", application["id"]
    )


def ensure_scan_access(scan: Mapping[str, Any] | None, user: Mapping[str, Any]) -> None:
    """حراسة صف فحص (None ⇒ 404، وإلا عبر سلسلة الملكية)."""
    if scan is None:
        raise _not_found("scan")
    _check_owner(owner_id_of_scan(int(scan["id"])), user, "scan", scan["id"])


def ensure_vulnerability_access(
    vulnerability: Mapping[str, Any] | None, user: Mapping[str, Any]
) -> None:
    """حراسة صف ثغرة (None ⇒ 404، وإلا عبر سلسلة الملكية)."""
    if vulnerability is None:
        raise _not_found("vulnerability")
    _check_owner(
        owner_id_of_vulnerability(int(vulnerability["id"])),
        user,
        "vulnerability",
        vulnerability["id"],
    )


def ensure_assessment_access(
    assessment: Mapping[str, Any] | None, user: Mapping[str, Any]
) -> None:
    """حراسة صف تقييم (None ⇒ 404، وإلا عبر سلسلة الملكية)."""
    if assessment is None:
        raise _not_found("assessment")
    _check_owner(
        owner_id_of_assessment(int(assessment["id"])), user, "assessment", assessment["id"]
    )


# =====================================================================
# تصفية القوائم (للقراءات المجمّعة)
# =====================================================================
def owned_project_ids(user: Mapping[str, Any]) -> list[int] | None:
    """معرّفات مشاريع المستخدم — أو None بمعنى «بلا تقييد» (admin)."""
    if is_admin(user):
        return None
    with get_session() as session:
        rows = session.execute(
            select(Project.id).where(Project.owner_id == user.get("id"))
        ).all()
    return [int(row[0]) for row in rows]


def owned_application_ids(user: Mapping[str, Any]) -> list[int] | None:
    """معرّفات تطبيقات المستخدم (عبر مشاريعها) — أو None بمعنى «بلا تقييد»."""
    if is_admin(user):
        return None
    with get_session() as session:
        rows = session.execute(
            select(Application.id)
            .join(Project, Application.project_id == Project.id)
            .where(Project.owner_id == user.get("id"))
        ).all()
    return [int(row[0]) for row in rows]


def filter_owned_projects(
    rows: list[dict[str, Any]], user: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """تصفية صفوف مشاريع: admin بلا تقييد، وغيره بمشاريعه فقط (عبر owner_id)."""
    if is_admin(user):
        return rows
    return [row for row in rows if row.get("owner_id") == user.get("id")]
