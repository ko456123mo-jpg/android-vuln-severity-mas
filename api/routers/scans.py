"""موجّه الفحوص / Scans API (المرحلة 6).

    GET    /scans                        سرد (فلترة بالتطبيق/الحالة)
    POST   /scans/start                  بدء فحص (Background Task) → 202
    GET    /scans/{id}                   تفاصيل + إحصاءات + آخر إجراء
    GET    /scans/{id}/status            polling الحالة الحيّة + نسبة التقدم
    GET    /scans/{id}/vulnerabilities   ثغرات الفحص + ملخص التقييم/الأدلة
    GET    /scans/{id}/assessments       تقييمات ثغرات الفحص
    DELETE /scans/{id}                   إلغاء فحص جارٍ/معلّق

قرارات موثقة (docs/api_reference.md):
    • الفحص يعمل في Background Task متزامن (threadpool) يستدعي asyncio.run
      على خط أنابيب LangGraph — يسلّم الطلب فوراً دون حجز حلقة الأحداث.
    • «الإلغاء» = status='failed' + error_message='cancelled by user'، لأن قيد
      فحص القاعدة ck_scans_status لا يتضمن 'cancelled' (لم نخترع قيمة جديدة).
      الإلغاء يمنع التقاط النتيجة فقط؛ المهمة الجارية تُكمل كتابتها إن سبقت.
    • نسبة التقدم في /status مشتقة من آخر إجراء مسجَّل في agent_logs.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from api import authz
from api.deps import get_current_user
from api.schemas import AssessmentBrief, EvidenceBrief, LastLogOut, ScanOut
from db.connection import get_session
from db.models import SeverityRule, Tool
from db.repositories import (
    applications_repo,
    assessments_repo,
    findings_repo,
    logs_repo,
    scans_repo,
)

router = APIRouter(prefix="/scans", tags=["scans"])

# ترتيب مراحل خط الأنابيب — أساس حساب التقدم في /status
_STAGE_ORDER = [
    "orchestrator",
    "run_static_tools",
    "run_dynamic_tools",
    "extractor_static",
    "extractor_dynamic",
    "scorer",
    "reviewer",
    "persist_scores",
    "reporter",
    "finalize",
]
_SCAN_TYPE_REQUESTS = {
    "static": "فحص ساكن للتطبيق",
    "dynamic": "فحص ديناميكي للتطبيق",
    "comprehensive": "فحص شامل للتطبيق",
}
_ACTIVE_STATUSES = ("pending", "running")


# ── مخططات ───────────────────────────────────────────────────────────
class StartScanInput(BaseModel):
    """طلب بدء فحص."""

    application_id: int
    scan_type: Literal["static", "dynamic", "comprehensive"] = "comprehensive"
    user_request: Optional[str] = Field(default=None, max_length=1000)


class StartScanOut(BaseModel):
    """رد البدء — scan_id للمتابعة عبر /scans/{id}/status."""

    scan_id: int
    application_id: int
    status: str
    scan_type: str
    requested_by: str
    message: str


class ScanStats(BaseModel):
    """إحصاءات فحص."""

    vulnerabilities: int = 0
    findings: int = 0
    assessments: int = 0


class ScanDetailOut(ScanOut):
    """فحص + سياق تطبيقه + إحصاءاته."""

    application_name: Optional[str] = None
    package_name: Optional[str] = None
    stats: ScanStats = Field(default_factory=ScanStats)
    last_log: Optional[LastLogOut] = None


class ScanStatusOut(BaseModel):
    """حالة الفحص الحيّة (للـ polling)."""

    scan_id: int
    status: str
    progress_percent: int = 0
    current_agent: Optional[str] = None
    current_action: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    total_duration_ms: int = 0
    total_tokens: int = 0
    error_message: Optional[str] = None


class ScanVulnerabilityOut(BaseModel):
    """ثغرة داخل فحص + ملخص تقييمها وأدلتها."""

    id: int
    application_id: int
    title: str
    description: Optional[str] = None
    masvs_category: Optional[str] = None
    cwe_id: Optional[str] = None
    status: str = "open"
    discovered_at: Optional[datetime] = None
    assessment: Optional[AssessmentBrief] = None
    evidence: EvidenceBrief = Field(default_factory=EvidenceBrief)


class CancelScanOut(BaseModel):
    """نتيجة الإلغاء."""

    scan_id: int
    status: str
    cancelled: bool
    note: str


# ── مساعدات ──────────────────────────────────────────────────────────
def _ensure_scan(scan_id: int, user: dict[str, Any]) -> dict[str, Any]:
    """جلب فحص أو 404، وفرض الملكية (403) إن لم يكن للمستخدم/غير admin."""
    scan = scans_repo.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} غير موجود")
    authz.ensure_scan_access(scan, user)
    return scan


def _active_rule_version() -> Optional[str]:
    """إصدار قاعدة الخطورة النشطة (يُسجَّل على الفحص)."""
    with get_session() as session:
        rule = session.scalar(select(SeverityRule).where(SeverityRule.active.is_(True)))
        return rule.version if rule else None


def _tool_names() -> dict[int, str]:
    """خريطة tools.id → name."""
    with get_session() as session:
        return {t.id: t.name for t in session.scalars(select(Tool)).all()}


def _last_log(scan_id: int) -> Optional[LastLogOut]:
    """آخر إجراء مسجَّل للفحص (لتقدم الواجهة)."""
    logs = logs_repo.list_by_scan(scan_id)
    if not logs:
        return None
    last = logs[-1]
    return LastLogOut(
        agent_name=last.get("agent_name"),
        action=last.get("action"),
        status=last.get("status"),
        created_at=last.get("created_at"),
    )


def _progress_percent(status: str, last_agent: Optional[str]) -> int:
    """نسبة تقدم حتمية: pending 5 · running 10→95 حسب المرحلة · نهائي 100."""
    if status == "pending":
        return 5
    if status not in _ACTIVE_STATUSES:
        return 100
    if last_agent in _STAGE_ORDER:
        return min(95, 10 + _STAGE_ORDER.index(last_agent) * 9)
    return 10


def _run_scan_background(
    scan_id: int,
    application_id: int,
    apk_path: str,
    package_name: str,
    app_category: str,
    scan_type: str,
    user_request: str,
) -> None:
    """مهمة الخلفية: تشغيل خط الأنابيب وتسجيل أي فشل على صف الفحص.

    متزامنة عمداً حتى تنفّذ خارج حلقة الأحداث (threadpool) — asyncio.run تبني
    الرسم داخل حلقة خاصة بها (نمط المرحلتين 3–5 الموثق).
    """
    scans_repo.update_status(scan_id, "running")
    try:
        from agents.graph import ainvoke_pipeline, build_scan_graph
        from agents.state import ScanState
    except Exception as exc:  # بيئة بلا نماذج/أدوات — فشل واضح لا صامت
        scans_repo.update_status(
            scan_id, "failed", error_message=f"تعذر تحميل خط الأنابيب: {exc}"[:500]
        )
        return

    state = ScanState(
        scan_id=f"scan_{scan_id:04d}",
        application_id=application_id,
        apk_path=apk_path,
        package_name=package_name,
        app_category=app_category,
        db_scan_id=scan_id,
        scan_type=scan_type,
        user_request=user_request,
    )

    async def _go() -> dict[str, Any]:
        graph = build_scan_graph()
        return await ainvoke_pipeline(graph, state)

    try:
        asyncio.run(_go())
    except Exception as exc:  # noqa: BLE001 — أي فشل يُسجَّل ويُنهي الفحص بأمان
        scans_repo.update_status(scan_id, "failed", error_message=str(exc)[:500])
        try:
            logs_repo.log_agent_action(
                agent_name="api_background",
                action="scan_exception",
                scan_id=scan_id,
                status="failed",
                error_message=str(exc)[:300],
            )
        except Exception:  # التسجيل لا يُسقط مهمة الخلفية
            pass


# ── المسارات ─────────────────────────────────────────────────────────
@router.get("", response_model=list[ScanOut])
async def list_scans(
    application_id: Optional[int] = None,
    status: Optional[Literal["pending", "running", "success", "failed", "partial"]] = None,
    limit: int = 200,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[ScanOut]:
    """سرد الفحوص (الأحدث أولاً) — محصور بتطبيقات المستخدم لغير admin."""
    if application_id is not None:
        authz.ensure_application_id_access(application_id, current_user)
    rows = scans_repo.list_all(application_id=application_id, status=status, limit=limit)
    allowed = authz.owned_application_ids(current_user)
    if allowed is not None:
        allowed_set = set(allowed)
        rows = [row for row in rows if row["application_id"] in allowed_set]
    return [ScanOut(**s) for s in rows]


@router.post("/start", response_model=StartScanOut, status_code=202)
async def start_scan(
    payload: StartScanInput,
    background_tasks: BackgroundTasks,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> StartScanOut:
    """ينشئ صف فحص (pending) ويشغّل خط الأنابيب في الخلفية."""
    app_row = applications_repo.get_by_id(payload.application_id)
    if app_row is None:
        raise HTTPException(status_code=404, detail=f"application {payload.application_id} غير موجود")
    authz.ensure_application_access(app_row, current_user)

    scan = scans_repo.create(
        application_id=payload.application_id,
        rule_version=_active_rule_version(),
        status="pending",
    )
    background_tasks.add_task(
        _run_scan_background,
        scan["id"],
        payload.application_id,
        app_row["file_path"],
        app_row.get("package_name") or "unknown.package",
        app_row.get("app_category") or "unknown",
        payload.scan_type,
        (payload.user_request or _SCAN_TYPE_REQUESTS[payload.scan_type]),
    )
    return StartScanOut(
        scan_id=scan["id"],
        application_id=payload.application_id,
        status="pending",
        scan_type=payload.scan_type,
        requested_by=current_user["username"],
        message="بدأ الفحص في الخلفية — تابع الحالة عبر /scans/{id}/status",
    )


@router.get("/{scan_id}", response_model=ScanDetailOut)
async def get_scan(
    scan_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> ScanDetailOut:
    """تفاصيل فحص + إحصاءات + آخر إجراء مسجَّل."""
    scan = _ensure_scan(scan_id, current_user)
    findings = findings_repo.list_by_scan(scan_id)
    vuln_ids = list(dict.fromkeys(f["vulnerability_id"] for f in findings))
    app_row = applications_repo.get_by_id(scan["application_id"]) or {}
    return ScanDetailOut(
        **{k: v for k, v in scan.items() if k in ScanOut.model_fields},
        application_name=app_row.get("name"),
        package_name=app_row.get("package_name"),
        stats=ScanStats(
            vulnerabilities=len(vuln_ids),
            findings=len(findings),
            assessments=len(assessments_repo.list_by_vuln_ids(vuln_ids)),
        ),
        last_log=_last_log(scan_id),
    )


@router.get("/{scan_id}/status", response_model=ScanStatusOut)
async def get_scan_status(
    scan_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> ScanStatusOut:
    """حالة الفحص الحيّة + نسبة التقدم (polling الواجهة)."""
    scan = _ensure_scan(scan_id, current_user)
    last = _last_log(scan_id)
    return ScanStatusOut(
        scan_id=scan_id,
        status=scan["status"],
        progress_percent=_progress_percent(
            scan["status"], last.agent_name if last else None
        ),
        current_agent=last.agent_name if last else None,
        current_action=last.action if last else None,
        started_at=scan.get("started_at"),
        finished_at=scan.get("finished_at"),
        total_duration_ms=scan.get("total_duration_ms") or 0,
        total_tokens=scan.get("total_tokens") or 0,
        error_message=scan.get("error_message"),
    )


@router.get("/{scan_id}/vulnerabilities", response_model=list[ScanVulnerabilityOut])
async def get_scan_vulnerabilities(
    scan_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> list[ScanVulnerabilityOut]:
    """ثغرات الفحص مع ملخص التقييم وأدلته لكل ثغرة."""
    _ensure_scan(scan_id, current_user)
    findings = findings_repo.list_by_scan(scan_id)
    tools = _tool_names()
    vuln_ids = list(dict.fromkeys(f["vulnerability_id"] for f in findings))
    assessments = {a["vulnerability_id"]: a for a in assessments_repo.list_by_vuln_ids(vuln_ids)}

    results: list[ScanVulnerabilityOut] = []
    for vuln_id in vuln_ids:
        vuln = findings_repo.get_vulnerability(vuln_id)
        if vuln is None:
            continue
        evidence_rows = [f for f in findings if f["vulnerability_id"] == vuln_id]
        brief = assessments.get(vuln_id)
        results.append(
            ScanVulnerabilityOut(
                **{k: v for k, v in vuln.items() if k in ScanVulnerabilityOut.model_fields and k != "evidence"},
                assessment=AssessmentBrief(**brief) if brief else None,
                evidence=EvidenceBrief(
                    findings_count=len(evidence_rows),
                    tools=[tools.get(f["tool_id"], "unknown") for f in evidence_rows],
                ),
            )
        )
    return results


@router.get("/{scan_id}/assessments", response_model=list[AssessmentBrief])
async def get_scan_assessments(
    scan_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> list[AssessmentBrief]:
    """تقييمات ثغرات الفحص (للتحليل والمراجعة)."""
    _ensure_scan(scan_id, current_user)
    findings = findings_repo.list_by_scan(scan_id)
    vuln_ids = list(dict.fromkeys(f["vulnerability_id"] for f in findings))
    return [
        AssessmentBrief(**a) for a in assessments_repo.list_by_vuln_ids(vuln_ids)
    ]


@router.delete("/{scan_id}", response_model=CancelScanOut)
async def cancel_scan(
    scan_id: int, current_user: dict[str, Any] = Depends(get_current_user)
) -> CancelScanOut:
    """إلغاء فحص معلّق/جارٍ (مبني كـ failed مع سبب واضح — انظر ترويسة الملف)."""
    scan = _ensure_scan(scan_id, current_user)
    if scan["status"] not in _ACTIVE_STATUSES:
        raise HTTPException(
            status_code=409,
            detail=f"لا يمكن إلغاء فحص بحالة '{scan['status']}' — الإلغاء للمعلّق/الجاري فقط",
        )
    scans_repo.update_status(
        scan_id, "failed", error_message="cancelled by user — أُلغي من الواجهة"
    )
    return CancelScanOut(
        scan_id=scan_id,
        status="failed",
        cancelled=True,
        note="قيد الحالة لا يتضمن 'cancelled' — الإلغاء يُسجَّل كـ failed مع السبب",
    )


# ── نهاية الموجّه ───────────────────────────────────────────────────
