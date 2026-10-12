"""موجّه التقارير / Reports API (المرحلة 5).

    POST /reports/{scan_id}/generate            توليد التقريرين (MD+HTML+PDF)
    GET  /reports/{scan_id}/technical           التقرير الفني (JSON: markdown+stats)
    GET  /reports/{scan_id}/executive           التقرير التنفيذي (JSON)
    GET  /reports/{scan_id}/download/{format}   تنزيل ملف التقرير
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api import authz
from api.deps import get_current_user
from fastapi.responses import FileResponse

from core.reports.generator import ReportGenerator
from mcp_servers.common import PROJECT_ROOT

router = APIRouter(prefix="/reports", tags=["reports"])

_FORMAT_FILES = {
    "technical_md": "technical_report.md",
    "executive_md": "executive_report.md",
    "technical_html": "technical_report.html",
    "executive_html": "executive_report.html",
    "technical_pdf": "technical_report.pdf",
    "executive_pdf": "executive_report.pdf",
}
_MEDIA_TYPES = {".md": "text/markdown", ".html": "text/html", ".pdf": "application/pdf"}


@router.post("/{scan_id}/generate")
async def generate_reports(
    scan_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """يولّد التقريرين بكل الصيغ في data/reports/<scan_id>/ (بديل حتمي للملخصات)."""
    authz.ensure_scan_id_access(scan_id, current_user)
    try:
        generator = ReportGenerator(scan_id)
        paths = generator.export_all(PROJECT_ROOT / "data" / "reports" / str(scan_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"scan_id": scan_id, "files": paths, "format_count": len(_FORMAT_FILES)}


def _load_generated(scan_id: int, kind: str) -> Path:
    """مسار تقرير مولَّد سابقاً — 404 إن لم يولَّد بعد."""
    path = PROJECT_ROOT / "data" / "reports" / str(scan_id) / _FORMAT_FILES[kind]
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"لم يُولَّد تقرير '{kind}' لفحص {scan_id} بعد — استدعِ POST generate",
        )
    return path


@router.get("/{scan_id}/technical")
async def get_technical_report(
    scan_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """التقرير الفني (JSON: markdown + البيانات المجمّعة)."""
    authz.ensure_scan_id_access(scan_id, current_user)
    path = _load_generated(scan_id, "technical_md")
    data = ReportGenerator(scan_id).collect_data()
    return {
        "scan_id": scan_id,
        "markdown": path.read_text(encoding="utf-8"),
        "stats": data["stats"],
        "vulnerabilities": data["vulnerabilities"],
    }


@router.get("/{scan_id}/executive")
async def get_executive_report(
    scan_id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """التقرير التنفيذي (JSON: markdown عربي)."""
    authz.ensure_scan_id_access(scan_id, current_user)
    path = _load_generated(scan_id, "executive_md")
    return {"scan_id": scan_id, "markdown": path.read_text(encoding="utf-8")}


@router.get("/{scan_id}/download/{format}")
async def download_report(
    scan_id: int,
    format: str,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> FileResponse:
    """تنزيل التقرير (technical_md|executive_md|technical_html|executive_html|
    technical_pdf|executive_pdf)."""
    if format not in _FORMAT_FILES:
        raise HTTPException(status_code=422, detail=f"صيغة مجهولة: {format}")
    authz.ensure_scan_id_access(scan_id, current_user)
    path = _load_generated(scan_id, format)
    return FileResponse(
        path=str(path),
        media_type=_MEDIA_TYPES.get(path.suffix, "application/octet-stream"),
        filename=path.name,
    )
