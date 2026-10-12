"""خادم MobSF عبر MCP — تحليل شامل عبر REST (FastMCP، stdio).

Tools / الأدوات:
    upload_apk      : رفع APK → scan_hash
    start_scan      : بدء الفحص → scan_id
    get_report      : جلب التقرير الكامل → artifact_ref (ضخم → مرجع فقط)
    get_findings    : استخراج الثغرات → list[dict] (فلترة بالخطورة اختيارية)
    healthcheck     : حالة الخادم (تلقائية)

التشغيل:  python -m mcp_servers.mobsf_server.server
Mock:     MCP_MOCK_MODE=1 python -m mcp_servers.mobsf_server.server
"""
from __future__ import annotations

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import (
    MobSFFindingsInput,
    MobSFFindingsOutput,
    MobSFReportInput,
    MobSFReportOutput,
    MobSFScanInput,
    MobSFScanOutput,
    MobSFUploadInput,
    MobSFUploadOutput,
)
from mcp_servers.mobsf_server.mobsf_client import MobSFClient

server = BaseMCPServer(
    name="mobsf",
    instructions=(
        "تحليل أمني شامل لملفات APK عبر MobSF REST API: رفع، فحص، "
        "تقارير، واستخراج ثغرات موحّدة. / Full APK security scan via MobSF."
    ),
)
mcp = server.mcp
_client = MobSFClient()


@mcp.tool()
def upload_apk(apk_path: str) -> dict:
    """رفع ملف APK إلى MobSF وإرجاع scan_hash للخطوات التالية."""
    try:
        params = MobSFUploadInput(apk_path=apk_path)
        out = MobSFUploadOutput(**_client.upload(params.apk_path))
    except Exception as exc:
        out = MobSFUploadOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def start_scan(scan_hash: str) -> dict:
    """بدء فحص APK مرفوع سابقاً (المسح في MobSF متزامن) وإرجاع scan_id."""
    try:
        params = MobSFScanInput(scan_hash=scan_hash)
        out = MobSFScanOutput(**_client.start_scan(params.scan_hash))
    except Exception as exc:
        out = MobSFScanOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def get_report(scan_id: str) -> dict:
    """جلب تقرير الفحص الكامل — يُحفظ كـ artifact ويُرجع مرجعه فقط."""
    try:
        params = MobSFReportInput(scan_id=scan_id)
        out = MobSFReportOutput(**_client.get_report(params.scan_id))
    except Exception as exc:
        out = MobSFReportOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def get_findings(scan_id: str, severity_filter: str | None = None) -> dict:
    """استخراج الثغرات موحّدة الشكل مع فلترة اختيارية (high/medium/low/info)."""
    try:
        params = MobSFFindingsInput(scan_id=scan_id, severity_filter=severity_filter)
        out = MobSFFindingsOutput(
            **_client.get_findings(params.scan_id, params.severity_filter)
        )
    except Exception as exc:
        out = MobSFFindingsOutput(success=False, error=str(exc))
    return out.model_dump()


if __name__ == "__main__":
    server.start()
