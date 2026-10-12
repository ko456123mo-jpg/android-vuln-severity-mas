"""خادم JADX عبر MCP — تحليل ساكن (FastMCP، stdio).

Tools / الأدوات:
    decompile          : فك تجميع APK بالكامل → artifact_ref
    get_manifest       : استخراج AndroidManifest.xml → dict
    search_code        : بحث عن كلمة في الكود المفكّك → [{file, line, snippet}]
    get_class          : استرجاع كود فئة محددة → مصدر Java
    list_permissions   : سرد صلاحيات التطبيق → [str]
    healthcheck        : حالة الخادم (تلقائية من BaseMCPServer)

التشغيل:  python -m mcp_servers.jadx_server.server
Mock:     MCP_MOCK_MODE=1 python -m mcp_servers.jadx_server.server
"""
from __future__ import annotations

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import (
    JadxDecompileInput,
    JadxDecompileOutput,
    JadxGetClassInput,
    JadxGetClassOutput,
    JadxGetManifestInput,
    JadxGetManifestOutput,
    JadxPermissionsInput,
    JadxPermissionsOutput,
    JadxSearchCodeInput,
    JadxSearchCodeOutput,
)
from mcp_servers.jadx_server.jadx_wrapper import JadxWrapper

server = BaseMCPServer(
    name="jadx",
    instructions=(
        "تحليل ساكن لتطبيقات أندرويد عبر jadx: فك تجميع، Manifest، "
        "بحث في الكود، استرجاع الفئات، والصلاحيات. / Static APK analysis."
    ),
)
mcp = server.mcp
_wrapper = JadxWrapper()


@mcp.tool()
def decompile(apk_path: str, timeout: int = 300) -> dict:
    """فك تجميع APK بالكامل وإرجاع artifact_ref + عدد الفئات."""
    try:
        params = JadxDecompileInput(apk_path=apk_path, timeout=timeout)
        out = JadxDecompileOutput(**_wrapper.decompile(params.apk_path, params.timeout))
    except Exception as exc:
        out = JadxDecompileOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def get_manifest(apk_path: str) -> dict:
    """استخراج AndroidManifest (صلاحيات، مكونات مُصدَّرة، خصائص التطبيق)."""
    try:
        params = JadxGetManifestInput(apk_path=apk_path)
        out = JadxGetManifestOutput(**_wrapper.get_manifest(params.apk_path))
    except Exception as exc:
        out = JadxGetManifestOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def search_code(apk_path: str, keyword: str, max_results: int = 50) -> dict:
    """بحث عن كلمة مفتاحية في الكود المفكّك (مثل password, http://, Cipher)."""
    try:
        params = JadxSearchCodeInput(
            apk_path=apk_path, keyword=keyword, max_results=max_results
        )
        out = JadxSearchCodeOutput(
            **_wrapper.search_code(params.apk_path, params.keyword, params.max_results)
        )
    except Exception as exc:
        out = JadxSearchCodeOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def get_class(apk_path: str, class_name: str) -> dict:
    """استرجاع مصدر Java الكامل لفئة باسمها المؤهل (مثال com.app.crypto.CryptoUtil)."""
    try:
        params = JadxGetClassInput(apk_path=apk_path, class_name=class_name)
        out = JadxGetClassOutput(
            **_wrapper.get_class(params.apk_path, params.class_name)
        )
    except Exception as exc:
        out = JadxGetClassOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def list_permissions(apk_path: str) -> dict:
    """سرد صلاحيات التطبيق (uses-permission) من Manifest."""
    try:
        params = JadxPermissionsInput(apk_path=apk_path)
        out = JadxPermissionsOutput(**_wrapper.list_permissions(params.apk_path))
    except Exception as exc:
        out = JadxPermissionsOutput(success=False, error=str(exc))
    return out.model_dump()


if __name__ == "__main__":
    server.start()
