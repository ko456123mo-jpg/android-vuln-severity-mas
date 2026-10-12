"""خادم Frida عبر MCP — تحليل ديناميكي / instrumentation (FastMCP، stdio).

Tools / الأدوات:
    list_devices     : سرد الأجهزة المتصلة → list[dict]
    spawn_app        : تشغيل تطبيق تحت Frida → session_id
    run_hook         : تنفيذ سكربت JS جاهز → artifact_ref (أحداث)
    capture_crypto   : تتبع استدعاءات التشفير (اختصار لـ run_hook crypto_trace)
    capture_network  : تتبع الشبكة (اختصار لـ run_hook network_trace)
    healthcheck      : حالة الخادم (تلقائية)

التشغيل:  python -m mcp_servers.frida_server.server
Mock:     MCP_MOCK_MODE=1 python -m mcp_servers.frida_server.server
"""
from __future__ import annotations

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import (
    FridaCaptureInput,
    FridaCaptureOutput,
    FridaDevicesOutput,
    FridaRunHookInput,
    FridaRunHookOutput,
    FridaSpawnInput,
    FridaSpawnOutput,
)
from mcp_servers.frida_server.session_manager import FridaSessionManager

server = BaseMCPServer(
    name="frida",
    instructions=(
        "تحليل ديناميكي لتطبيقات أندرويد عبر Frida: تشغيل تحت السيطرة، "
        "خطافات تشفير/شبكة/ssl/root، وجمع أدلة runtime. / Dynamic analysis."
    ),
)
mcp = server.mcp
_manager = FridaSessionManager()


@mcp.tool()
def list_devices() -> dict:
    """سرد أجهزة أندرويد المتصلة (محاكي/فيزيائي) المتاحة لـ Frida."""
    try:
        out = FridaDevicesOutput(**_manager.list_devices())
    except Exception as exc:
        out = FridaDevicesOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def spawn_app(package_name: str, device_id: str | None = None) -> dict:
    """تشغيل تطبيق تحت Frida على جهاز وإرجاع session_id نشط."""
    try:
        params = FridaSpawnInput(package_name=package_name, device_id=device_id)
        session = _manager.create_session(params.package_name, params.device_id)
        out = FridaSpawnOutput(
            success=True, session_id=session.session_id, pid=session.pid, error=None
        )
    except Exception as exc:
        out = FridaSpawnOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def run_hook(session_id: str, script_name: str, duration: int = 15) -> dict:
    """تنفيذ سكربت JS جاهز (ssl_bypass/root_bypass/crypto_trace/network_trace) وجمع الأحداث."""
    try:
        params = FridaRunHookInput(
            session_id=session_id, script_name=script_name, duration=duration
        )
        out = FridaRunHookOutput(
            **_manager.run_hook(params.session_id, params.script_name, params.duration)
        )
    except Exception as exc:
        out = FridaRunHookOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def capture_crypto(session_id: str, duration: int = 30) -> dict:
    """تتبع استدعاءات التشفير (Cipher/MessageDigest/Keys) — دليل MASVS-CRYPTO."""
    try:
        params = FridaCaptureInput(session_id=session_id, duration=duration)
        result = _manager.run_hook(params.session_id, "crypto_trace", params.duration)
        out = FridaCaptureOutput(
            success=result["success"],
            artifact_ref=result["artifact_ref"],
            captured_count=result["events_count"],
            error=result["error"],
        )
    except Exception as exc:
        out = FridaCaptureOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def capture_network(session_id: str, duration: int = 30) -> dict:
    """تتبع حركة الشبكة (URL connections / OkHttp) — دليل MASVS-NETWORK."""
    try:
        params = FridaCaptureInput(session_id=session_id, duration=duration)
        result = _manager.run_hook(params.session_id, "network_trace", params.duration)
        out = FridaCaptureOutput(
            success=result["success"],
            artifact_ref=result["artifact_ref"],
            captured_count=result["events_count"],
            error=result["error"],
        )
    except Exception as exc:
        out = FridaCaptureOutput(success=False, error=str(exc))
    return out.model_dump()


if __name__ == "__main__":
    server.start()
