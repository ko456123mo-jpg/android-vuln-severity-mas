"""خادم Objection عبر MCP — فحص runtime جاهز (FastMCP، stdio).

Tools / الأدوات:
    explore_storage  : استكشاف التخزين المحلي (SharedPrefs/DBs/ملفات) → artifact_ref
    dump_keystore    : استخراج محتويات Android Keystore → artifact_ref + items_count
    bypass_pinning   : تعطيل SSL Pinning → bypassed (bool)
    root_bypass      : تجاوز كشف الروت → bypassed (bool)
    list_activities  : سرد الأنشطة → [str]
    healthcheck      : حالة الخادم (تلقائية)

التشغيل:  python -m mcp_servers.objection_server.server
Mock:     MCP_MOCK_MODE=1 python -m mcp_servers.objection_server.server
"""
from __future__ import annotations

from mcp_servers.common.base_server import BaseMCPServer
from mcp_servers.common.schemas import (
    ObjectionActivitiesOutput,
    ObjectionBypassOutput,
    ObjectionExploreOutput,
    ObjectionKeystoreOutput,
    ObjectionPackageInput,
)
from mcp_servers.objection_server.objection_wrapper import ObjectionWrapper

server = BaseMCPServer(
    name="objection",
    instructions=(
        "فحص runtime لتطبيقات أندرويد عبر Objection: تخزين، keystore، "
        "تجاوز pinning/root، وسرد الأنشطة. / Runtime mobile exploration."
    ),
)
mcp = server.mcp
_wrapper = ObjectionWrapper()


@mcp.tool()
def explore_storage(package_name: str) -> dict:
    """استكشاف التخزين المحلي للتطبيق — دليل MASVS-STORAGE (نصوص صريحة، ملفات حساسة)."""
    try:
        params = ObjectionPackageInput(package_name=package_name)
        out = ObjectionExploreOutput(**_wrapper.explore_storage(params.package_name))
    except Exception as exc:
        out = ObjectionExploreOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def dump_keystore(package_name: str) -> dict:
    """استخراج محتويات Android Keystore التي يصل إليها التطبيق."""
    try:
        params = ObjectionPackageInput(package_name=package_name)
        out = ObjectionKeystoreOutput(**_wrapper.dump_keystore(params.package_name))
    except Exception as exc:
        out = ObjectionKeystoreOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def bypass_pinning(package_name: str) -> dict:
    """محاولة تعطيل SSL Pinning — نجاحها دليل ديناميكي على غياب MASVS-NETWORK."""
    try:
        params = ObjectionPackageInput(package_name=package_name)
        out = ObjectionBypassOutput(**_wrapper.bypass_pinning(params.package_name))
    except Exception as exc:
        out = ObjectionBypassOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def root_bypass(package_name: str) -> dict:
    """محاولة تجاوز كشف الروت — نجاحها دليل ديناميكي على غياب MASVS-RESILIENCE."""
    try:
        params = ObjectionPackageInput(package_name=package_name)
        out = ObjectionBypassOutput(**_wrapper.root_bypass(params.package_name))
    except Exception as exc:
        out = ObjectionBypassOutput(success=False, error=str(exc))
    return out.model_dump()


@mcp.tool()
def list_activities(package_name: str) -> dict:
    """سرد Activities التطبيق (لاستكشاف السطح الهجومي — MASVS-PLATFORM)."""
    try:
        params = ObjectionPackageInput(package_name=package_name)
        out = ObjectionActivitiesOutput(**_wrapper.list_activities(params.package_name))
    except Exception as exc:
        out = ObjectionActivitiesOutput(success=False, error=str(exc))
    return out.model_dump()


if __name__ == "__main__":
    server.start()
