"""AgentMCPClient — غلاف موحّد لاستدعاء أدوات MCP من الوكلاء.

وضعان / Two modes:
    direct (Mock/dev): استدعاء دوال الخوادم مباشرة عند MCP_MOCK_MODE=1
        (نفس دوال الأدوات المسجّلة في FastMCP — بلا عمليات فرعية، أسرع للاختبارات).
        يُعطَّل عبر MCP_DIRECT_CALL=0.
    protocol (real)  : MultiServerMCPClient عبر MCPManager (stdio/http حقيقي).

كل الاستدعاءات async مع timeout من config/tools.yaml.
"""
from __future__ import annotations

import asyncio
import importlib
import os
import time
from typing import Any

import yaml

from mcp_servers.common import PROJECT_ROOT, is_mock_mode
from mcp_servers.manager import MCPManager

# (server → module path) — نفس خوادم المرحلة 2 (لا أدوات مخترعة)
_TOOL_MODULES = MCPManager.DEFAULT_SERVERS  # {jadx: "mcp_servers.jadx_server.server", ...}

# timeout لكل خادم من config/tools.yaml
TOOLS_YAML = PROJECT_ROOT / "config" / "tools.yaml"


def _load_timeouts() -> dict[str, int]:
    if TOOLS_YAML.is_file():
        cfg = yaml.safe_load(TOOLS_YAML.read_text(encoding="utf-8")) or {}
        return {k: int(v.get("timeout", 300)) for k, v in (cfg.get("tools") or {}).items()}
    return {}


class AgentMCPClient:
    """عميل MCP مخصص للوكلاء مع Timeout و Logging hooks."""

    def __init__(self, manager: MCPManager | None = None) -> None:
        self.manager = manager or MCPManager()
        self.client: Any = None  # MultiServerMCPClient في mode protocol
        self.direct: bool = False
        self._registry: dict[str, Any] = {}  # "jadx.decompile" -> callable
        self._protocol_tools: dict[str, Any] = {}
        self._timeouts = _load_timeouts()

    # ------------------------------------------------------------------
    async def initialize(self) -> "AgentMCPClient":
        """تهيئة العميل — يختار الوضع تلقائياً."""
        if is_mock_mode() and os.getenv("MCP_DIRECT_CALL", "1") == "1":
            self.direct = True
            self._registry = self._build_direct_registry()
            return self

        self.direct = False
        self.client = self.manager.get_mcp_client()  # يستخدم config/tools.yaml
        tools = await self.client.get_tools()
        # أسماء الأدوات عبر MCP غير مؤهلة بالخادم — نبني server.tool من التجريدات
        for tool in tools:
            self._protocol_tools[tool.name] = tool
        return self

    def _build_direct_registry(self) -> dict[str, Any]:
        """سجل الاستدعاء المباشر من دوال الخوادم (نفس أجسام أدوات MCP)."""
        registry: dict[str, Any] = {}
        for server_name, module_path in _TOOL_MODULES.items():
            module = importlib.import_module(module_path)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                # دوال الأدوات مزيّنة بـ @mcp.tool() لكنها تبقى قابلة للاستدعاء
                if (
                    callable(attr)
                    and not attr_name.startswith("_")
                    and attr_name not in {"server", "mcp", "BaseMCPServer"}
                    and getattr(attr, "__module__", None) == module.__name__
                ):
                    registry[f"{server_name}.{attr_name}"] = attr
        return registry

    # ------------------------------------------------------------------
    async def call_tool(self, tool_name: str, **kwargs: Any) -> dict[str, Any]:
        """استدعاء أداة بصيغة "server.tool" مع مهلة الخادم من tools.yaml.

        يعيد dict كما تعيده الأداة نفسها (success/error...) أو يرفع KeyError
        لأداة غير معروفة. timeout > المهلة ⇒ TimeoutError.
        """
        started = time.perf_counter()
        timeout = self._timeouts.get(tool_name.split(".")[0], 300)
        try:
            if self.direct:
                fn = self._registry.get(tool_name)
                if fn is None:
                    raise KeyError(
                        f"أداة غير معروفة: {tool_name} — "
                        f"المتاح: {sorted(self._registry)}"
                    )
                result = await asyncio.wait_for(
                    asyncio.to_thread(lambda: fn(**kwargs)), timeout=timeout
                )
            else:
                short_name = tool_name.split(".", 1)[1]
                tool = self._protocol_tools.get(short_name)
                if tool is None:
                    raise KeyError(f"أداة غير معروفة عبر MCP: {tool_name}")
                result = await asyncio.wait_for(tool.ainvoke(kwargs), timeout=timeout)
                if not isinstance(result, dict):
                    result = {"success": True, "result": result}
        except asyncio.TimeoutError as exc:
            raise TimeoutError(
                f"تجاوزت الأداة {tool_name} المهلة ({timeout}s)"
            ) from exc
        result["duration_ms"] = int((time.perf_counter() - started) * 1000)
        return result

    # ------------------------------------------------------------------
    async def list_all_tools(self) -> list[str]:
        """سرد كل الأدوات المتاحة بصيغة "server.tool"."""
        if self.direct:
            return sorted(self._registry)
        return sorted(f"[mcp] {name}" for name in self._protocol_tools)

    async def close(self) -> None:
        """إغلاق الموارد (وضع protocol يدير عملياته عبر المدير)."""
        self.manager.stop_all()

    # ------------------------------------------------------------------
    async def __aenter__(self) -> "AgentMCPClient":
        return await self.initialize()

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()
