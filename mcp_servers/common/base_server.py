"""BaseMCPServer — قاعدة موحّدة لكل خوادم MCP (مبنية على FastMCP الرسمية).

توفر:
    register_tool() : تسجيل أداة (دالة مباشرة أو decorator مع وسائط)
    start()/stop()  : تشغيل/إيقاف
    healthcheck()   : أداة healthcheck مسجّلة تلقائياً في كل خادم
    audit()         : تسجيل اختياري في agent_logs (المرحلة 2 — عند MCP_DB_LOGGING=1)
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_servers.common import is_mock_mode


class BaseMCPServer:
    """غلاف حول FastMCP مع تسجيل موحّد وأدوات نظام (healthcheck)."""

    def __init__(self, name: str, instructions: str | None = None) -> None:
        self.name = name
        self.instructions = instructions or f"خادم {name} عبر MCP"
        self.mcp: FastMCP = FastMCP(name=name, instructions=self.instructions)
        self._tools: dict[str, Callable[..., Any]] = {}
        # أداة نظام في كل خادم / built-in system tool
        self.register_tool(
            self._healthcheck,
            name="healthcheck",
            description="فحص صحة الخادم: الحالة، وضع Mock، وقائمة الأدوات.",
        )

    # ------------------------------------------------------------------
    # تسجيل الأدوات / Tool registration
    # ------------------------------------------------------------------
    def register_tool(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> Any:
        """تسجيل أداة: يعمل كاستدعاء مباشر أو decorator.

        register_tool(fn) أو @register_tool(name="...", description="...")
        """
        decorator = self.mcp.tool(name=name, description=description)
        if fn is None:
            def _wrap(f: Callable[..., Any]) -> Callable[..., Any]:
                self._tools[name or f.__name__] = f
                return decorator(f)

            return _wrap
        self._tools[name or fn.__name__] = fn
        return decorator(fn)

    # ------------------------------------------------------------------
    # تدقيق اختياري / Optional audit logging (Phase 2: optional)
    # ------------------------------------------------------------------
    def audit(self, tool: str, ok: bool, duration_ms: int, error: str | None = None) -> None:
        """تسجيل الاستدعاء في agent_logs — معطّل افتراضياً في المرحلة 2.

        يُفعَّل بـ MCP_DB_LOGGING=1. صامت عند أي خطأ (القاعدة غير جاهزة مثلاً).
        """
        if os.getenv("MCP_DB_LOGGING", "0") != "1":
            return
        try:
            from db.repositories.logs_repo import log_agent_action

            log_agent_action(
                agent_name=f"mcp:{self.name}",
                action=tool,
                scan_id=None,
                llm_model=None,
                latency_ms=duration_ms,
                status="success" if ok else "failed",
                error_message=error,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # أدوات النظام والتشغيل / System tools & lifecycle
    # ------------------------------------------------------------------
    async def _healthcheck(self) -> dict[str, Any]:
        """حالة الخادم (تُسجَّل تلقائياً كأداة healthcheck)."""
        return {
            "server": self.name,
            "status": "ok",
            "mock_mode": is_mock_mode(),
            "tools": self.list_tool_names(),
        }

    def list_tool_names(self) -> list[str]:
        """أسماء كل الأدوات المسجّلة (مرتّبة)."""
        return sorted(self._tools)

    def start(self, transport: str = "stdio") -> None:
        """تشغيل الخادم — stdio هو الافتراضي (يعمل حتى نهاية العملية)."""
        self.mcp.run(transport=transport)

    def stop(self) -> None:
        """الإيقاف — FastMCP تعمل كعملية stdio مستقلة.

        الإيقاف الفعلي يتم من المشغّل (MCPManager) عبر terminate/kill للعملية.
        """
