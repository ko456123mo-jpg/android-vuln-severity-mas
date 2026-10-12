"""MCPManager — تسجيل وتشغيل كل خوادم MCP الأربعة + عميل موحّد.

يقدّم:
    get_connection_configs() : إعدادات MultiServerMCPClient (stdio/http) من config/tools.yaml
    get_mcp_client()         : MultiServerMCPClient موحّد (استيراد كسول للمهايئ)
    start_server()/start_all(): تشغيل خوادم stdio كعمليات فرعية (لوضع standalone)
    stop_all()               : إيقاف كل العمليات
    registered_servers()     : الخوادم المعروفة
"""
from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

from mcp_servers.common import PROJECT_ROOT

CONFIG_PATH = PROJECT_ROOT / "config" / "tools.yaml"


class MCPManager:
    """سجل مركزي وتشغيل لخوادم MCP."""

    # module → stdio server (يجب أن يحتوي server.py على `mcp` (FastMCP) + __main__)
    DEFAULT_SERVERS: dict[str, str] = {
        "jadx": "mcp_servers.jadx_server.server",
        "mobsf": "mcp_servers.mobsf_server.server",
        "frida": "mcp_servers.frida_server.server",
        "objection": "mcp_servers.objection_server.server",
    }

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path) if config_path else CONFIG_PATH
        self._processes: dict[str, subprocess.Popen] = {}
        self.settings: dict[str, Any] = {}
        if self.config_path.is_file():
            self.settings = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}

    # ------------------------------------------------------------------
    # السجل / Registry
    # ------------------------------------------------------------------
    def registered_servers(self) -> list[str]:
        """أسماء الخوادم المعروفة (من تعريفات DEFAULT_SERVERS)."""
        return sorted(self.DEFAULT_SERVERS)

    # ------------------------------------------------------------------
    # إعدادات العميل الموحّد / Unified MCP client configs
    # ------------------------------------------------------------------
    def get_connection_configs(self) -> dict[str, dict[str, Any]]:
        """بناء إعدادات MultiServerMCPClient من config/tools.yaml.

        stdio: {transport, command, args, cwd} — "python" تُحوَّل إلى sys.executable.
        http : {transport: streamable_http, url}
        """
        configs: dict[str, dict[str, Any]] = {}
        for name, cfg in (self.settings.get("tools") or {}).items():
            kind = cfg.get("type")
            if kind == "stdio":
                parts = shlex.split(str(cfg["command"]))
                if parts and parts[0].endswith("python"):
                    parts[0] = sys.executable
                configs[name] = {
                    "transport": "stdio",
                    "command": parts[0],
                    "args": parts[1:],
                    "cwd": str(PROJECT_ROOT),
                }
            elif kind == "http":
                configs[name] = {
                    "transport": "streamable_http",
                    "url": str(cfg["url"]),
                }
        return configs

    def get_mcp_client(self) -> Any:
        """إرجاع MultiServerMCPClient موحّد (استيراد كسول — يتطلب langchain-mcp-adapters)."""
        try:
            from langchain_mcp_adapters.client import MultiServerMCPClient
        except ImportError as exc:
            raise RuntimeError(
                "حزمة langchain-mcp-adapters غير مثبتة — ثبّتها لاستخدام العميل الموحّد"
            ) from exc
        return MultiServerMCPClient(self.get_connection_configs())

    # ------------------------------------------------------------------
    # تشغيل standalone كعمليات فرعية / Manage stdio servers as processes
    # ------------------------------------------------------------------
    def start_server(self, name: str) -> subprocess.Popen:
        """تشغيل خادم stdio كعملية فرعية (cstdio: stdin/stdout ملك العميل)."""
        if name not in self.DEFAULT_SERVERS:
            raise KeyError(f"خادم غير معروف: {name} — المعروف: {self.registered_servers()}")
        if name in self._processes and self._processes[name].poll() is None:
            return self._processes[name]  # يعمل أصلاً — idempotent
        proc = subprocess.Popen(
            [sys.executable, "-m", self.DEFAULT_SERVERS[name]],
            cwd=PROJECT_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._processes[name] = proc
        return proc

    def start_all(self) -> dict[str, int]:
        """تشغيل كل الخوادم — يعيد {name: pid}."""
        return {name: self.start_server(name).pid for name in self.registered_servers()}

    def stop_all(self) -> None:
        """إيقاف كل العمليات الفرعية (terminate ثم kill عند الحاجة)."""
        for proc in self._processes.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._processes.clear()
