"""OrchestratorAgent — وكيل التنسيق: يخطط الفحص ويوزع المهام على أدوات MCP.

المسؤوليات:
    1. تحليل طلب المستخدم (نص طبيعي) عبر LLM → خطة JSON مُتحقق منها
    2. التحقق من الخطة مقابل كتالوج الأدوات (لا أدوات/أفعال مخترعة)
    3. ترتيب التنفيذ: static (jadx, mobsf) أولاً ثم dynamic (frida, objection)
    4. تنفيذ حزم أدوات عبر AgentMCPClient وتخزين النتائج كـ artifacts
    5. تدهور رشيق: فشل أداة يُسجَّل في state.errors ولا يوقف الباقي
    6. تسجيل كل خطوة في agent_logs (وراثة من BaseAgent)
"""
from __future__ import annotations

import time
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from agents.base_agent import BaseAgent, StructuredOutputError
from agents.llm_client import PROMPTS_DIR
from agents.mcp_client import AgentMCPClient
from agents.state import ScanState
from mcp_servers.common import McpToolError
from mcp_servers.common.artifact_store import ArtifactStore

# ---------------------------------------------------------------------
# كتالوج الأدوات المسموح — من المرحلة 2 فقط (لا أدوات مخترعة)
# ---------------------------------------------------------------------
TOOL_CATALOG: dict[str, set[str]] = {
    "jadx": {"decompile", "get_manifest", "search_code", "get_class", "list_permissions"},
    "mobsf": {"upload_apk", "start_scan", "get_report", "get_findings"},
    "frida": {"list_devices", "spawn_app", "run_hook", "capture_crypto", "capture_network"},
    "objection": {
        "explore_storage", "dump_keystore", "bypass_pinning", "root_bypass", "list_activities",
    },
}
STATIC_TOOLS = ("jadx", "mobsf")
DYNAMIC_TOOLS = ("frida", "objection")
TOOL_EXECUTION_ORDER = ("jadx", "mobsf", "frida", "objection")

_jinja = Environment(
    loader=FileSystemLoader(PROMPTS_DIR), autoescape=select_autoescape(disabled_extensions=("j2",))
)


class PlannedAction(BaseModel):
    tool: str
    action: str = "auto"
    params: dict[str, Any] = {}


class OrchestratorPlan(BaseModel):
    """عقد خطة التنسيق (Output Validation)."""

    scan_type: Literal["static", "dynamic", "comprehensive"]
    tools_sequence: list[PlannedAction]
    reasoning: str = ""


class OrchestratorAgent(BaseAgent):
    """وكيل التنسيق الرئيسي — يورث التدقيق و LLM من BaseAgent."""

    def __init__(self, llm: Any = None, mcp: AgentMCPClient | None = None, **kwargs: Any) -> None:
        super().__init__(name="orchestrator", llm=llm, **kwargs)
        self.mcp = mcp or AgentMCPClient()
        self.store = ArtifactStore()

    # ------------------------------------------------------------------
    # المرحلة 1: التخطيط / Planning
    # ------------------------------------------------------------------
    async def run(self, state: ScanState) -> dict[str, Any]:
        """إنتاج خطة فحص مُتحقق منها وتحديث الحالة."""
        request = state.user_request or "فحص شامل شامل للتطبيق (comprehensive)"
        prompt = _jinja.get_template("orchestrator.j2").render(
            user_request=request,
            package_name=state.package_name,
            app_category=state.app_category,
            available_tools=TOOL_CATALOG,
        )
        errors: list[str] = []
        try:
            plan = await self.call_llm_structured(
                prompt, OrchestratorPlan, scan_id=state.db_scan_id
            )
        except (StructuredOutputError, Exception) as exc:  # خطة بديلة قواعدية
            errors.append(f"orchestrator LLM plan failed → fallback: {exc}")
            plan = self._fallback_plan(request)

        plan = self._validate_plan(plan, errors)
        stage = "static_scan" if self._needs_static(plan) else "extraction"
        return {
            "scan_plan": plan.model_dump(),
            "scan_type": plan.scan_type,
            "current_stage": stage,
            "errors": list(state.errors) + errors,
        }

    @staticmethod
    def _fallback_plan(request: str) -> OrchestratorPlan:
        """خطة قواعدية عند فشل LLM — تدهور رشيق بلا توقف."""
        lowered = request.lower()
        if "ساكن" in request and "ديناميكي" not in request:
            scan_type: Literal["static", "dynamic", "comprehensive"] = "static"
        elif "ديناميكي" in request and "ساكن" not in request:
            scan_type = "dynamic"
        else:
            scan_type = "comprehensive"
        tools = (
            list(STATIC_TOOLS)
            if scan_type == "static"
            else list(DYNAMIC_TOOLS)
            if scan_type == "dynamic"
            else list(TOOL_EXECUTION_ORDER)
        )
        return OrchestratorPlan(
            scan_type=scan_type,
            tools_sequence=[PlannedAction(tool=t) for t in tools],
            reasoning="fallback rule-based plan (LLM unavailable)",
        )

    @staticmethod
    def _validate_plan(plan: OrchestratorPlan, errors: list[str]) -> OrchestratorPlan:
        """تنقية الخطة: إسقاط الأدوات/الأفعال غير المعروفة + فرض الترتيب."""
        valid = [
            action
            for action in plan.tools_sequence
            if action.tool in TOOL_CATALOG
            and (action.action == "auto" or action.action in TOOL_CATALOG[action.tool])
        ]
        dropped = {a.tool for a in plan.tools_sequence} - {a.tool for a in valid}
        for tool in sorted(dropped):
            errors.append(f"orchestrator: dropped invalid action for tool '{tool}'")

        tools_in_plan = {a.tool for a in valid}
        if not tools_in_plan:  # خطة فارغة بالكامل ⇒ شامل بالأدوات كلها
            plan.scan_type = "comprehensive"
            tools_in_plan = set(TOOL_EXECUTION_ORDER)

        ordered = [t for t in TOOL_EXECUTION_ORDER if t in tools_in_plan]
        by_tool = {a.tool: a for a in valid}
        plan.tools_sequence = [by_tool.get(t, PlannedAction(tool=t)) for t in ordered]
        plan.scan_type = (
            "static"
            if set(ordered) <= set(STATIC_TOOLS)
            else "dynamic"
            if set(ordered) <= set(DYNAMIC_TOOLS)
            else "comprehensive"
        )
        return plan

    @staticmethod
    def _needs_static(plan: OrchestratorPlan) -> bool:
        return any(a.tool in STATIC_TOOLS for a in plan.tools_sequence)

    def planned_tools(self, state: ScanState, stage: Literal["static", "dynamic"]) -> list[str]:
        """أدوات مرحلة معيّنة من الخطة المُتحقق منها."""
        sequence = state.scan_plan.get("tools_sequence") or []
        wanted = STATIC_TOOLS if stage == "static" else DYNAMIC_TOOLS
        return [a["tool"] for a in sequence if a.get("tool") in wanted]

    # ------------------------------------------------------------------
    # المرحلة 2: تنفيذ حزم الأدوات / Tool execution bundles
    # ------------------------------------------------------------------
    async def execute_stage(
        self, state: ScanState, stage: Literal["static", "dynamic"]
    ) -> dict[str, Any]:
        """تنفيذ أدوات مرحلة (static/dynamic) وتجميع النتائج كـ bundles."""
        if not self.mcp.direct and self.mcp.client is None:
            await self.mcp.initialize()

        artifacts: dict[str, str] = dict(state.raw_artifacts)
        executed: list[str] = list(state.tools_executed)
        errors: list[str] = []
        for tool in self.planned_tools(state, stage):
            started = time.perf_counter()
            try:
                if tool == "jadx":
                    bundle = await self._run_jadx(state)
                elif tool == "mobsf":
                    bundle = await self._run_mobsf(state)
                elif tool == "frida":
                    bundle = await self._run_frida(state)
                elif tool == "objection":
                    bundle = await self._run_objection(state)
                else:
                    raise McpToolError(f"أداة غير مدعومة في التنفيذ: {tool}")
                ref = self.store.save(state.scan_id, f"{tool}_bundle", bundle)
                artifacts[tool] = ref
                executed.append(tool)
                duration_ms = int((time.perf_counter() - started) * 1000)
                self.log_tool_action(tool, ok=True, duration_ms=duration_ms, scan_id=state.db_scan_id)
            except Exception as exc:  # تدهور رشيق — نسجّل ونكمل
                duration_ms = int((time.perf_counter() - started) * 1000)
                errors.append(f"{tool} failed: {exc}")
                self.log_tool_action(
                    tool, ok=False, duration_ms=duration_ms,
                    scan_id=state.db_scan_id, error_message=str(exc)[:500],
                )
        return {
            "raw_artifacts": artifacts,
            "tools_executed": executed,
            # دمج مع الأخطاء المتراكمة: العقدة تُستدعى لمرحلتين (static/dynamic)
            # وأي عقدة تُرجع "errors" تستبدل الحقل، فحذف السابق = فقدان صامت.
            "errors": list(state.errors) + errors,
        }

    # ------------------------------------------------------------------
    # حزم الأدوات / Per-tool bundles (أدوات MCP الحقيقية من المرحلة 2 فقط)
    # ------------------------------------------------------------------
    async def _run_jadx(self, state: ScanState) -> dict[str, Any]:
        apk = state.apk_path
        decompile = await self.mcp.call_tool("jadx.decompile", apk_path=apk)
        manifest = await self.mcp.call_tool("jadx.get_manifest", apk_path=apk)
        permissions = await self.mcp.call_tool("jadx.list_permissions", apk_path=apk)
        search = await self.mcp.call_tool(
            "jadx.search_code", apk_path=apk, keyword="password", max_results=50
        )
        return {
            "decompile_ref": decompile.get("artifact_ref"),
            "classes_count": decompile.get("classes_count", 0),
            "manifest": manifest.get("manifest"),
            "permissions": permissions.get("permissions", []),
            "search_password": search.get("matches", []),
        }

    async def _run_mobsf(self, state: ScanState) -> dict[str, Any]:
        up = await self.mcp.call_tool("mobsf.upload_apk", apk_path=state.apk_path)
        if not up.get("success"):
            raise McpToolError(f"upload failed: {up.get('error')}")
        scan = await self.mcp.call_tool("mobsf.start_scan", scan_hash=up["scan_hash"])
        if not scan.get("success"):
            raise McpToolError(f"scan failed: {scan.get('error')}")
        report = await self.mcp.call_tool("mobsf.get_report", scan_id=scan["scan_id"])
        findings = await self.mcp.call_tool("mobsf.get_findings", scan_id=scan["scan_id"])
        return {
            "scan_id": scan["scan_id"],
            "report_ref": report.get("artifact_ref"),
            "findings": findings.get("findings", []),
        }

    async def _run_frida(self, state: ScanState) -> dict[str, Any]:
        devices = await self.mcp.call_tool("frida.list_devices")
        if not devices.get("devices"):
            raise McpToolError("لا توجد أجهزة متاحة لـ Frida")
        spawn = await self.mcp.call_tool("frida.spawn_app", package_name=state.package_name)
        if not spawn.get("success"):
            raise McpToolError(f"spawn failed: {spawn.get('error')}")
        session_id = spawn["session_id"]
        crypto = await self.mcp.call_tool(
            "frida.capture_crypto", session_id=session_id, duration=10
        )
        network = await self.mcp.call_tool(
            "frida.capture_network", session_id=session_id, duration=10
        )
        ssl = await self.mcp.call_tool(
            "frida.run_hook", session_id=session_id, script_name="ssl_bypass", duration=5
        )
        root = await self.mcp.call_tool(
            "frida.run_hook", session_id=session_id, script_name="root_bypass", duration=5
        )
        return {
            "session_id": session_id,
            "pid": spawn.get("pid"),
            "devices": devices.get("devices", []),
            "crypto_ref": crypto.get("artifact_ref"),
            "network_ref": network.get("artifact_ref"),
            "ssl_bypass_ref": ssl.get("artifact_ref"),
            "root_bypass_ref": root.get("artifact_ref"),
        }

    async def _run_objection(self, state: ScanState) -> dict[str, Any]:
        pkg = state.package_name
        storage = await self.mcp.call_tool("objection.explore_storage", package_name=pkg)
        keystore = await self.mcp.call_tool("objection.dump_keystore", package_name=pkg)
        pinning = await self.mcp.call_tool("objection.bypass_pinning", package_name=pkg)
        root = await self.mcp.call_tool("objection.root_bypass", package_name=pkg)
        activities = await self.mcp.call_tool("objection.list_activities", package_name=pkg)
        return {
            "storage_ref": storage.get("artifact_ref"),
            "keystore_ref": keystore.get("artifact_ref"),
            "keystore_count": keystore.get("items_count", 0),
            "pinning_bypassed": pinning.get("bypassed", False),
            "pinning_detail": pinning.get("detail", ""),
            "root_bypassed": root.get("bypassed", False),
            "root_detail": root.get("detail", ""),
            "activities": activities.get("activities", []),
        }
