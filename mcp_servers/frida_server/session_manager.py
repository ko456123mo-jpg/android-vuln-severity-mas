"""FridaSessionManager — إدارة جلسات Frida + تنفيذ سكربتات JS + Mock Mode.

Real mode (يتطلب frida-tools + جهاز/محاكي فيه frida-server):
    list_devices  : frida.get_device_manager().enumerate_devices()
    create_session: device.spawn(pkg) → attach(pid) → resume(pid)
    run_hook      : session.create_script(js) → جمع الأحداث لمدة duration → unload
Mock mode  : جلسات وأجهزة وأحداث واقعية من mock_data دون أي جهاز.

الأمان: script_name مقيّد بقائمة ملفات موجودة فعلياً في scripts/ (لا مسارات حرة).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_servers.common import ARTIFACTS_DIR, McpToolError, is_mock_mode
from mcp_servers.common.artifact_store import ArtifactStore
from mcp_servers.common.mock_data import (
    FRIDA_DEVICES,
    FRIDA_HOOK_EVENTS,
)

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"
ALLOWED_SCRIPTS = {
    p.stem: p for p in SCRIPTS_DIR.glob("*.js")
}  # {ssl_bypass: path, ...} — whitelist حقيقية من القرص


@dataclass
class FridaSession:
    """جلسة Frida نشطة (حقيقية أو Mock)."""

    session_id: str
    package_name: str
    device_id: str
    pid: int
    backend: str  # "frida" | "mock"
    created_at: float = field(default_factory=time.time)
    _handle: Any = None  # كائن frida.core.Session في Real mode


class FridaSessionManager:
    """إنشاء/إدارة/إغلاق جلسات Frida وتنفيذ الخطافات."""

    def __init__(self, store: ArtifactStore | None = None) -> None:
        self._sessions: dict[str, FridaSession] = {}
        self.store = store or ArtifactStore(ARTIFACTS_DIR)

    # ------------------------------------------------------------------
    # الأجهزة / Devices
    # ------------------------------------------------------------------
    def list_devices(self) -> dict[str, Any]:
        """سرد الأجهزة المتصلة (ADB/frida-server)."""
        if is_mock_mode():
            return {"success": True, "devices": list(FRIDA_DEVICES), "error": None}
        try:
            import frida
        except ImportError as exc:
            raise McpToolError(
                "حزمة frida غير مثبتة، وMock Mode غير مفعّل "
                "(pip install frida-tools أو MCP_MOCK_MODE=1)"
            ) from exc
        devices = [
            {"id": d.id, "name": d.name, "type": d.type, "state": "attached"}
            for d in frida.get_device_manager().enumerate_devices()
        ]
        return {"success": True, "devices": devices, "error": None}

    # ------------------------------------------------------------------
    # الجلسات / Sessions lifecycle
    # ------------------------------------------------------------------
    def create_session(self, package_name: str, device_id: str | None = None) -> FridaSession:
        """تشغيل التطبيق تحت Frida وإرجاع جلسة نشطة."""
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        if is_mock_mode():
            session = FridaSession(
                session_id=session_id,
                package_name=package_name,
                device_id=device_id or "emulator-5554",
                pid=5000 + (uuid.uuid4().int % 4000),
                backend="mock",
            )
        else:
            try:
                import frida
            except ImportError as exc:
                raise McpToolError("حزمة frida غير مثبتة (pip install frida-tools)") from exc
            try:
                device = (
                    frida.get_device(device_id) if device_id else frida.get_usb_device(timeout=10)
                )
                pid = device.spawn([package_name])
                handle = device.attach(pid)
                device.resume(pid)
            except Exception as exc:
                raise McpToolError(f"فشل تشغيل {package_name} تحت Frida: {exc}") from exc
            session = FridaSession(
                session_id=session_id,
                package_name=package_name,
                device_id=device.id,
                pid=pid,
                backend="frida",
                _handle=handle,
            )
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> FridaSession:
        """جلب جلسة نشطة أو رفع خطأ واضح."""
        session = self._sessions.get(session_id)
        if session is None:
            raise McpToolError(f"جلسة غير موجودة أو مغلقة / unknown session: {session_id}")
        return session

    def list_active_sessions(self) -> list[dict[str, Any]]:
        """سرد الجلسات النشطة."""
        return [
            {
                "session_id": s.session_id,
                "package_name": s.package_name,
                "device_id": s.device_id,
                "pid": s.pid,
                "backend": s.backend,
                "age_s": round(time.time() - s.created_at, 1),
            }
            for s in self._sessions.values()
        ]

    def close_session(self, session_id: str) -> bool:
        """إغلاق جلسة (detach حقيقي في Real mode)."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        if session.backend == "frida" and session._handle is not None:
            try:
                session._handle.detach()
            except Exception:
                pass  # الجلسة ربما ماتت أصلاً — الإغلاق idempotent
        return True

    # ------------------------------------------------------------------
    # تنفيذ الخطافات / Hook execution
    # ------------------------------------------------------------------
    def run_hook(
        self, session_id: str, script_name: str, duration: int = 15
    ) -> dict[str, Any]:
        """تنفيذ سكربت Frida JS على جلسة وجمع الأحداث لمدة duration ثانية.

        يعيد: artifact_ref لملف الأحداث + events_count.
        """
        session = self.get_session(session_id)
        name = script_name.removesuffix(".js")
        if name not in ALLOWED_SCRIPTS:
            raise McpToolError(
                f"سكربت غير معروف: {script_name} — المسموح: {sorted(ALLOWED_SCRIPTS)}"
            )

        if session.backend == "mock":
            started = session.created_at
            events = [
                {"ts": round(time.time() - started, 3), **e}
                for e in FRIDA_HOOK_EVENTS.get(name, [])
            ]
            events.append({"event": "hook.completed", "detail": f"duration={duration}s (mock)"})
        else:
            events = self._run_frida_script(session, ALLOWED_SCRIPTS[name], duration)

        ref = self.store.save(
            session_id,
            f"frida_{name}",
            {"session_id": session_id, "script": name, "duration_s": duration, "events": events},
        )
        return {
            "success": True,
            "artifact_ref": ref,
            "events_count": len(events),
            "error": None,
        }

    @staticmethod
    def _run_frida_script(session: FridaSession, script_path: Path, duration: int) -> list[dict]:
        """تنفيذ سكربت Frida حقيقي وجمع رسائل send()/error."""
        source = script_path.read_text(encoding="utf-8")
        events: list[dict[str, Any]] = []
        started = time.time()

        def on_message(message: dict, _data: bytes | None) -> None:
            entry = {"ts": round(time.time() - started, 3)}
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, dict):
                    entry.update(payload)
                else:
                    entry["event"] = "hook.log"
                    entry["detail"] = str(payload)
            elif message.get("type") == "error":
                entry["event"] = "hook.error"
                entry["detail"] = message.get("description") or message.get("stack") or "error"
            events.append(entry)

        try:
            script = session._handle.create_script(source)
            script.on("message", on_message)
            script.load()
            time.sleep(duration)
            script.unload()
        except Exception as exc:
            raise McpToolError(f"فشل تنفيذ سكربت Frida: {exc}") from exc
        return events
