"""اختبارات خوادم MCP — Mock Mode بالكامل (لا حاجة لأدوات حقيقية).

تغطي:
    1. process_runner: نجاح / timeout / retry
    2. ArtifactStore: save + load + list + حماية path traversal
    3. schemas: التحقق من المدخلات (Pydantic validation)
    4. الأدوات الأربع × جميع أدواتها: عقود المخرجات صحيحة
    5. مسارات الفشل: جلسة غير موجودة، سكربت غير معروف، فلتر خاطئ
"""
from __future__ import annotations

import os

os.environ["MCP_MOCK_MODE"] = "1"  # قبل أي استيراد للخوادم / must run before imports

import asyncio  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from mcp_servers.common import McpToolError  # noqa: E402
from mcp_servers.common.artifact_store import ArtifactStore  # noqa: E402
from mcp_servers.common.process_runner import run_command  # noqa: E402
from mcp_servers.common.schemas import (  # noqa: E402
    JadxDecompileInput,
    JadxSearchCodeInput,
    MobSFFindingsInput,
)

# =====================================================================
# أدوات مساعدة / Helpers
# =====================================================================
SERVER_MODULES = {
    "jadx": ("mcp_servers.jadx_server.server", {
        "decompile", "get_manifest", "search_code", "get_class", "list_permissions",
    }),
    "mobsf": ("mcp_servers.mobsf_server.server", {
        "upload_apk", "start_scan", "get_report", "get_findings",
    }),
    "frida": ("mcp_servers.frida_server.server", {
        "list_devices", "spawn_app", "run_hook", "capture_crypto", "capture_network",
    }),
    "objection": ("mcp_servers.objection_server.server", {
        "explore_storage", "dump_keystore", "bypass_pinning", "root_bypass",
        "list_activities",
    }),
}
SAMPLE_APK = "/tmp/mock_sample.apk"  # لا يُقرأ في Mock Mode
SAMPLE_PKG = "com.insecurebank.app"


def _list_tools(server_module: str) -> list[str]:
    """أسماء الأدوات المسجّلة في خادم (عبر FastMCP نفسها)."""
    import importlib

    module = importlib.import_module(server_module)
    tools = asyncio.run(module.mcp.list_tools())
    return [t.name for t in tools]


# =====================================================================
# 1) process_runner
# =====================================================================
class TestProcessRunner:
    def test_success(self):
        result = run_command([sys.executable, "-c", "print('hello-mcp')"], timeout=10)
        assert result["exit_code"] == 0
        assert "hello-mcp" in result["stdout"]
        assert result["timed_out"] is False
        assert result["duration_ms"] >= 0

    def test_timeout_kills_process(self):
        result = run_command(
            [sys.executable, "-c", "import time; time.sleep(30)"], timeout=1
        )
        assert result["timed_out"] is True
        assert result["exit_code"] == -9
        assert result["duration_ms"] < 10_000  # قُتل مبكراً وليس بعد 30 ثانية

    def test_retry_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "attempt.log"
            cmd = [
                sys.executable, "-c",
                "import pathlib,sys; "
                f"p=pathlib.Path(r'{marker}'); "
                "n=int(p.read_text() or '0')+1 if p.exists() else 1; "
                "p.write_text(str(n)); sys.exit(0 if n>=2 else 1)",
            ]
            result = run_command(cmd, timeout=10, retries=1, backoff=0.1)
            assert result["exit_code"] == 0
            assert result["attempts"] == 2  # فشل ثم نجح

    def test_command_not_found(self):
        with pytest.raises(FileNotFoundError):
            run_command(["definitely-not-a-real-binary-xyz"], timeout=5)


# =====================================================================
# 2) ArtifactStore
# =====================================================================
class TestArtifactStore:
    def test_save_load_roundtrip(self, tmp_path):
        store = ArtifactStore(tmp_path)
        big = {"data": "x" * 10_000}
        ref = store.save("test_scan", "jadx", big)
        loaded = store.load(ref)
        assert loaded["data"] == "x" * 10_000

    def test_load_missing_ref(self, tmp_path):
        store = ArtifactStore(tmp_path)
        with pytest.raises(McpToolError):
            store.load("nope/missing.json")

    def test_path_traversal_blocked(self, tmp_path):
        store = ArtifactStore(tmp_path)
        with pytest.raises(McpToolError):
            store.load("../../etc/passwd")

    def test_list_artifacts(self, tmp_path):
        store = ArtifactStore(tmp_path)
        r1 = store.save("scan_a", "jadx", {"n": 1})
        r2 = store.save("scan_a", "mobsf", {"n": 2})
        items = store.list_artifacts("scan_a")
        refs = {i["ref"] for i in items}
        assert {r1, r2} <= refs
        assert all(i["size_bytes"] > 0 for i in items)
        assert store.list_artifacts("no_such_scan") == []


# =====================================================================
# 3) Pydantic schemas (Output/Input validation)
# =====================================================================
class TestSchemas:
    def test_decompile_input_defaults(self):
        params = JadxDecompileInput(apk_path="x.apk")
        assert params.timeout == 300

    def test_search_requires_keyword(self):
        with pytest.raises(ValidationError):
            JadxSearchCodeInput(apk_path="x.apk", keyword="")

    def test_timeout_out_of_range_rejected(self):
        with pytest.raises(ValidationError):
            JadxDecompileInput(apk_path="x.apk", timeout=0)

    def test_findings_input_optional_filter(self):
        assert MobSFFindingsInput(scan_id="s1").severity_filter is None


# =====================================================================
# 4) تسجيل الأدوات في الخوادم الأربعة / Tool registration
# =====================================================================
class TestServerRegistration:
    @pytest.mark.parametrize("server_name", sorted(SERVER_MODULES))
    def test_server_exposes_expected_tools(self, server_name):
        module_path, expected = SERVER_MODULES[server_name]
        names = set(_list_tools(module_path))
        assert expected <= names, f"{server_name}: missing {expected - names}"
        assert "healthcheck" in names


# =====================================================================
# 5) JADX (Mock)
# =====================================================================
class TestJadxServer:
    def test_decompile(self):
        from mcp_servers.jadx_server.server import decompile

        out = decompile(apk_path=SAMPLE_APK)
        assert out["success"] is True
        assert out["classes_count"] > 0
        assert out["artifact_ref"]
        assert out["error"] is None

    def test_get_manifest(self):
        from mcp_servers.jadx_server.server import get_manifest

        out = get_manifest(apk_path=SAMPLE_APK)
        assert out["success"] is True
        manifest = out["manifest"]
        assert manifest["package"] == SAMPLE_PKG
        assert manifest["exported_components"]  # MASVS-PLATFORM evidence

    def test_search_code(self):
        from mcp_servers.jadx_server.server import search_code

        out = search_code(apk_path=SAMPLE_APK, keyword="password")
        assert out["success"] is True
        assert out["total"] == len(out["matches"]) > 0
        assert all("file" in m and "line" in m and "snippet" in m for m in out["matches"])

    def test_get_class(self):
        from mcp_servers.jadx_server.server import get_class

        out = get_class(apk_path=SAMPLE_APK, class_name="com.insecurebank.app.crypto.CryptoUtil")
        assert out["success"] is True
        assert "class CryptoUtil" in out["source"]

    def test_list_permissions(self):
        from mcp_servers.jadx_server.server import list_permissions

        out = list_permissions(apk_path=SAMPLE_APK)
        assert out["success"] is True
        assert "android.permission.INTERNET" in out["permissions"]


# =====================================================================
# 6) MobSF (Mock) — تدفق كامل
# =====================================================================
class TestMobSFServer:
    def test_full_flow(self):
        from mcp_servers.mobsf_server.server import (
            get_findings,
            get_report,
            start_scan,
            upload_apk,
        )

        up = upload_apk(apk_path=SAMPLE_APK)
        assert up["success"] is True and up["scan_hash"]

        scan = start_scan(scan_hash=up["scan_hash"])
        assert scan["success"] is True and scan["scan_id"]
        assert scan["status"] == "completed"

        report = get_report(scan_id=scan["scan_id"])
        assert report["success"] is True and report["artifact_ref"]

        findings = get_findings(scan_id=scan["scan_id"])
        assert findings["success"] is True
        assert findings["total"] == len(findings["findings"]) > 0
        first = findings["findings"][0]
        assert first["cwe_id"] and first["masvs_category"]

    def test_findings_severity_filter(self):
        from mcp_servers.mobsf_server.server import get_findings

        out = get_findings(scan_id="scan_x", severity_filter="high")
        assert out["success"] is True
        assert out["total"] > 0
        assert all(f["severity"] == "High" for f in out["findings"])

    def test_findings_invalid_filter(self):
        from mcp_servers.mobsf_server.server import get_findings

        out = get_findings(scan_id="scan_x", severity_filter="critical!")
        assert out["success"] is False
        assert "غير صالح" in out["error"]


# =====================================================================
# 7) Frida (Mock)
# =====================================================================
class TestFridaServer:
    def _spawn(self):
        from mcp_servers.frida_server.server import spawn_app

        out = spawn_app(package_name=SAMPLE_PKG)
        assert out["success"] is True
        assert out["session_id"] and out["pid"]
        return out["session_id"]

    def test_list_devices(self):
        from mcp_servers.frida_server.server import list_devices

        out = list_devices()
        assert out["success"] is True
        assert out["devices"] and all("id" in d for d in out["devices"])

    def test_spawn_app(self):
        self._spawn()

    def test_run_hook_crypto(self):
        from mcp_servers.frida_server.server import run_hook

        session_id = self._spawn()
        out = run_hook(session_id=session_id, script_name="crypto_trace", duration=2)
        assert out["success"] is True
        assert out["events_count"] > 0 and out["artifact_ref"]

    def test_capture_crypto_and_network(self):
        from mcp_servers.frida_server.server import capture_crypto, capture_network

        session_id = self._spawn()
        crypto = capture_crypto(session_id=session_id, duration=2)
        network = capture_network(session_id=session_id, duration=2)
        assert crypto["success"] is True and crypto["captured_count"] > 0
        assert network["success"] is True and network["captured_count"] > 0

    def test_unknown_script_fails_gracefully(self):
        from mcp_servers.frida_server.server import run_hook

        session_id = self._spawn()
        out = run_hook(session_id=session_id, script_name="evil_script", duration=1)
        assert out["success"] is False
        assert "سكربت غير معروف" in out["error"]

    def test_unknown_session_fails_gracefully(self):
        from mcp_servers.frida_server.server import capture_crypto

        out = capture_crypto(session_id="sess_00000000", duration=1)
        assert out["success"] is False
        assert "unknown session" in out["error"]


# =====================================================================
# 8) Objection (Mock)
# =====================================================================
class TestObjectionServer:
    def test_explore_storage(self):
        from mcp_servers.objection_server.server import explore_storage

        out = explore_storage(package_name=SAMPLE_PKG)
        assert out["success"] is True and out["artifact_ref"]

    def test_dump_keystore(self):
        from mcp_servers.objection_server.server import dump_keystore

        out = dump_keystore(package_name=SAMPLE_PKG)
        assert out["success"] is True and out["items_count"] > 0

    def test_bypass_pinning(self):
        from mcp_servers.objection_server.server import bypass_pinning

        out = bypass_pinning(package_name=SAMPLE_PKG)
        assert out["success"] is True and out["bypassed"] is True

    def test_root_bypass(self):
        from mcp_servers.objection_server.server import root_bypass

        out = root_bypass(package_name=SAMPLE_PKG)
        assert out["success"] is True and out["bypassed"] is True

    def test_list_activities(self):
        from mcp_servers.objection_server.server import list_activities

        out = list_activities(package_name=SAMPLE_PKG)
        assert out["success"] is True
        assert any(a.endswith("LoginActivity") for a in out["activities"])


# =====================================================================
# 9) MCPManager
# =====================================================================
class TestMCPManager:
    def test_registered_servers(self):
        from mcp_servers.manager import MCPManager

        manager = MCPManager()
        assert manager.registered_servers() == ["frida", "jadx", "mobsf", "objection"]

    def test_connection_configs_from_yaml(self):
        from mcp_servers.manager import MCPManager

        configs = MCPManager().get_connection_configs()
        assert set(configs) == {"jadx", "mobsf", "frida", "objection"}
        stdio = {k: v for k, v in configs.items() if v["transport"] == "stdio"}
        assert set(stdio) == {"jadx", "frida", "objection"}
        for cfg in stdio.values():
            assert "server" in cfg["args"][-1] or "-m" in cfg["args"]
        assert configs["mobsf"]["transport"] == "streamable_http"
        assert configs["mobsf"]["url"].startswith("http://")

    def test_unknown_server_raises(self):
        from mcp_servers.manager import MCPManager

        with pytest.raises(KeyError):
            MCPManager().start_server("nope")
