"""ObjectionWrapper — تغليف أوامر Objection CLI الحقيقية + Mock Mode.

Real mode (يتطلب objection مثبتاً + جهاز/محاكي عليه frida-server):
    objection -q -g <pkg> explore --startup-command "<cmd>" ...
    (objection مبني فوق Frida — يشغّل التطبيق وينفّذ الأوامر ويخرج)
Mock mode : بيانات واقعية من mock_data (shared_prefs بنص صريح، keystore...).

كل النتائج الضخمة تُخزَّن عبر ArtifactStore ويُرجع ref فقط.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any

from mcp_servers.common import ARTIFACTS_DIR, McpToolError, is_mock_mode
from mcp_servers.common.artifact_store import ArtifactStore
from mcp_servers.common.mock_data import (
    JADX_PACKAGE,
    OBJECTION_ACTIVITIES,
    OBJECTION_KEYSTORE_ITEMS,
    OBJECTION_STORAGE,
)
from mcp_servers.common.process_runner import run_command


class ObjectionWrapper:
    """واجهة موحّدة فوق objection CLI (مع وضع محاكاة)."""

    def __init__(
        self,
        objection_bin: str | None = None,
        store: ArtifactStore | None = None,
        timeout: int = 180,
    ) -> None:
        self.objection_bin = objection_bin or os.getenv("OBJECTION_BIN", "objection")
        self.store = store or ArtifactStore(ARTIFACTS_DIR)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # مساعدات داخلية / Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_key(package_name: str) -> str:
        return f"pkg_{hashlib.sha1(package_name.encode()).hexdigest()[:8]}"

    def _run_commands(self, package_name: str, commands: list[str], timeout: int) -> str:
        """تنفيذ سلسلة أوامر objection على تطبيق وإرجاع stdout مدمجاً."""
        argv = [self.objection_bin, "-q", "-g", package_name, "explore"]
        for cmd in commands:
            argv.append(f"--startup-command={cmd}")
        result = run_command(argv, timeout=timeout, capture_output=True, retries=1)
        if result["exit_code"] != 0 or result["timed_out"]:
            raise McpToolError(
                f"فشل objection على {package_name} "
                f"(code={result['exit_code']}, timeout={result['timed_out']}): "
                f"{result['stderr'][:400]}"
            )
        return result["stdout"]

    @staticmethod
    def _ok(stdout: str, *needles: str) -> bool:
        """تحقق ساذج من نجاح أمر objection بوجود كلمات مفتاحية."""
        lowered = stdout.lower()
        return any(n.lower() in lowered for n in needles)

    # ------------------------------------------------------------------
    # الأدوات / Tools
    # ------------------------------------------------------------------
    def explore_storage(self, package_name: str) -> dict[str, Any]:
        """استكشاف التخزين المحلي للتطبيق (SharedPrefs/DBs/ملفات خارجية)."""
        if is_mock_mode():
            data = dict(OBJECTION_STORAGE)
            data["package"] = package_name
            ref = self.store.save(self._scan_key(package_name), "objection", data)
            return {"success": True, "artifact_ref": ref, "error": None}

        stdout = self._run_commands(
            package_name,
            ["env", "android hooking search classes android.app.SharedPreferencesImpl"],
            timeout=self.timeout,
        )
        # أفضل جهد: نحفظ المخرجات الخام ليحللها Extractor لاحقاً
        ref = self.store.save(
            self._scan_key(package_name),
            "objection",
            {"package": package_name, "raw_output": stdout},
        )
        return {"success": True, "artifact_ref": ref, "error": None}

    def dump_keystore(self, package_name: str) -> dict[str, Any]:
        """استخراج محتويات Android Keystore المرئية للتطبيق."""
        if is_mock_mode():
            items = [dict(item) for item in OBJECTION_KEYSTORE_ITEMS]
            for item in items:
                item["package"] = package_name
            ref = self.store.save(
                self._scan_key(package_name), "objection", {"keystore_items": items}
            )
            return {
                "success": True,
                "artifact_ref": ref,
                "items_count": len(items),
                "error": None,
            }

        stdout = self._run_commands(package_name, ["android keystore list"], timeout=self.timeout)
        aliases = [line.strip() for line in stdout.splitlines() if "Alias:" in line]
        items = [{"alias": a.replace("Alias:", "").strip()} for a in aliases]
        ref = self.store.save(
            self._scan_key(package_name), "objection", {"keystore_items": items}
        )
        return {
            "success": True,
            "artifact_ref": ref,
            "items_count": len(items),
            "error": None,
        }

    def bypass_pinning(self, package_name: str) -> dict[str, Any]:
        """تعطيل SSL Pinning داخل التطبيق (دليل غياب/ضعف الحماية)."""
        if is_mock_mode():
            return {
                "success": True,
                "bypassed": True,
                "detail": "android sslpinning disable — نجح (mock): لا يوجد Pinning فعّال.",
                "error": None,
            }
        stdout = self._run_commands(
            package_name, ["android sslpinning disable"], timeout=self.timeout
        )
        bypassed = self._ok(stdout, "disabled", "(agent)")
        return {
            "success": True,
            "bypassed": bypassed,
            "detail": stdout.strip()[:300],
            "error": None,
        }

    def root_bypass(self, package_name: str) -> dict[str, Any]:
        """تجاوز كشف الروت داخل التطبيق (دليل غياب MASVS-RESILIENCE)."""
        if is_mock_mode():
            return {
                "success": True,
                "bypassed": True,
                "detail": "android root disable — نجح (mock): كشف الروت غير فعّال.",
                "error": None,
            }
        stdout = self._run_commands(package_name, ["android root disable"], timeout=self.timeout)
        bypassed = self._ok(stdout, "disabled", "(agent)")
        return {
            "success": True,
            "bypassed": bypassed,
            "detail": stdout.strip()[:300],
            "error": None,
        }

    def list_activities(self, package_name: str) -> dict[str, Any]:
        """سرد الـ Activities المعلنة في التطبيق."""
        if is_mock_mode():
            renamed = [a.replace(JADX_PACKAGE, package_name) for a in OBJECTION_ACTIVITIES]
            return {"success": True, "activities": renamed, "error": None}
        stdout = self._run_commands(
            package_name, ["android hooking list activities"], timeout=self.timeout
        )
        activities = sorted(
            {line.strip() for line in stdout.splitlines() if line.strip().startswith("com.")}
        )
        return {"success": True, "activities": activities, "error": None}
