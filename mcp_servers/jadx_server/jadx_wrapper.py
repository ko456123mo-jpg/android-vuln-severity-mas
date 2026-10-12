"""JadxWrapper — تغليف أوامر JADX CLI الحقيقية + Mock Mode.

Real mode : jadx -d <out_dir> <apk>  ثم قراءة sources/resources من out_dir.
Mock mode : بيانات واقعية من mcp_servers.common.mock_data (بدون الحاجة لـ jadx).

كل مخرجاته صالحة لمخططات schemas.Jadx*Output.
"""
from __future__ import annotations

import hashlib
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from mcp_servers.common import ARTIFACTS_DIR, PROJECT_ROOT, McpToolError, is_mock_mode
from mcp_servers.common.artifact_store import ArtifactStore
from mcp_servers.common.mock_data import (
    JADX_CLASSES_COUNT,
    JADX_CLASS_SOURCE,
    JADX_MANIFEST,
    JADX_PERMISSIONS,
    JADX_SAMPLE_CLASSES,
    JADX_SEARCH_MATCHES,
)
from mcp_servers.common.process_runner import run_command

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


class JadxWrapper:
    """واجهة برمجية موحّدة فوق jadx CLI (مع وضع محاكاة)."""

    def __init__(
        self,
        jadx_bin: str | None = None,
        store: ArtifactStore | None = None,
        work_dir: str | Path | None = None,
    ) -> None:
        self.jadx_bin = jadx_bin or os.getenv("JADX_BIN", "jadx")
        self.store = store or ArtifactStore(ARTIFACTS_DIR)
        self.work_dir = Path(work_dir) if work_dir else PROJECT_ROOT / "data" / "artifacts" / "_jadx_work"

    # ------------------------------------------------------------------
    # مساعدات داخلية / Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_key(apk_path: str) -> str:
        """مفتاح artifacts مشتق من مسار الـ APK (ثابت وقصير)."""
        return f"apk_{hashlib.sha1(str(apk_path).encode()).hexdigest()[:8]}"

    def _out_dir(self, apk_path: str) -> Path:
        return self.work_dir / self._scan_key(apk_path)

    def _ensure_exists(self, apk_path: str) -> None:
        if not Path(apk_path).is_file():
            raise McpToolError(f"ملف APK غير موجود / APK not found: {apk_path}")

    def _ensure_decompiled(self, apk_path: str, timeout: int) -> Path:
        """فك التجميع عند الحاجة فقط (cache في out_dir)."""
        out_dir = self._out_dir(apk_path)
        if (out_dir / "sources").is_dir():
            return out_dir
        self._ensure_exists(apk_path)
        out_dir.mkdir(parents=True, exist_ok=True)
        result = run_command(
            [self.jadx_bin, "-d", str(out_dir), apk_path],
            timeout=timeout,
            capture_output=True,
            retries=1,
        )
        if result["exit_code"] != 0 or result["timed_out"]:
            raise McpToolError(
                f"فشل jadx (code={result['exit_code']}, timeout={result['timed_out']}): "
                f"{result['stderr'][:500]}"
            )
        return out_dir

    # ------------------------------------------------------------------
    # الأدوات / Tools (تعيد حقول *Output)
    # ------------------------------------------------------------------
    def decompile(self, apk_path: str, timeout: int = 300) -> dict[str, Any]:
        """فك تجميع كامل وإرجاع artifact_ref للملخص."""
        if is_mock_mode():
            bundle = {
                "apk": apk_path,
                "package": JADX_MANIFEST["package"],
                "classes_count": JADX_CLASSES_COUNT,
                "sample_classes": JADX_SAMPLE_CLASSES,
                "decompiled_by": "jadx-mock 1.5.0",
            }
            ref = self.store.save(self._scan_key(apk_path), "jadx", bundle)
            return {
                "success": True,
                "artifact_ref": ref,
                "classes_count": JADX_CLASSES_COUNT,
                "error": None,
            }

        out_dir = self._ensure_decompiled(apk_path, timeout)
        java_files = sorted((out_dir / "sources").rglob("*.java"))
        bundle = {
            "apk": apk_path,
            "out_dir": str(out_dir),
            "classes_count": len(java_files),
            "sample_classes": [
                str(p.relative_to(out_dir / "sources")) for p in java_files[:50]
            ],
        }
        ref = self.store.save(self._scan_key(apk_path), "jadx", bundle)
        return {
            "success": True,
            "artifact_ref": ref,
            "classes_count": len(java_files),
            "error": None,
        }

    def get_manifest(self, apk_path: str) -> dict[str, Any]:
        """استخراج AndroidManifest كقاموس (صلاحيات + مكونات مُصدَّرة)."""
        if is_mock_mode():
            return {"success": True, "manifest": dict(JADX_MANIFEST), "error": None}

        out_dir = self._ensure_decompiled(apk_path, timeout=300)
        manifest_candidates = [
            out_dir / "resources" / "AndroidManifest.xml",
            out_dir / "AndroidManifest.xml",
        ]
        manifest_path = next((p for p in manifest_candidates if p.is_file()), None)
        if manifest_path is None:
            raise McpToolError("لم يُعثر على AndroidManifest.xml بعد فك التجميع")
        return {
            "success": True,
            "manifest": self._parse_manifest(manifest_path),
            "error": None,
        }

    @staticmethod
    def _parse_manifest(manifest_path: Path) -> dict[str, Any]:
        """تحليل Manifest إلى dict (قدر معقول للتقييم الساكن)."""
        try:
            root = ET.parse(manifest_path).getroot()
        except ET.ParseError as exc:
            raise McpToolError(f"Manifest غير صالح XML: {exc}") from exc

        data: dict[str, Any] = {
            "package": root.get("package"),
            "version_name": root.get(f"{_ANDROID_NS}versionName"),
            "version_code": root.get(f"{_ANDROID_NS}versionCode"),
            "permissions": [],
            "application": {},
            "exported_components": [],
        }
        for child in root.iter("uses-permission"):
            name = child.get(f"{_ANDROID_NS}name")
            if name:
                data["permissions"].append(name)

        app = root.find("application")
        if app is not None:
            data["application"] = {
                "debuggable": app.get(f"{_ANDROID_NS}debuggable") == "true",
                "allow_backup": app.get(f"{_ANDROID_NS}allowBackup") != "false",
                "uses_cleartext_traffic": app.get(f"{_ANDROID_NS}usesCleartextTraffic")
                == "true",
            }
            for tag in ("activity", "service", "receiver", "provider"):
                for comp in app.iter(tag):
                    name = comp.get(f"{_ANDROID_NS}name")
                    exported = comp.get(f"{_ANDROID_NS}exported") == "true"
                    if name and exported:
                        data["exported_components"].append(
                            {"type": tag, "name": name, "exported": True}
                        )
        return data

    def search_code(
        self, apk_path: str, keyword: str, max_results: int = 50
    ) -> dict[str, Any]:
        """بحث نصي في الكود المفكّك: [{file, line, snippet}, ...]."""
        if is_mock_mode():
            kw = keyword.lower()
            matches = [
                m
                for m in JADX_SEARCH_MATCHES
                if kw in m["snippet"].lower() or kw in m["file"].lower()
            ]
            matches = matches[:max_results]
            return {"success": True, "matches": matches, "total": len(matches), "error": None}

        out_dir = self._ensure_decompiled(apk_path, timeout=300)
        sources = out_dir / "sources"
        matches: list[dict[str, Any]] = []
        kw = keyword.lower()
        for java_file in sorted(sources.rglob("*.java")):
            if len(matches) >= max_results:
                break
            try:
                for line_no, line in enumerate(
                    java_file.read_text(encoding="utf-8", errors="replace").splitlines(),
                    start=1,
                ):
                    if kw in line.lower():
                        matches.append(
                            {
                                "file": str(java_file.relative_to(sources)),
                                "line": line_no,
                                "snippet": line.strip()[:200],
                            }
                        )
                        if len(matches) >= max_results:
                            break
            except OSError:
                continue
        return {
            "success": True,
            "matches": matches,
            "total": len(matches),
            "error": None,
        }

    def get_class(self, apk_path: str, class_name: str) -> dict[str, Any]:
        """استرجاع كود فئة كاملة باسمها المؤهل (com.x.Y)."""
        if is_mock_mode():
            return {
                "success": True,
                "class_name": class_name,
                "source": JADX_CLASS_SOURCE,
                "error": None,
            }

        out_dir = self._ensure_decompiled(apk_path, timeout=300)
        sources = out_dir / "sources"
        rel_path = sources / Path(*class_name.split(".")).with_suffix(".java")
        if not rel_path.is_file():
            raise McpToolError(f"الفئة غير موجودة في الكود المفكّك / class not found: {class_name}")
        return {
            "success": True,
            "class_name": class_name,
            "source": rel_path.read_text(encoding="utf-8", errors="replace"),
            "error": None,
        }

    def list_permissions(self, apk_path: str) -> dict[str, Any]:
        """سرد صلاحيات التطبيق من Manifest."""
        if is_mock_mode():
            return {"success": True, "permissions": list(JADX_PERMISSIONS), "error": None}
        manifest = self.get_manifest(apk_path)["manifest"]
        return {
            "success": True,
            "permissions": (manifest or {}).get("permissions", []),
            "error": None,
        }
