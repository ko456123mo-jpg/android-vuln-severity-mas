"""MobSFClient — عميل MobSF REST API الحقيقي + Mock Mode.

Real mode (يتطلب MobSF يعمل، انظر docs/mcp_design.md):
    POST {MOBSF_URL}/api/v1/upload        (multipart) → scan_hash
    POST {MOBSF_URL}/api/v1/scan          (form)      → نتائج متزامنة
    POST {MOBSF_URL}/api/v1/report_json   (form)      → تقرير JSON كامل
    Headers: Authorization: <MOBSF_API_KEY>
Mock mode: بيانات واقعية من mcp_servers.common.mock_data.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from mcp_servers.common import ARTIFACTS_DIR, McpToolError, is_mock_mode
from mcp_servers.common.artifact_store import ArtifactStore
from mcp_servers.common.mock_data import MOBSF_FINDINGS, MOBSF_REPORT

_ALLOWED_SEVERITIES = {"high", "medium", "low", "info", "warning"}


class MobSFClient:
    """عميل MobSF (upload → scan → report → findings)."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        store: ArtifactStore | None = None,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("MOBSF_URL") or "http://localhost:8000"
        ).rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("MOBSF_API_KEY", "")
        self.store = store or ArtifactStore(ARTIFACTS_DIR)

    # ------------------------------------------------------------------
    # مساعدات داخلية / Internal helpers
    # ------------------------------------------------------------------
    def _require_requests(self):
        """استيراد كسول لـ requests — مطلوبة فقط في Real mode."""
        try:
            import requests

            return requests
        except ImportError as exc:
            raise McpToolError(
                "حزمة requests غير مثبتة، وMock Mode غير مفعّل. "
                "ثبّت requests أو فعّل MCP_MOCK_MODE=1"
            ) from exc

    def _post(self, endpoint: str, timeout: int, **kwargs) -> dict[str, Any]:
        requests = self._require_requests()
        headers = {"Authorization": self.api_key} if self.api_key else {}
        try:
            resp = requests.post(
                f"{self.base_url}{endpoint}", headers=headers, timeout=timeout, **kwargs
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise McpToolError(f"فشل الاتصال بـ MobSF ({endpoint}): {exc}") from exc
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise McpToolError(f"استجابة MobSF ليست JSON ({endpoint})") from exc

    @staticmethod
    def _scan_key(scan_id: str) -> str:
        return f"mobsf_{scan_id[:16]}"

    # ------------------------------------------------------------------
    # الأدوات / Tools
    # ------------------------------------------------------------------
    def upload(self, apk_path: str) -> dict[str, Any]:
        """رفع APK إلى MobSF وإرجاع scan_hash."""
        if is_mock_mode():
            mock_hash = hashlib.md5(apk_path.encode("utf-8")).hexdigest()
            return {
                "success": True,
                "scan_hash": mock_hash,
                "file_name": Path(apk_path).name or "sample.apk",
                "error": None,
            }
        if not Path(apk_path).is_file():
            raise McpToolError(f"ملف APK غير موجود: {apk_path}")
        with open(apk_path, "rb") as fh:
            data = self._post(
                "/api/v1/upload",
                timeout=300,
                files={"file": (Path(apk_path).name, fh, "application/octet-stream")},
                data={"scan_type": "apk"},
            )
        scan_hash = data.get("hash")
        if not scan_hash:
            raise McpToolError(f"لم يُرجع MobSF hash: {str(data)[:200]}")
        return {
            "success": True,
            "scan_hash": scan_hash,
            "file_name": data.get("file_name", Path(apk_path).name),
            "error": None,
        }

    def start_scan(self, scan_hash: str) -> dict[str, Any]:
        """بدء الفحص (متزامن في MobSF) وإرجاع scan_id."""
        if is_mock_mode():
            return {
                "success": True,
                "scan_id": f"scan_{scan_hash[:8]}",
                "status": "completed",
                "error": None,
            }
        self._post(
            "/api/v1/scan",
            timeout=600,
            data={"scan_type": "apk", "hash": scan_hash, "re_scan": "0"},
        )
        return {
            "success": True,
            "scan_id": scan_hash,  # MobSF يستخدم الـ hash كمعرّف للفحص
            "status": "completed",
            "error": None,
        }

    def get_report(self, scan_id: str) -> dict[str, Any]:
        """جلب التقرير الكامل وحفظه كـ artifact (قد يكون ضخماً → ref فقط)."""
        if is_mock_mode():
            report = {
                **MOBSF_REPORT,
                "scan_id": scan_id,
                "findings_count": len(MOBSF_FINDINGS),
            }
        else:
            report = self._post("/api/v1/report_json", timeout=300, data={"hash": scan_id})
        ref = self.store.save(self._scan_key(scan_id), "mobsf", report)
        return {"success": True, "artifact_ref": ref, "error": None}

    def get_findings(
        self, scan_id: str, severity_filter: str | None = None
    ) -> dict[str, Any]:
        """استخراج الثغرات موحّدة الشكل، مع فلترة اختيارية بالخطورة."""
        if severity_filter:
            normalized = severity_filter.strip().lower()
            if normalized not in _ALLOWED_SEVERITIES:
                raise McpToolError(
                    f"severity_filter غير صالح: {severity_filter} — "
                    f"القيم المسموحة: {sorted(_ALLOWED_SEVERITIES)}"
                )
        else:
            normalized = None

        if is_mock_mode():
            findings = list(MOBSF_FINDINGS)
        else:
            report_ref = self.get_report(scan_id)["artifact_ref"]
            findings = self._extract_from_report(self.store.load(report_ref))

        if normalized:
            findings = [f for f in findings if f["severity"].lower() == normalized]
        return {"success": True, "findings": findings, "total": len(findings), "error": None}

    @staticmethod
    def _extract_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
        """تبسيط تقرير MobSF الكامل إلى قائمة findings موحّدة (best-effort).

        بنية تقرير MobSF تتغير بين الإصدارات — نستخرج من code_analysis
        وmanifest_analysis ما أمكن، ونكمّل الحقول الناقصة بقيم افتراضية.
        """
        findings: list[dict[str, Any]] = []
        severity_map = {"high": "High", "warning": "Medium", "info": "Low", "good": "Low"}

        code_analysis = (report.get("code_analysis") or {}).get("findings") or {}
        for _key, item in code_analysis.items():
            meta = item.get("metadata") or item
            findings.append(
                {
                    "title": str(meta.get("description") or _key)[:120],
                    "severity": severity_map.get(str(meta.get("severity", "info")).lower(), "Low"),
                    "description": str(meta.get("description") or "")[:500],
                    "cwe_id": meta.get("cwe"),
                    "masvs_category": meta.get("masvs"),
                    "location": ", ".join((item.get("files") or {}).keys())[:300] or None,
                    "evidence_type": "static",
                    "tool": "mobsf",
                }
            )

        manifest_analysis = report.get("manifest_analysis") or {}
        for item in manifest_analysis.get("manifest_findings") or []:
            findings.append(
                {
                    "title": str(item.get("title") or item.get("name") or "Manifest issue")[:120],
                    "severity": severity_map.get(str(item.get("severity", "info")).lower(), "Low"),
                    "description": str(item.get("description") or "")[:500],
                    "cwe_id": item.get("cwe"),
                    "masvs_category": item.get("masvs"),
                    "location": "AndroidManifest.xml",
                    "evidence_type": "static",
                    "tool": "mobsf",
                }
            )
        return findings
