"""ArtifactStore — تخزين مخرجات الأدوات الضخمة كملفات JSON وإرجاع مرجع (ref).

الفكرة الأساسية / Rationale:
    لا نرسل 30,000 سطر من الكود المفكّك للـ LLM دفعة واحدة —
    نحفظ المخرجات ونرسل ref فقط، فيسترجعه الوكيل عند الحاجة.

المسار: <base_dir>/<scan_id>/<tool_name>_<timestamp>_<hash>.json
المرجع (ref): مسار نسبي posix داخل base_dir — مثل: "scan_12/capture_crypto_...json"
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_servers.common import ARTIFACTS_DIR, McpToolError

_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def _sanitize(part: str) -> str:
    """تعقيم مكوّن مسار (منع الأحرف الخطرة و path traversal)."""
    return _SAFE.sub("_", str(part))[:80] or "unknown"


class ArtifactStore:
    """مخزن ملفات JSON لمخرجات الأدوات مع مراجع آمنة."""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else ARTIFACTS_DIR

    # ------------------------------------------------------------------
    def save(self, scan_id: str, tool_name: str, content: Any) -> str:
        """حفظ المحتوى وإرجاع المرجع النسبي.

        يُخزَّن المحتوى كما هو (JSON) حتى يعيد load() القيمة الأصلية تماماً.
        """
        scan_dir = self.base_dir / _sanitize(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)

        payload = json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)
        digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:6]
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        filename = f"{_sanitize(tool_name)}_{timestamp}_{digest}.json"

        (scan_dir / filename).write_text(
            json.dumps(content, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
        return f"{scan_dir.name}/{filename}"

    # ------------------------------------------------------------------
    def _resolve_ref(self, ref: str) -> Path:
        """تحويل المرجع إلى مسار آمن داخل base_dir (منع الخروج منه)."""
        candidate = (self.base_dir / ref).resolve()
        base = self.base_dir.resolve()
        if base != candidate and base not in candidate.parents:
            raise McpToolError(f"مرجع غير قانوني (خارج المخزن) / illegal ref: {ref}")
        return candidate

    def load(self, ref: str) -> Any:
        """استرجاع المحتوى الأصلي كما حُفظ."""
        path = self._resolve_ref(ref)
        if not path.is_file():
            raise McpToolError(f"المرجع غير موجود / artifact not found: {ref}")
        return json.loads(path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    def list_artifacts(self, scan_id: str) -> list[dict[str, Any]]:
        """سرد artifacts فحص معيّن (الأحدث أولاً)."""
        scan_dir = self.base_dir / _sanitize(scan_id)
        if not scan_dir.is_dir():
            return []
        items: list[dict[str, Any]] = []
        for path in sorted(scan_dir.glob("*.json"), reverse=True):
            stat = path.stat()
            items.append(
                {
                    "ref": f"{scan_dir.name}/{path.name}",
                    "tool_name": path.name.split("_")[0],
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
        return items
