"""المكتبة المشتركة لخوادم MCP / Common utilities shared by all MCP servers.

تصدّر:
- PROJECT_ROOT, ARTIFACTS_DIR : مسارات الجذر والـ artifacts
- is_mock_mode()              : هل Mock Mode مفعّل (MCP_MOCK_MODE=1)
- McpToolError               : استثناء موحّد لأخطاء الأدوات
"""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ARTIFACTS_DIR = PROJECT_ROOT / "data" / "artifacts"


def is_mock_mode() -> bool:
    """تفعيل Mock Mode عبر متغير البيئة MCP_MOCK_MODE=1.

    يُقرأ عند كل استدعاء (وليس عند الاستيراد) ليتمكن المشغّل من تبديله ديناميكياً.
    """
    return os.getenv("MCP_MOCK_MODE", "0") == "1"


class McpToolError(Exception):
    """استثناء متوقع من أداة MCP (ملف مفقود، أمر فاشل، مدخل غير صالح...)."""
