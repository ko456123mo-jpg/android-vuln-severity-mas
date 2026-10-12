"""إعدادات pytest مشتركة — مسار المشروع + Mock Mode + قاعدة اختبار معزولة.

قاعدة الاختبار: ملف SQLite مؤقت (DATABASE_PATH) يُضبط قبل أي استيراد لـ db،
ويُهيَّأ (init_db + seed) مرة واحدة لكل جلسة عبر fixture تلقائية.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# الاختبارات لا تعتمد أدوات/نماذج حقيقية إطلاقاً / fully offline tests
os.environ.setdefault("MCP_MOCK_MODE", "1")
os.environ.setdefault("LLM_MOCK_MODE", "1")
# RAG: متجهات ثابتة البذرة افتراضياً في الاختبارات (نمط المرحلة 7)
os.environ.setdefault("EMBEDDING_MOCK_MODE", "1")
# المرحلة 8: الاختبارات تُجري مئات الطلبات من نفس العنوان — نُعطّل حدّ المعدل
# صراحةً هنا، واختبارات الأمن تُعيد تفعيله بحدود صغيرة للتحقق الفعلي.
os.environ.setdefault("MAS_RATE_LIMIT_ENABLED", "0")

# قاعدة اختبار معزولة — تُضبط قبل استيراد db (يقرأها get_engine كسولاً)
_TEST_TMP = Path(tempfile.mkdtemp(prefix="mas_test_"))
os.environ["DATABASE_PATH"] = str(_TEST_TMP / "test_app.db")

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _prepare_test_db():
    """تهيئة قاعدة الاختبار: مخطط + بيانات أساسية (users/tools/kb/rules)."""
    from db.connection import init_db
    from db.seed import (
        seed_knowledge_base,
        seed_severity_rules,
        seed_tools,
        seed_users,
    )

    init_db()
    seed_users()
    seed_tools()
    seed_severity_rules()
    seed_knowledge_base()
    yield
