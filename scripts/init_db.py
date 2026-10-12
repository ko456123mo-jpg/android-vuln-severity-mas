#!/usr/bin/env python
"""تهيئة قاعدة البيانات — ينشئ الجداول الـ14 من db/schema.sql (idempotent).

Usage / الاستخدام:
    python scripts/init_db.py
"""
import sys
from pathlib import Path

# السماح بالاستيراد من جذر المشروع عند التشغيل المباشر
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from db.connection import get_db_path, init_db  # noqa: E402

EXPECTED_TABLES = {
    "users",
    "projects",
    "applications",
    "app_context",
    "tools",
    "scans",
    "vulnerabilities",
    "vulnerability_findings",
    "severity_rules",
    "assessments",
    "corrections",
    "feedback_examples",
    "agent_logs",
    "knowledge_base",
}


def main() -> int:
    db_path = get_db_path()
    print("=" * 60)
    print("🗄️  تهيئة قاعدة البيانات / Database initialization")
    print("=" * 60)
    print(f"[init_db] مسار القاعدة / DB path: {db_path}")

    tables = init_db()
    print(f"[init_db] الجداول الموجودة ({len(tables)}):")
    for table in tables:
        print(f"  - {table}")

    missing = EXPECTED_TABLES - set(tables)
    extra = set(tables) - EXPECTED_TABLES
    if missing:
        print(f"[✗] فشل: جداول مفقودة / Missing tables: {sorted(missing)}")
        return 1
    if extra:
        print(f"[i] جداول إضافية (لا مشكلة): {sorted(extra)}")

    print(f"[✓] نجاح: جميع الجداول الـ{len(EXPECTED_TABLES)} موجودة — WAL مفعّل.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
