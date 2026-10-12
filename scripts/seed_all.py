#!/usr/bin/env python
"""بذر كامل — تهيئة القاعدة ثم ملء البيانات الأولية (admin + tools + rules + KB).

Usage / الاستخدام:
    python scripts/seed_all.py
"""
import sys
from pathlib import Path

# السماح بالاستيراد من جذر المشروع عند التشغيل المباشر
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from db.connection import init_db  # noqa: E402
from db.seed import main as seed_main  # noqa: E402


def main() -> int:
    init_db()  # ضمان وجود الجداول قبل البذر / ensure schema first
    seed_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
