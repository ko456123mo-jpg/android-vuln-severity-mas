"""طبقة الوصول للبيانات / Repositories package.

كل دوال CRUD هنا تعيد dict عادي (وليس كائن ORM منفصل) لتجنّب
مشاكل DetachedInstanceError بعد إغلاق الجلسة.
All CRUD functions return plain dicts (not detached ORM objects).
"""
from __future__ import annotations

from typing import Any


def row_to_dict(obj: Any) -> dict[str, Any]:
    """تحويل صف ORM إلى dict (يُستدعى داخل الجلسة قبل إغلاقها)."""
    if obj is None:
        return {}
    return {col.name: getattr(obj, col.name) for col in obj.__table__.columns}
