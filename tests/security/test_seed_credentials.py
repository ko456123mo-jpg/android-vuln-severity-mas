"""انحدار: البذر كان يتجاهل MAS_ADMIN_PASSWORD تماماً.

core/security/secrets.py يحذّر (ويُسقط الإنتاج) عند بقاء كلمة المرور
الافتراضية، ويقرأ MAS_ADMIN_PASSWORD — لكن db/seed.py كان يعيّن الثابت
"admin123" مباشرة. النتيجة: تعيين المتغير كما تنص الوثائق لا يغيّر شيئاً،
ويُنشر الحساب الإداري بالكلمة المعروفة في كل نشر.
"""
from __future__ import annotations

import bcrypt
import pytest

from db.connection import get_session
from db.models import User


def _admin_hash() -> bytes:
    with get_session() as session:
        user = session.query(User).filter(User.username == "admin").first()
        assert user is not None, "البذر يجب أن ينشئ مستخدم admin"
        return user.password_hash.encode("utf-8")


def test_seeded_admin_uses_the_default_password_in_development() -> None:
    """الافتراضي يبقى admin123 حتى لا ينكسر التجريب المحلي الموثّق."""
    assert bcrypt.checkpw(b"admin123", _admin_hash())


def test_seed_password_constant_honours_the_environment(monkeypatch) -> None:
    """القراءة من البيئة تُطبَّق فعلاً — لا ثابت مضمَّن."""
    import importlib

    import db.seed as seed_module

    monkeypatch.setenv("MAS_ADMIN_PASSWORD", "Zx9!production-Admin#2026")
    reloaded = importlib.reload(seed_module)
    try:
        assert reloaded.ADMIN_PASSWORD == "Zx9!production-Admin#2026"
    finally:
        monkeypatch.delenv("MAS_ADMIN_PASSWORD", raising=False)
        importlib.reload(seed_module)
