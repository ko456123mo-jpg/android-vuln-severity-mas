"""مصادقة JWT كاملة — المرحلة 6 (بديل مستخدم admin المُثبَّت).

قرارات موثقة (docs/api_reference.md §المصادقة):
    • python-jose للتوقيع/التحقق (HS256) + bcrypt خام لتجديد كلمات المرور.
      ملاحظة تعارض: passlib 1.7.4 غير متوافق مع bcrypt>=4 (خطأ قراءة الإصدار
      ``__about__`` وقيود 72 بايت) — لذلك نستدعي bcrypt مباشرة بنفس صيغة
      db/seed.py حرفياً، فيبقى التوافق مع المستخدمين المزروعين قائماً.
    • المفتاح السري: auth.secret_key من settings.yaml مع تجاوز بيئي
      MAS_SECRET_KEY (للنشر). القيمة الافتراضية تطويرية صراحةً.
    • sub في التوكن = str(users.id)؛ تُعاد قراءة المستخدم من القاعدة عند كل
      طلب (تعطيل فوري للحسابات المحذوفة/المنقولة).
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import bcrypt
import yaml
from jose import JWTError, jwt
from sqlalchemy import select

from db.connection import get_session
from db.models import User

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"

# إعدادات افتراضية — تُقرأ فعلياً من settings.yaml (انظر load_auth_settings)
_DEFAULT_AUTH: dict[str, Any] = {
    "secret_key": "mas-dev-secret-key-change-in-production",
    "algorithm": "HS256",
    "access_token_expire_minutes": 60,
}

_BCRYPT_MAX_BYTES = 72  # حد bcrypt الصلب — نقصّ بدل الرفض (سلوك موثق)


def load_auth_settings() -> dict[str, Any]:
    """إعدادات المصادقة: settings.yaml ← تجاوز بيئي MAS_SECRET_KEY."""
    cfg = dict(_DEFAULT_AUTH)
    if SETTINGS_PATH.exists():
        raw = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
        cfg.update({k: v for k, v in (raw.get("auth") or {}).items() if v is not None})
    env_secret = os.getenv("MAS_SECRET_KEY")
    if env_secret:
        cfg["secret_key"] = env_secret
    return cfg


# ---------------------------------------------------------------------
# كلمات المرور
# ---------------------------------------------------------------------
def hash_password(password: str) -> str:
    """تجزئة bcrypt (نفس صيغة seed — متوافق مع admin المزروع)."""
    digest = bcrypt.hashpw(password.encode("utf-8")[:_BCRYPT_MAX_BYTES], bcrypt.gensalt())
    return digest.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """تحقق bcrypt آمن (سجل غير صالح ⇒ False، لا استثناء)."""
    try:
        return bcrypt.checkpw(
            plain.encode("utf-8")[:_BCRYPT_MAX_BYTES], hashed.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------
# التوكن
# ---------------------------------------------------------------------
def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """ينشئ JWT موقّعاً — data تُدمج مع exp/iat."""
    cfg = load_auth_settings()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=int(cfg["access_token_expire_minutes"]))
    )
    payload = {**data, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, cfg["secret_key"], algorithm=cfg["algorithm"])


def verify_token(token: str) -> dict[str, Any]:
    """يفك التوكن ويتحقق من التوقيع والصلاحية — ValueError عند أي خلل."""
    cfg = load_auth_settings()
    try:
        payload = jwt.decode(token, cfg["secret_key"], algorithms=[cfg["algorithm"]])
    except JWTError as exc:  # يشمل ExpiredSignatureError
        raise ValueError(f"توكن غير صالح أو منتهي: {exc}") from exc
    if not payload.get("sub"):
        raise ValueError("التوكن يفتقد الحقل sub")
    return payload


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    """قراءة المستخدم من القاعدة (يُستدعى عند كل طلب مُصادَق)."""
    with get_session() as session:
        user = session.get(User, user_id)
        if user is None:
            return None
        return {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "email": user.email,
        }


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    """تحقق بيانات الدخول — يحدّث users.last_login عند النجاح."""
    with get_session() as session:
        user = session.scalar(select(User).where(User.username == username))
        if user is None or not verify_password(password, user.password_hash):
            return None
        user.last_login = datetime.now(timezone.utc).replace(tzinfo=None)
        session.flush()
        return {"id": user.id, "username": user.username, "role": user.role, "email": user.email}


def register_user(
    username: str,
    password: str,
    role: str,
    email: str | None = None,
) -> dict[str, Any]:
    """إنشاء مستخدم جديد — يرفض الاسم المكرر (ValueError)."""
    with get_session() as session:
        existing = session.scalar(select(User).where(User.username == username))
        if existing is not None:
            raise ValueError(f"اسم المستخدم '{username}' محجوز")
        user = User(
            username=username,
            password_hash=hash_password(password),
            role=role,
            email=email,
        )
        session.add(user)
        session.flush()
        session.refresh(user)
        return {"id": user.id, "username": user.username, "role": user.role, "email": user.email}
