"""اعتمادات API المشتركة — هوية المستخدم الحالية عبر JWT (المرحلة 6).

استُبدل مستخدم admin المُثبَّت (المرحلة 5 المؤقت) بنظام JWT كامل:
    • get_current_user: يستخرج ``Authorization: Bearer <token>``، يتحقق من
      التوقيع/الصلاحية (api.auth.verify_token)، ثم يعيد قراءة المستخدم من
      القاعدة — يعيد 401 لأي توكن غائب/باطل/منتهٍ أو مستخدم محذوف.
    • require_roles(*roles) / require_admin: حراسة مسارات حسب الدور.

بصمة get_current_user ثابتة (dict بـ id/username/role/email) لذا routers
المرحلة 5 (reviews) تستمر بلا تغيير.
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api import auth as auth_module

_bearer = HTTPBearer(auto_error=False, description="JWT Bearer — من POST /auth/login")

_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    """المستخدم الحالي من التوكن — 401 عند أي فشل مصادقة."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ترويسة Authorization: Bearer مفقودة",
            headers=_UNAUTHORIZED_HEADERS,
        )
    try:
        payload = auth_module.verify_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers=_UNAUTHORIZED_HEADERS,
        ) from exc

    user = auth_module.get_user_by_id(int(payload["sub"]))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="حساب المستخدم لم يعد قائماً",
            headers=_UNAUTHORIZED_HEADERS,
        )
    return user


def require_roles(*roles: str) -> Callable[..., Any]:
    """مصنع اعتماد حراسة بالأدوار — مثال: Depends(require_roles('admin'))."""

    async def _guard(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if current_user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"الدور '{current_user['role']}' غير مخوّل — المطلوب: {'/'.join(roles)}",
            )
        return current_user

    return _guard


require_admin = require_roles("admin")
