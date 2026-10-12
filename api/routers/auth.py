"""موجّه المصادقة / Auth API (المرحلة 6).

    POST /auth/login      تسجيل الدخول → JWT
    POST /auth/register   إنشاء مستخدم (admin فقط)
    GET  /auth/me         بيانات المستخدم الحالي
    POST /auth/logout     خروج (JWT stateless — إبطال مرتبط بالعميل)
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api import auth as auth_module
from api.deps import get_current_user, require_admin

router = APIRouter(prefix="/auth", tags=["auth"])


# ── مخططات الطلب/الرد ────────────────────────────────────────────────
class LoginInput(BaseModel):
    """بيانات تسجيل الدخول."""

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    """مستخدم بلا أسرار."""

    id: int
    username: str
    role: str
    email: Optional[str] = None


class TokenResponse(BaseModel):
    """رد تسجيل الدخول."""

    access_token: str
    token_type: str = "bearer"
    user: UserOut


class RegisterInput(BaseModel):
    """إنشاء مستخدم (admin فقط)."""

    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "analyst", "reviewer"] = "analyst"
    email: Optional[str] = Field(default=None, max_length=255)


class MessageOut(BaseModel):
    """رسالة نصية موحدة."""

    message: str


# ── المسارات ─────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginInput) -> TokenResponse:
    """يتحقق من البيانات ويعيد JWT + بيانات المستخدم."""
    user = auth_module.authenticate_user(payload.username, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="اسم المستخدم أو كلمة المرور غير صحيحة")
    token = auth_module.create_access_token(
        {"sub": str(user["id"]), "username": user["username"], "role": user["role"]}
    )
    return TokenResponse(access_token=token, user=UserOut(**user))


@router.post("/register", response_model=UserOut, status_code=201)
async def register(
    payload: RegisterInput,
    _admin: dict[str, Any] = Depends(require_admin),
) -> UserOut:
    """ينشئ مستخدماً جديداً — admin فقط."""
    try:
        created = auth_module.register_user(
            username=payload.username,
            password=payload.password,
            role=payload.role,
            email=payload.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return UserOut(**created)


@router.get("/me", response_model=UserOut)
async def me(current_user: dict[str, Any] = Depends(get_current_user)) -> UserOut:
    """بيانات المستخدم المُصادَق الحالي."""
    return UserOut(**current_user)


@router.post("/logout", response_model=MessageOut)
async def logout(_user: dict[str, Any] = Depends(get_current_user)) -> MessageOut:
    """خروج منطقي — JWT stateless: العميل يحذف التوكن (لا قائمة إبطال في هذه المرحلة)."""
    return MessageOut(message="تم تسجيل الخروج — احذف التوكن من العميل")
