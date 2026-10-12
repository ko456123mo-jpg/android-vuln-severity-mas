"""تجميع تطبيق FastAPI — المرحلة 6 (API كاملة).

- 9 موجّهات: auth · projects · applications · scans · findings · assessments
  · reviews · reports · dashboard
- معالجات استثناءات موحّدة (404/422/500 بصيغة JSON واحدة)
- CORS مفتوح لبيئة التطوير (يُضيَّق في النشر — قرار موثق)
- فحص الصحة GET /health مع فحص اتصال القاعدة

التشغيل: python scripts/run_api.py --port 8000   أو   uvicorn api.main:app
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.routers import applications, assessments, dashboard, findings, projects
from api.routers import auth as auth_router
from api.routers import reports, reviews, scans
from core.security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    assert_secrets_or_exit,
    load_dotenv_if_present,
    with_security_headers,
)
from db.connection import get_session
from db.models import Application, Project, Scan, Vulnerability

APP_VERSION = "1.0.0"
logger = logging.getLogger("mas.api")


class HealthOut(BaseModel):
    """رد فحص الصحة."""

    status: str
    version: str
    database: str
    counts: dict[str, int] = {}


def _health_counts() -> dict[str, int]:
    """عدادات سريعة للصحة (SELECT فقط)."""
    with get_session() as session:
        return {
            "projects": int(session.scalar(select(func.count()).select_from(Project)) or 0),
            "applications": int(
                session.scalar(select(func.count()).select_from(Application)) or 0
            ),
            "scans": int(session.scalar(select(func.count()).select_from(Scan)) or 0),
            "vulnerabilities": int(
                session.scalar(select(func.count()).select_from(Vulnerability)) or 0
            ),
        }


def _cors_origins() -> list[str]:
    """أصول CORS: MAS_CORS_ORIGINS (نشر) ← «*» تطويرياً (قرار موثق)."""
    raw = os.getenv("MAS_CORS_ORIGINS")
    if raw:
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    return ["*"]


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """دورة حياة التطبيق (المرحلة 8): تحميل .env ثم التحقق من الأسرار.

    في التطوير: تحذيرات فقط. في الإنتاج (MAS_ENV=production): خطأ يمنع الإقلاع.
    """
    load_dotenv_if_present()
    assert_secrets_or_exit()
    yield


def create_app() -> FastAPI:
    """مصنع التطبيق — جاهز للاختبار عبر TestClient وللتشغيل المباشر."""
    app = FastAPI(
        title="Android Vuln Severity MAS",
        version=APP_VERSION,
        description=(
            "نظام متعدد الوكلاء لتقييم خطورة ثغرات تطبيقات أندرويد — "
            "API كاملة (المرحلة 6 + تصليب المرحلة 8): مصادقة JWT، حدود معدل الطلبات، "
            "ترويسات أمنية، مشاريع/تطبيقات/فحوص/ثغرات، حلقة مراجعة بشرية، "
            "تقارير، ولوحة معلومات."
        ),
        lifespan=_lifespan,
        contact={
            "name": "Engineer Mohammed Moneer",
            "email": "moh123mon456@gmail.com",
            "url": "https://github.com/ko456123mo-jpg/android-vuln-severity-mas",
        },
        license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    )

    # CORS — MAS_CORS_ORIGINS في النشر، و«*» تطويرياً: بلا اعتمادات كوكيز (JWT في الترويسة)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── طبقات التصليب (المرحلة 8) ───────────────────────────────────
    # الترتيب: يُضاف الحدّ أولاً ثم الترويسات ⇒ الترويسات أقصى الخارج فتشمل
    # استجابات 429/500 أيضاً (تُضاف Middleware بنمط «الأحدث أولاً» في Starlette).
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    for module in (
        auth_router,
        projects,
        applications,
        scans,
        findings,
        assessments,
        reviews,
        reports,
        dashboard,
    ):
        app.include_router(module.router)

    # ── معالجات الاستثناءات الموحّدة ────────────────────────────────
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """404/401/403/409… بصيغة موحّدة {detail, error} + الترويسات الأمنية."""
        return with_security_headers(
            JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail, "error": "http_error"},
                # ترويسات الاستثناء تُمرَّر صراحةً (WWW-Authenticate على 401،
                # Retry-After…): معالج مخصّص يُلغي السلوك الافتراضي لـ FastAPI.
                headers=getattr(exc, "headers", None),
            ),
            request,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """422 بأخطاء Pydantic كاملة (site/msg/type) — صيغة موحّدة + الترويسات الأمنية."""
        return with_security_headers(
            JSONResponse(
                status_code=422,
                content={"detail": jsonable_encoder(exc.errors()), "error": "validation_error"},
            ),
            request,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """500 بلا تسريب تفاصيل داخلية + سجل كامل في الخادم.

        الترويسات تصل هنا صراحةً: هذا المعالج يُنفَّذ في ServerErrorMiddleware
        خارج مكدّس الوسائط، فلا يمر عبر SecurityHeadersMiddleware.
        """
        logger.exception("Unhandled API error: %s", exc)
        return with_security_headers(
            JSONResponse(
                status_code=500,
                content={"detail": "خطأ داخلي في الخادم", "error": "internal_error"},
            ),
            request,
        )

    @app.get("/health", response_model=HealthOut, tags=["system"])
    def health() -> HealthOut:
        """فحص الصحة: حالة الخدمة + اتصال القاعدة + عدادات سريعة."""
        try:
            counts = _health_counts()
            return HealthOut(status="ok", version=APP_VERSION, database="ok", counts=counts)
        except Exception as exc:  # noqa: BLE001 — فشل القاعدة لا يُسقط الخدمة
            logger.warning("Health check DB failure: %s", exc)
            return HealthOut(status="degraded", version=APP_VERSION, database="error", counts={})

    return app


app = create_app()
