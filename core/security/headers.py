"""ترويسات الأمن / Security headers (المرحلة 8).

كل استجابة API تحمل الترويسات الدفاعية الأساسية:

| الترويسة | القيمة | المخاطرة المُعالجة |
|---|---|---|
| ``X-Content-Type-Options`` | ``nosniff`` | تفسير محتوى بنوع خاطئ (MIME sniffing) |
| ``X-Frame-Options`` | ``DENY`` | Clickjacking عبر تأطير الاستجابات |
| ``X-XSS-Protection`` | ``1; mode=block`` | مرشّحات XSS في المتصفحات القديمة |
| ``Referrer-Policy`` | ``no-referrer`` | تسريب عناوين داخلية عبر Referer |
| ``Permissions-Policy`` | تعطيل الكاميرا/الميكروفون/الموقع | استغلال غير مصرّح به لأجهزة المستخدم |
| ``Content-Security-Policy`` | ``default-src 'none'`` | تحميل موارد خارجية من استجابات API |
| ``Strict-Transport-Security`` | ``max-age=31536000; includeSubDomains`` | **في الإنتاج فقط** (HSTS) |

HSTS يُرسَل فقط عندما يكون ``MAS_ENV=production`` (أو ``MAS_HSTS=1``) أو الطلب
عبر HTTPS — إرساله على HTTP محلي لا معنى له وقد يخدع مطوّري التطوير.
"""
from __future__ import annotations

import os
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

HSTS_VALUE = "max-age=31536000; includeSubDomains"
CSP_VALUE = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

BASE_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": CSP_VALUE,
}


def is_production() -> bool:
    """هل البيئة إنتاج؟ (MAS_ENV=production أو MAS_HSTS=1)."""
    return os.getenv("MAS_ENV", "development").strip().lower() == "production" or os.getenv(
        "MAS_HSTS", "0"
    ).strip().lower() in {"1", "true", "yes", "on"}


def build_security_headers(https: bool = False) -> dict[str, str]:
    """ترويسات الأمن المطبَّقة — مع HSTS عند الإنتاج/HTTPS."""
    headers = dict(BASE_SECURITY_HEADERS)
    if https or is_production():
        headers["Strict-Transport-Security"] = HSTS_VALUE
    return headers


def with_security_headers(
    response: Response, request: Request | None = None, https: bool | None = None
) -> Response:
    """يُلحق الترويسات الأمنية باستجابة صريحة (setdefault — لا يستبدل شيئاً).

    ضرورية لمسار 500: في Starlette تُنفَّذ معالجات ``Exception`` العامة داخل
    ``ServerErrorMiddleware`` **خارج** مكدّس وسائط التطبيق (add_middleware)،
    فلا تمر استجابتها عبر ``SecurityHeadersMiddleware``. استدعاء هذه الدالة
    داخل المعالج يضمن وصول الترويسات لاستجابات 4xx/5xx كلها.

    Args:
        response: الاستجابة المستهدفة.
        request: يُستعمل لاستنتاج HTTPS إن لم تُمرَّر ``https`` صراحةً.
        https: فرض وضع HTTPS (يُفعّل HSTS) — يسبق استنتاج الطلب.
    """
    if https is None:
        https = bool(request is not None and request.url.scheme == "https")
    for name, value in build_security_headers(https=https).items():
        response.headers.setdefault(name, value)
    return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """يضيف الترويسات الأمنية إلى كل استجابة تمر في المكدّس (بما فيها الأخطاء)."""

    def __init__(self, app, force_https: bool = False) -> None:
        super().__init__(app)
        self.force_https = force_https

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """تنفيذ الطلب ثم إلحاق الترويسات (تضمن وصولها لاستجابات 4xx/5xx أيضاً)."""
        response = await call_next(request)
        https = self.force_https or request.url.scheme == "https"
        return with_security_headers(response, https=https)
