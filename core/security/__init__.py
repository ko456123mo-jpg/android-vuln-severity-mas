"""حزمة الأمن — المرحلة 8 (تصليب الإنتاج).

المكوّنات:
    • ``rate_limiter`` — حدّ معدل الطلبات لكل IP (in-memory، بلا Redis).
    • ``headers``      — ترويسات أمنية على كل استجابة + HSTS في الإنتاج.
    • ``secrets``      — تحقق من الأسرار/المفاتيح عند بدء التطبيق.

قرارات التصميم موثقة في ``docs/security_hardening.md``.
"""
from __future__ import annotations

from core.security.headers import (
    SecurityHeadersMiddleware,
    build_security_headers,
    with_security_headers,
)
from core.security.rate_limiter import RateLimiter, RateLimitMiddleware
from core.security.secrets import (
    SecretsReport,
    assert_secrets_or_exit,
    load_dotenv_if_present,
    validate_secrets,
)

__all__ = [
    "RateLimiter",
    "RateLimitMiddleware",
    "SecurityHeadersMiddleware",
    "build_security_headers",
    "with_security_headers",
    "SecretsReport",
    "validate_secrets",
    "assert_secrets_or_exit",
    "load_dotenv_if_present",
]
