"""حدّ معدل الطلبات / In-memory rate limiting (المرحلة 8).

القرار: نافذة انزلاقية (sliding window) بـ ``deque`` من الطوابع الزمنية لكل مفتاح
(IP افتراضياً) — بلا Redis ولا اعتماد خارجي، ما يناسب نشراً أحادي العملية.

الحدّ الافتراضي: **60 طلباً / دقيقة لكل IP** (قابل للضبط عبر
``MAS_RATE_LIMIT_PER_MINUTE``، والتعطيل الكامل عبر ``MAS_RATE_LIMIT_ENABLED=0``).

ملاحظات تشغيلية (موثقة في docs/security_hardening.md):
    • ``/health`` وطلبات ``OPTIONS`` معفاة (فحوص الحاويات/preflight لا تُحسب).
    • الاستجابة 429 بصيغة الأخطاء الموحّدة ``{detail, error}`` + ترويسة ``Retry-After``.
    • الاختبارات الآلية تعطّل الحدّ صراحةً (MAS_RATE_LIMIT_ENABLED=0 في conftest)
      لأنها تُجري مئات الطلبات من نفس العنوان؛ واختبار الأمن يفعّله بحدود صغيرة
      للتحقق الفعلي — لا يُخفى السلوك الإنتاجي خلف «وضع اختبار» دائم.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

DEFAULT_LIMIT_PER_MINUTE = 60
DEFAULT_WINDOW_SECONDS = 60.0
EXEMPT_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})


def _env_flag(name: str, default: bool) -> bool:
    """قراءة علم بيئي ("1"/"0"/"true"/"false") بحالة افتراضية."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class RateLimiter:
    """محاسب نافذة انزلاقية لكل مفتاح — thread-safe."""

    def __init__(
        self,
        max_requests: int = DEFAULT_LIMIT_PER_MINUTE,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        enabled: bool = True,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests يجب أن يكون ≥ 1")
        self.max_requests = int(max_requests)
        self.window_seconds = float(window_seconds)
        self.enabled = bool(enabled)
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._clock: Callable[[], float] = time.monotonic

    # ── الواجهة العامة ────────────────────────────────────────────────
    def allow(self, key: str) -> tuple[bool, dict[str, float]]:
        """هل يُسمح بالطلب؟ يُعيد (مسموح، معلومات) حيث المعلومات تحوي:
        ``limit``, ``remaining``, ``retry_after``."""
        if not self.enabled:
            return True, {"limit": float(self.max_requests), "remaining": float(self.max_requests), "retry_after": 0.0}
        now = self._clock()
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            self._prune(bucket, now)
            if len(bucket) >= self.max_requests:
                retry_after = max(0.0, self.window_seconds - (now - bucket[0]))
                return False, {
                    "limit": float(self.max_requests),
                    "remaining": 0.0,
                    "retry_after": round(retry_after, 3),
                }
            bucket.append(now)
            return True, {
                "limit": float(self.max_requests),
                "remaining": float(self.max_requests - len(bucket)),
                "retry_after": 0.0,
            }

    def reset(self, key: Optional[str] = None) -> None:
        """تصفير مفتاح محدّد (أو الكل) — يُستدعى بين الاختبارات."""
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

    @property
    def tracked_keys(self) -> int:
        """عدد المفاتيح المتتبَّعة حالياً (تشخيص/اختبارات)."""
        with self._lock:
            return len(self._hits)

    # ── داخلي ────────────────────────────────────────────────────────
    def _prune(self, bucket: deque[float], now: float) -> None:
        """إزالة الطوابع الأقدم من النافذة."""
        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    @staticmethod
    def client_key(request: Request) -> str:
        """مفتاح الموازنة: أول IP في X-Forwarded-For وإلا المنفذ المباشر."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"


def build_limiter_from_env() -> RateLimiter:
    """بناء محاسب من متغيرات البيئة (يُستدعى مرة عند تجميع التطبيق)."""
    limit_raw = os.getenv("MAS_RATE_LIMIT_PER_MINUTE", str(DEFAULT_LIMIT_PER_MINUTE))
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = DEFAULT_LIMIT_PER_MINUTE
    enabled = _env_flag("MAS_RATE_LIMIT_ENABLED", True)
    return RateLimiter(max_requests=limit, enabled=enabled)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware يطبّق :class:`RateLimiter` على كل طلب (عدا المعفى)."""

    def __init__(self, app, limiter: Optional[RateLimiter] = None) -> None:
        super().__init__(app)
        self.limiter = limiter or build_limiter_from_env()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """يمرّر الطلب أو يرد 429 مع Retry-After."""
        if request.method == "OPTIONS" or request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        allowed, info = self.limiter.allow(self.limiter.client_key(request))
        if not allowed:
            retry_after = int(info.get("retry_after", 1)) + 1
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"تجاوز حدّ الطلبات ({self.limiter.max_requests}/دقيقة) — أعد المحاولة بعد {retry_after} ثانية",
                    "error": "rate_limited",
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(int(info["limit"]))
        response.headers["X-RateLimit-Remaining"] = str(int(info["remaining"]))
        return response
