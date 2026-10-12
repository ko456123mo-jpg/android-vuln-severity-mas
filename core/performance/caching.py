"""تخزين مؤقت داخلي / In-process caching (المرحلة 8).

القرار المعماري: **ذاكرة العملية** لا Redis — النظام أحادي العملية (uvicorn
بعامل واحد + Streamlit)، وإدخال Redis يضيف خدمة واعتماداً بلا مكسب قياسي هنا.

الواجهتان:
    ``@cached(ttl=300)``  — تزيين دوال بلا وسائط/بوسائط قابلة للتجزئة؛ تخزين
        TTL + إمكانية ``cache_clear()`` (تُستدعى في الاختبارات عند تغيير البيانات).
        threading-safe لأن Streamlit يشغّل طلبات في خيوط متعددة.
    ``LRUCacheDict(size)`` — قاموس محدود الحجم بإخلاء الأقدم استخداماً،
        مستخدم لتخزين متجهات النصوص المتكررة (استعلامات RAG).

سياسة الطزاجة (TTL):
    • قواعد التقييم ``severity_rules``: 300 ثانية — نادراً ما تتغير (تُنگَز يدوياً).
    • متجهات النصوص: بلا TTL لكن مع سعة محدودة (1000 نص) — مفتاحها النص نفسه
      والنتيجة حتمية لعُقدة/nموذج ثابت، فأي تغيّر للنموذج يستدعي عملية جديدة.
"""
from __future__ import annotations

import functools
import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

_REGISTRY: list[Any] = []  # كل الدوال المزيّنة — لتفريغ شامل في الاختبارات


class LRUCacheDict:
    """قاموس محدود السعة يُخلي الأقل استخداماً حديثاً (LRU) — thread-safe."""

    def __init__(self, maxsize: int = 1000) -> None:
        if maxsize < 1:
            raise ValueError("maxsize يجب أن يكون ≥ 1")
        self.maxsize = int(maxsize)
        self._data: OrderedDict[Any, Any] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: Any, default: Any = None) -> Any:
        """إرجاع قيمة (ويرفع المفتاح لرأس الترتيب) أو الافتراضي."""
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self.hits += 1
                return self._data[key]
            self.misses += 1
            return default

    def put(self, key: Any, value: Any) -> None:
        """إدراج/تحديث قيمة مع إخلاء الأقدم إن امتلأ."""
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def clear(self) -> None:
        """تفريغ كامل."""
        with self._lock:
            self._data.clear()
            self.hits = 0
            self.misses = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    @property
    def hit_rate(self) -> float:
        """نسبة الإصابة (0 عند غياب أي طلب)."""
        total = self.hits + self.misses
        return round(self.hits / total, 4) if total else 0.0


def _make_key(args: tuple, kwargs: dict) -> str:
    """مفتاح تجزئة حتمي للوسائط (repr مرتبة)."""
    payload = repr(args) + repr(sorted(kwargs.items()))
    return hashlib.blake2b(payload.encode("utf-8"), digest_size=16).hexdigest()


def cached(ttl: float = 300.0, maxsize: int = 256) -> Callable[[F], F]:
    """مُزيّن تخزين مؤقت بزمن صلاحية — مع ``cache_clear()`` و``cache_info()``.

    مثال:
        @cached(ttl=300)
        def load_active_rule() -> dict: ...
    """

    def decorator(func: F) -> F:
        store: dict[str, tuple[float, Any]] = {}
        lock = threading.Lock()
        stats = {"hits": 0, "misses": 0, "evictions": 0}

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key = _make_key(args, kwargs)
            now = time.monotonic()
            with lock:
                entry = store.get(key)
                if entry is not None and (ttl <= 0 or now - entry[0] < ttl):
                    stats["hits"] += 1
                    return entry[1]
                if entry is not None:
                    stats["evictions"] += 1
            value = func(*args, **kwargs)
            with lock:
                stats["misses"] += 1
                store[key] = (time.monotonic(), value)
                while len(store) > maxsize:
                    store.pop(next(iter(store)))
            return value

        def cache_clear() -> None:
            """تفريغ التخزين (تُستدعى عند تغيير الأسطر المرجعية في الاختبارات)."""
            with lock:
                store.clear()

        def cache_info() -> dict[str, Any]:
            """إحصاءات الاستخدام (للتقرير/الاختبارات)."""
            with lock:
                return {**stats, "size": len(store), "ttl": ttl, "maxsize": maxsize}

        wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
        wrapper.cache_info = cache_info  # type: ignore[attr-defined]
        _REGISTRY.append(wrapper)
        return wrapper  # type: ignore[return-value]

    return decorator


def clear_all_caches() -> int:
    """تفريغ كل التخزينات المسجَّلة — يُعيد عدد الدوال المُفرَّغة."""
    count = 0
    for wrapper in _REGISTRY:
        clear = getattr(wrapper, "cache_clear", None)
        if callable(clear):
            clear()
            count += 1
    return count
