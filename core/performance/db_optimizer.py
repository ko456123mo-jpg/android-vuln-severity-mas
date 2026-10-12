"""تحسين قاعدة البيانات / DB optimization (المرحلة 8).

ثلاث أدوات عملية:

1. ``optimize_database()`` — تشغيل ``PRAGMA optimize`` ثم ``ANALYZE`` لتحسين
   خطط الاستعلام (يُنصح دورياً — انظر ``--analyze`` في سكربت الفحص النهائي).
   ``ANALYZE`` "أسبوعياً" في النشر: يُنفَّذ من cron/CI أو يدوياً، وليس من كل طلب.
2. ``apply_connection_pragmas()`` — ضبط WAL + ``busy_timeout`` + ``synchronous``
   على اتصال SQLAlchemy (يُستدعى عبر حدث connect كي يسري على كل الاتصالات).
3. ``retry_on_lock()`` — إعادة محاولة عند ``database is locked`` بتراجع أسّي
   قصير (منافسة كتابة متزامنة مع فحص يعمل في الخلفية).

ملاحظة صدق قياسي: هذه تحسينات **محلية لـ SQLite**؛ فالحد الأقصى الحقيقي هو
كاتب واحد في اللحظة (WAL يسمح بقرّاء متزامنين مع كاتب واحد).
"""
from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger("mas.db.optimizer")

T = TypeVar("T")

DEFAULT_BUSY_TIMEOUT_MS = 5000
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY = 0.05


def _resolve_db_path(db_path: Optional[str] = None) -> str:
    """مسار القاعدة: الوسيط ← DATABASE_PATH ← db.connection.get_db_path()."""
    if db_path:
        return str(db_path)
    import os

    env = os.getenv("DATABASE_PATH")
    if env:
        return env
    from db.connection import get_db_path

    return str(get_db_path())


def apply_connection_pragmas(
    connection: Any, busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS
) -> None:
    """تطبيق PRAGMAs الأداء على اتصال SQLAlchemy (يُربط بحدث ``connect``)."""
    cursor = connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA temp_store=MEMORY")
    finally:
        cursor.close()


def optimize_database(db_path: Optional[str] = None, analyze: bool = True) -> dict[str, Any]:
    """تشغيل ``PRAGMA optimize`` (+``ANALYZE``) وإرجاع ملخص قابل للتقرير."""
    resolved = _resolve_db_path(db_path)
    started = time.perf_counter()
    result: dict[str, Any] = {"db_path": resolved, "optimize": None, "analyze": None, "ok": False}
    try:
        with sqlite3.connect(resolved) as connection:
            connection.execute(f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS}")
            optimize_row = connection.execute("PRAGMA optimize").fetchall()
            result["optimize"] = "ok"
            logger.info("PRAGMA optimize: %s", optimize_row)
            if analyze and not resolved == ":memory:":
                connection.execute("ANALYZE")
                result["analyze"] = "ok"
            result["journal_mode"] = connection.execute("PRAGMA journal_mode").fetchone()[0]
            result["page_count"] = connection.execute("PRAGMA page_count").fetchone()[0]
            result["freelist_count"] = connection.execute("PRAGMA freelist_count").fetchone()[0]
        result["ok"] = True
    except sqlite3.Error as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        logger.warning("فشل تحسين القاعدة: %s", exc)
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def vacuum_database(db_path: Optional[str] = None) -> dict[str, Any]:
    """``VACUUM`` لاستعادة المساحة (يُنفَّذ يدوياً — قفل كامل أثناءه)."""
    resolved = _resolve_db_path(db_path)
    started = time.perf_counter()
    try:
        with sqlite3.connect(resolved) as connection:
            connection.execute("VACUUM")
        return {"ok": True, "db_path": resolved,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2)}
    except sqlite3.Error as exc:
        return {"ok": False, "db_path": resolved, "error": f"{type(exc).__name__}: {exc}"}


def retry_on_lock(
    func: Callable[..., T],
    *args: Any,
    attempts: int = DEFAULT_RETRY_ATTEMPTS,
    base_delay: float = DEFAULT_RETRY_BASE_DELAY,
    **kwargs: Any,
) -> T:
    """تنفيذ ``func`` مع إعادة محاولة عند قفل القاعدة.

    شرط الإعادة: ``sqlite3.OperationalError`` رسالتها تحوي «locked» أو «busy»
    (أي تنازع كاتب) — أما أخطاء الاستعلام البرمجية فلا تُعاد (فشل سريع وصحيح).
    التأخير: أسّي 50ms → 100ms → 200ms (سقف إجمالي ≈350ms + زمن المحاولات).
    """
    if attempts < 1:
        raise ValueError("attempts يجب أن يكون ≥ 1")
    last_error: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            return func(*args, **kwargs)
        except sqlite3.OperationalError as exc:  # pragma: no branch — حسب المنافسة
            message = str(exc).lower()
            if "locked" not in message and "busy" not in message:
                raise
            last_error = exc
            if attempt == attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "قاعدة مقفولة (محاولة %d/%d) — إعادة بعد %.0fms", attempt, attempts, delay * 1000
            )
            time.sleep(delay)
    raise sqlite3.OperationalError(
        f"القاعدة ما زالت مقفولة بعد {attempts} محاولات: {last_error}"
    )


def database_stats(db_path: Optional[str] = None) -> dict[str, Any]:
    """معلومات تشخيصية: الحجم، عدد الجداول، WAL، الفهارس."""
    resolved = _resolve_db_path(db_path)
    path = Path(resolved)
    stats: dict[str, Any] = {
        "db_path": resolved,
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
    }
    if not path.exists():
        return stats
    try:
        with sqlite3.connect(resolved) as connection:
            stats["tables"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
            )
            stats["indexes"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
            )
            stats["journal_mode"] = connection.execute("PRAGMA journal_mode").fetchone()[0]
            stats["page_size"] = connection.execute("PRAGMA page_size").fetchone()[0]
            wal = Path(f"{resolved}-wal")
            stats["wal_size_bytes"] = wal.stat().st_size if wal.exists() else 0
    except sqlite3.Error as exc:
        stats["error"] = f"{type(exc).__name__}: {exc}"
    return stats
