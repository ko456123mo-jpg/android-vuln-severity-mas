"""حزمة الأداء — المرحلة 8 (تخزين مؤقت + تحسين القاعدة).

    • ``caching``       — ``@cached(ttl=...)`` للنصوص الثابتة + ``LRUCacheDict`` للمتجهات.
    • ``db_optimizer``  — ``PRAGMA optimize`` / ``ANALYZE`` / WAL + ``retry_on_lock``.

كل قرارات التصميم (لماذا in-process بلا Redis، لماذا ttl=300 للقواعد) موثقة في
``docs/security_hardening.md`` §الأداء و``docs/thesis/appendix_c_decision_log.md``.
"""
from __future__ import annotations

from core.performance.caching import LRUCacheDict, cached, clear_all_caches
from core.performance.db_optimizer import (
    database_stats,
    optimize_database,
    retry_on_lock,
)

__all__ = [
    "cached",
    "clear_all_caches",
    "LRUCacheDict",
    "optimize_database",
    "database_stats",
    "retry_on_lock",
]
