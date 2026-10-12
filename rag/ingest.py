"""تحميل قاعدة المعرفة إلى المخزن المتجهي / KB ingestion (المرحلة 7).

الخطوات (عند الحاجة فقط — الصفوف التي embedding فارغ، أو force):
    1. قراءة صفوف knowledge_base.
    2. compose_kb_text لكل صف (نفس تركيبة الاستعلام — اتساق إجباري).
    3. engine.embed → متجهات.
    4. store.init_schema(dim) + upsert_many (kb_id = knowledge_base.id).
    5. تحديث knowledge_base.embedding (BLOB float32) — عمود المرحلة 1 الجاهز.

المخرجات ملخص قابل للتحقق: {embedded, skipped, store_total, backend, dim, recreated}.
"""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select

from db.connection import get_session
from db.models import KnowledgeBase
from rag.embeddings import EmbeddingEngine, compose_kb_text
from rag.store_sqlitevec import SqliteVecStore, serialize_float32


def ingest_knowledge_base(
    force: bool = False,
    engine: Optional[EmbeddingEngine] = None,
    store: Optional[SqliteVecStore] = None,
) -> dict[str, Any]:
    """يفهرس knowledge_base في المخزن المتجهي — idempotent بلا مضاعفات."""
    engine = engine or EmbeddingEngine()
    store = store or SqliteVecStore()

    with get_session() as session:
        rows = session.scalars(select(KnowledgeBase).order_by(KnowledgeBase.id)).all()
        pending = [r for r in rows if force or r.embedding is None]
        skipped = len(rows) - len(pending)
        total_rows = len(rows)

    if not pending:
        return {
            "embedded": 0,
            "skipped": skipped,
            "total_kb_rows": total_rows,
            "store_total": store.count(),
            "backend": store.backend,
            "dim": store.existing_dim(),
            "recreated": False,
            "note": "لا صفوف جديدة — استخدم force=True لإعادة الفهرسة الكاملة",
        }

    texts = [compose_kb_text(r) for r in pending]
    vectors = engine.embed(texts)
    recreated = store.init_schema(len(vectors[0]))
    if recreated:
        # أبعاد مختلفة عن الجدول القائم ⇒ أُعيد الإنشاء؛ نعيد فهرسة الكل لضمان الاتساق
        for row, vector in zip(pending, vectors, strict=True):
            store.upsert(row.id, vector)
    else:
        store.upsert_many([(row.id, vec) for row, vec in zip(pending, vectors, strict=True)])

    # تحديث عمود embedding في knowledge_base (BLOB float32)
    with get_session() as session:
        for row, vector in zip(pending, vectors, strict=True):
            record = session.get(KnowledgeBase, row.id)
            if record is not None:
                record.embedding = serialize_float32(vector)

    return {
        "embedded": len(pending),
        "skipped": skipped,
        "total_kb_rows": total_rows,
        "store_total": store.count(),
        "backend": store.backend,
        "dim": len(vectors[0]),
        "recreated": recreated,
    }
