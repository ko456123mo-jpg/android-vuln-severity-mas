"""مخزن المتجهات / Vector store (المرحلة 7).

خلفيتان بواجهة واحدة:
    1. sqlite-vec  — الامتداد الأصلي (vec0 virtual table) عند توفر التحميل؛
                     جدول vec_knowledge_base(embedding float[N] distance_metric=cosine).
    2. python      — بديل كامل بلا امتداد: جدول عادي vec_knowledge_base
                     (kb_id, dim, embedding BLOB) + تشابه جيبي في NumPy.

قرارات موثقة (docs/rag_architecture.md):
    • المخزن يفتح اتصال sqlite3 مستقلاً على نفس ملف قاعدة البيانات (تحميل
      الامتداد مطلب لاتصال sqlite3 وليس لـ SQLAlchemy) — والاتصالان على نفس
      الملف آمنان (SQLite multi-connection).
    • اختلاف أبعاد المتجهات بين الأوضاع (mock=384 ثابت، tfidf=حجم المعجم)
      يُكتشف عند init_schema(dim): الجدول يُعاد إنشاؤه تلقائياً مع تحذير،
      وعليه تُعاد الفهرسة (ingest) — سلوك حتمي موثق.
    • درجة التشابه المعادة دائماً «تشابه جيبي» ∈ [-1, 1] بصرف النظر عن الخلفية.
"""
from __future__ import annotations

import os
import sqlite3
import struct
from typing import Any, Optional, Sequence

import numpy as np

TABLE_NAME = "vec_knowledge_base"
BACKEND_AUTO = "auto"
BACKEND_SQLITE_VEC = "sqlite-vec"
BACKEND_PYTHON = "python"


def _db_path(db_path: Optional[str] = None) -> str:
    """مسار قاعدة البيانات: وسيط ← DATABASE_PATH ← db.connection."""
    if db_path:
        return str(db_path)
    env = os.getenv("DATABASE_PATH")
    if env:
        return env
    from db.connection import get_db_path  # الاسم الصحيح في db.connection

    return str(get_db_path())


def serialize_float32(vector: Sequence[float]) -> bytes:
    """تسلسل متجه float32 بإحداثيات little-endian (صيغة sqlite-vec)."""
    return struct.pack(f"<{len(vector)}f", *[float(x) for x in vector])


def deserialize_float32(blob: bytes) -> list[float]:
    """فك تسلسل متجه float32."""
    count = len(blob) // 4
    return list(struct.unpack(f"<{count}f", blob))


class SqliteVecStore:
    """مخزن متجهات knowledge_base — واجهة واحدة لخلفيتين."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        backend: str = BACKEND_AUTO,
        dim: Optional[int] = None,
    ) -> None:
        self.db_path = _db_path(db_path)
        self._requested_backend = backend or os.getenv("MAS_VECTOR_BACKEND", BACKEND_AUTO)
        self.dim = dim
        self._conn: Optional[sqlite3.Connection] = None
        self.backend = self._resolve_backend()

    # ── الاتصال والخلفية ─────────────────────────────────────────────
    def _resolve_backend(self) -> str:
        """يحدد الخلفية الفعلية (مع fallback آمن للـ python)."""
        if self._requested_backend == BACKEND_PYTHON:
            return BACKEND_PYTHON
        try:
            self._load_extension_available()
            return BACKEND_SQLITE_VEC
        except Exception:
            if self._requested_backend == BACKEND_SQLITE_VEC:
                raise
            return BACKEND_PYTHON

    def _load_extension_available(self) -> None:
        """يتحقق من إمكانية تحميل امتداد sqlite-vec."""
        import sqlite_vec  # ImportError ⇒ يسقط للبديل

        conn = sqlite3.connect(":memory:")
        try:
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            version = conn.execute("SELECT vec_version()").fetchone()
            if not version:
                raise RuntimeError("sqlite-vec لم يُحمّل")
        finally:
            conn.close()

    @property
    def conn(self) -> sqlite3.Connection:
        """اتصال sqlite3 كسول + تحميل الامتداد حسب الخلفية."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            if self.backend == BACKEND_SQLITE_VEC:
                import sqlite_vec

                self._conn.enable_load_extension(True)
                sqlite_vec.load(self._conn)
                self._conn.enable_load_extension(False)
        return self._conn

    def close(self) -> None:
        """إغلاق الاتصال."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── المخطط ───────────────────────────────────────────────────────
    def existing_schema(self) -> dict[str, Any]:
        """وصف الجدول القائم من DDL نصياً فقط (بلا PRAGMA — آمن بلا الامتداد).

        يعيد {exists: bool, kind: "vec0"|"table"|None, dim: int|None}.
        قراءة sqlite_master متاحة دائماً؛ PRAGMA على جدول vec0 يتطلب تحميل
        الامتداد لذلك نتجنبه عمداً (علّة حقيقية اكتشفتها الاختبارات).
        """
        row = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?", (TABLE_NAME,)
        ).fetchone()
        if row is None:
            return {"exists": False, "kind": None, "dim": None}
        ddl = row[0] or ""
        if "USING vec0" in ddl:
            start = ddl.find("float[")
            dim = int(ddl[start + 6 : ddl.find("]", start)]) if start >= 0 else None
            return {"exists": True, "kind": "vec0", "dim": dim}
        first = self.conn.execute(f"SELECT dim FROM {TABLE_NAME} LIMIT 1").fetchone()
        return {"exists": True, "kind": "table", "dim": int(first[0]) if first else None}

    def existing_dim(self) -> Optional[int]:
        """أبعاد الجدول القائم (توافق خلفي — يعيد None عند الغياب)."""
        return self.existing_schema()["dim"]

    def init_schema(self, dim: int) -> bool:
        """ينشئ الجدول المتجهي بالبعد المعطى — يعيد True إذا أُعيد إنشاؤه.

        قواعد الانتقال (موثقة):
          • جدول vec0 موجود بينما الخلفية python ← خطأ صريح (قراءته تحتاج
            الامتداد غير المتاح) بدل فعل غير محدد.
          • جدول عادي موجود بينما الخلفية vec0 ← يُسقط ويُنشأ vec0.
          • اختلاف الأبعاد ← إسقاط وإعادة إنشاء (وعليه تُعاد الفهرسة).
        """
        schema = self.existing_schema()
        recreated = False
        if not schema["exists"]:
            self._create_table(dim)
        elif schema["kind"] == "vec0" and self.backend == BACKEND_PYTHON:
            raise RuntimeError(
                f"جدول {TABLE_NAME} نوعه vec0 بينما الخلفية المطلوبة python — "
                "قراءته تتطلب امتداد sqlite-vec؛ استخدم الخلفية auto/sqlite-vec "
                "أو أزل الجدول لبدء تخزين بديل."
            )
        elif schema["dim"] != int(dim):
            self.conn.execute(f"DROP TABLE IF EXISTS {TABLE_NAME}")
            self._create_table(dim)
            recreated = True
        self.dim = int(dim)
        self.conn.commit()
        return recreated

    def _create_table(self, dim: int) -> None:
        """DDL حسب الخلفية."""
        if self.backend == BACKEND_SQLITE_VEC:
            self.conn.execute(
                f"CREATE VIRTUAL TABLE {TABLE_NAME} USING vec0("
                f"embedding float[{int(dim)}] distance_metric=cosine)"
            )
        else:
            self.conn.execute(
                f"CREATE TABLE {TABLE_NAME} ("
                "kb_id INTEGER PRIMARY KEY, dim INTEGER NOT NULL, embedding BLOB NOT NULL)"
            )

    # ── الكتابة ──────────────────────────────────────────────────────
    def upsert(self, kb_id: int, embedding: Sequence[float]) -> None:
        """إدراج/تحديث متجه (idempotent — rowid = knowledge_base.id)."""
        if self.backend == BACKEND_SQLITE_VEC:
            self.conn.execute(f"DELETE FROM {TABLE_NAME} WHERE rowid = ?", (kb_id,))
            self.conn.execute(
                f"INSERT INTO {TABLE_NAME}(rowid, embedding) VALUES (?, ?)",
                (kb_id, serialize_float32(embedding)),
            )
        else:
            self.conn.execute(
                f"INSERT OR REPLACE INTO {TABLE_NAME}(kb_id, dim, embedding) VALUES (?, ?, ?)",
                (kb_id, len(embedding), serialize_float32(embedding)),
            )
        self.conn.commit()

    def upsert_many(self, items: Sequence[tuple[int, Sequence[float]]]) -> int:
        """إدراج دفعة — يعيد عدد الصفوف."""
        for kb_id, embedding in items:
            self.upsert(kb_id, embedding)
        return len(items)

    def delete(self, kb_id: int) -> bool:
        """حذف متجه — True إذا حُذف صف فعلاً."""
        cursor = self.conn.execute(
            f"DELETE FROM {TABLE_NAME} WHERE {'rowid' if self.backend == BACKEND_SQLITE_VEC else 'kb_id'} = ?",
            (kb_id,),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def clear(self) -> None:
        """إفراغ الجدول (لإعادة الفهرسة الكاملة)."""
        self.conn.execute(f"DELETE FROM {TABLE_NAME}")
        self.conn.commit()

    # ── القراءة ──────────────────────────────────────────────────────
    def count(self) -> int:
        """عدد المتجهات المخزنة."""
        row = self.conn.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}").fetchone()
        return int(row[0]) if row else 0

    def get_embedding(self, kb_id: int) -> Optional[list[float]]:
        """جلب متجه kb_id."""
        column = "embedding"
        key = "rowid" if self.backend == BACKEND_SQLITE_VEC else "kb_id"
        row = self.conn.execute(
            f"SELECT {column} FROM {TABLE_NAME} WHERE {key} = ?", (kb_id,)
        ).fetchone()
        return deserialize_float32(row[0]) if row else None

    def search(
        self,
        query_embedding: Sequence[float],
        top_k: int = 5,
        allowed_ids: Optional[Sequence[int]] = None,
    ) -> list[tuple[int, float]]:
        """أقرب الجيران → [(kb_id, cosine_similarity)] تنازلياً.

        allowed_ids: قيد اختياري (فلترة MASVS من المسترجع).
        """
        if self.count() == 0:
            return []
        qvec = np.asarray(query_embedding, dtype=np.float32)
        qnorm = float(np.linalg.norm(qvec))
        if qnorm == 0.0:
            # متجه صفري (استعلام بلا أي تطابق معجمي في TF-IDF): لا اتجاه ⇒ لا
            # جيران. كان هذا المسار يُسقط sqlite-vec (distance = NULL).
            return []
        allowed = set(int(i) for i in allowed_ids) if allowed_ids is not None else None

        if self.backend == BACKEND_SQLITE_VEC:
            # distance_metric=cosine ⇒ distance = 1 − similarity؛ نسحب هامشاً
            # أكبر عند الفلترة ثم نقتطع (مجموعة KB صغيرة — مقبول وموثق).
            limit = top_k if allowed is None else max(top_k, self.count())
            rows = self.conn.execute(
                f"SELECT rowid, distance FROM {TABLE_NAME} "
                "WHERE embedding MATCH ? ORDER BY distance LIMIT ?",
                (serialize_float32(query_embedding), limit),
            ).fetchall()
            # حماية إضافية: distance قد يكون NULL لصفوف غير قابلة للحساب — نتخطّاها
            candidates = [(int(r), 1.0 - float(d)) for r, d in rows if d is not None]
        else:
            rows = self.conn.execute(f"SELECT kb_id, embedding FROM {TABLE_NAME}").fetchall()
            candidates = []
            for kb_id, blob in rows:
                vec = np.asarray(deserialize_float32(blob), dtype=np.float32)
                vnorm = float(np.linalg.norm(vec)) or 1.0
                similarity = float(np.dot(qvec, vec) / (qnorm * vnorm))
                candidates.append((int(kb_id), similarity))
            candidates.sort(key=lambda item: item[1], reverse=True)

        if allowed is not None:
            candidates = [item for item in candidates if item[0] in allowed]
        return candidates[: int(top_k)]
