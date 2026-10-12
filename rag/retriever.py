"""المسترجع / Knowledge retriever (المرحلة 7).

    • retrieve(query, top_k=5, masvs_filter=None)       — استرجاع عام
    • retrieve_for_vulnerability(vuln, top_k=3)          — استرجاع موجّه بثغرة
    • build_context_prompt(retrieved)                    — تنسيق كتلة البرومبت

قرارات موثقة:
    • top_k الافتراضي يُقرأ من config/settings.yaml → rag.retrieval_top_k
      (تجاوز بيئي RAG_RETRIEVAL_TOP_K) — لا ثوابت مبعثرة.
    • إن كان المخزن فارغاً: تُحاوَل فهرسة كسولة مرة واحدة، ثم يقع التراجع
      الآمن إلى قاعدة المعرفة كاملة (السلوك القديم) بدل إسقاط الاستخراج.
    • فلترة MASVS تُمرَّر إلى المخزن كقيد candidates ثم يُقتطع top_k بعدها.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from sqlalchemy import select

from db.connection import get_session
from db.models import KnowledgeBase
from rag.embeddings import EmbeddingEngine
from rag.store_sqlitevec import SqliteVecStore

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"

DEFAULT_TOP_K = 3


def _settings_top_k() -> int:
    """top_k من الإعدادات (بيئة ← yaml ← افتراضي)."""
    env_value = os.getenv("RAG_RETRIEVAL_TOP_K")
    if env_value:
        return max(1, int(env_value))
    try:
        config = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8")) or {}
        return max(1, int((config.get("rag") or {}).get("retrieval_top_k", DEFAULT_TOP_K)))
    except Exception:
        return DEFAULT_TOP_K


def build_context_prompt(retrieved: list[dict[str, Any]]) -> str:
    """تنسيق الأنماط المسترجعة ككتلة نصية تُحقن في برومبت الاستخراج.

    التنسيق يطابق صيغة المرحلة 3 (سطر لكل نمط) مع درجة التشابه — كي لا
    ينكسر أي كاشف في MockLLM أو قوالب برومبت قائمة.
    """
    if not retrieved:
        return "(لم يُسترجع أي نمط — اعتمد على معرفتك العامة بـ MASVS/CWE)"
    lines = []
    for item in retrieved:
        score = item.get("similarity")
        score_text = f" [تشابه {score:.3f}]" if isinstance(score, (int, float)) else ""
        lines.append(
            f"- {item.get('ref_id')} | {item.get('title')} | {item.get('cwe_id')} | "
            f"{item.get('masvs_category')}: {item.get('content')}{score_text}"
        )
    return "\n".join(lines)


class KnowledgeRetriever:
    """مسترجع أنماط knowledge_base بالمتجهات (مع تراجع آمن للكامل)."""

    def __init__(
        self,
        engine: Optional[EmbeddingEngine] = None,
        store: Optional[SqliteVecStore] = None,
        auto_ingest: bool = True,
    ) -> None:
        self.engine = engine or EmbeddingEngine()
        self.store = store or SqliteVecStore()
        self.auto_ingest = auto_ingest

    # ── الاسترجاع ────────────────────────────────────────────────────
    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
        masvs_filter: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """أقرب الأنماط لاستعلام نصي (مع فلترة MASVS اختيارية)."""
        top_k = top_k or _settings_top_k()
        rows = self._load_kb_rows()
        if not rows:
            return []

        if self.store.count() == 0 and self.auto_ingest:
            self._lazy_ingest()
        if self.store.count() == 0:
            return self._fallback(rows, masvs_filter)

        allowed = None
        if masvs_filter:
            allowed = [r["id"] for r in rows if r["masvs_category"] == masvs_filter]
            if not allowed:
                return self._fallback(rows, masvs_filter)

        embedding = self.engine.embed_single(query)
        hits = self.store.search(embedding, top_k=top_k, allowed_ids=allowed)
        by_id = {r["id"]: r for r in rows}
        return [
            {**by_id[kb_id], "similarity": round(score, 4), "source": "vector"}
            for kb_id, score in hits
            if kb_id in by_id
        ]

    def retrieve_for_vulnerability(
        self, vuln: dict[str, Any], top_k: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """استرجاع موجّه: استعلام مركّب من عنوان الثغرة ووصفها وCWE/MASVS."""
        query = " | ".join(
            str(part)
            for part in (
                vuln.get("title"),
                vuln.get("description"),
                vuln.get("cwe_id"),
                vuln.get("masvs_category"),
                vuln.get("sub_category"),
            )
            if part
        ) or str(vuln.get("title") or "vulnerability")
        return self.retrieve(query, top_k=top_k, masvs_filter=vuln.get("masvs_category"))

    def build_context_prompt(self, retrieved: list[dict[str, Any]]) -> str:
        """غلاف للدالة الحرة build_context_prompt (توافق واجهة)."""
        return build_context_prompt(retrieved)

    # ── داخليات ──────────────────────────────────────────────────────
    @staticmethod
    def _load_kb_rows() -> list[dict[str, Any]]:
        """صفوف قاعدة المعرفة كقواميس."""
        with get_session() as session:
            rows = session.scalars(select(KnowledgeBase).order_by(KnowledgeBase.id)).all()
            return [
                {
                    "id": r.id,
                    "source": r.source,
                    "ref_id": r.ref_id,
                    "title": r.title,
                    "content": r.content,
                    "cwe_id": r.cwe_id,
                    "masvs_category": r.masvs_category,
                }
                for r in rows
            ]

    def _lazy_ingest(self) -> None:
        """فهرسة كسولة أولى (بلا كسر عند أي فشل)."""
        try:
            from rag.ingest import ingest_knowledge_base

            ingest_knowledge_base(engine=self.engine, store=self.store)
        except Exception:
            pass

    @staticmethod
    def _fallback(rows: list[dict[str, Any]], masvs_filter: Optional[str]) -> list[dict[str, Any]]:
        """تراجع آمن: قاعدة المعرفة كاملة (مع احترام فلتر MASVS إن وُجد)."""
        selected = [r for r in rows if not masvs_filter or r["masvs_category"] == masvs_filter]
        return [{**r, "similarity": None, "source": "fallback_full_kb"} for r in selected]
