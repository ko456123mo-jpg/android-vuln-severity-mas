"""محرك التوليد المتجهي / Embedding engine (المرحلة 7).

أوضاع العمل (بالترتيب عند mode="auto"):
    1. mock        — EMBEDDING_MOCK_MODE=1: متجهات شبه-عشوائية ثابتة البذرة
                     (حتمية بالكامل: نفس النص ⇒ نفس المتجه) — للاختبارات بلا إنترنت.
    2. sentence-transformers — النموذج السائد محلياً إن كان مثبتاً
                     (افتراضي: paraphrase-multilingual-MiniLM-L12-v2 لدعم العربية).
    3. api         — خدمة embeddings متوافقة مع OpenAI (مفتاح من البيئة).
    4. tfidf       — بديل محلي كامل بلا إنترنت عبر TF-IDF (scikit-learn)؛
                     يُلائم الجسم مرة واحدة على corpus قاعدة المعرفة ثم يخدم الاستعلامات.

قرار موثق (docs/rag_architecture.md): ترتيب الـ auto يفضّل المحلي أولاً (st → tfidf)
قبل API لتجنّب تكاليف شبكية في التشغيل الافتراضي، مع إمكانية الفرض صراحةً.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Optional

import numpy as np

from core.performance.caching import LRUCacheDict as _LRUCacheDict

MOCK_DIM = 384
DEFAULT_ST_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"
DEFAULT_API_MODEL = "text-embedding-3-small"
MOCK_SEED = 20260712  # بذرة ثابتة — تغييرها تغيّر المتجهات (مقصود: ثبات الاختبارات)


class EmbeddingEngine:
    """محرك موحّد: embed(texts) / embed_single(text) بغض النظر عن الخلفية."""

    def __init__(
        self,
        mode: Optional[str] = None,
        model_name: Optional[str] = None,
        st_model: Optional[str] = None,
    ) -> None:
        self.model_name = model_name
        self.st_model = st_model or os.getenv("MAS_ST_MODEL", DEFAULT_ST_MODEL)
        self.mode = mode or self._resolve_mode()
        self._st_model_obj: Any = None  # تحميل كسول للنموذج الثقيل
        self._tfidf: Any = None
        self._tfidf_matrix: Any = None
        self._fitted_corpus: list[str] = []
        # تخزين LRU لمتجهات النصوص المتكررة (استعلامات RAG — المرحلة 8)
        self._vector_cache = _LRUCacheDict(maxsize=1000)
        self.fallback_reason: Optional[str] = None  # سبب التراجع التلقائي (تدقيق)
        self._ensure_backend_available()

    # ── تحديد الوضع ──────────────────────────────────────────────────
    @staticmethod
    def _resolve_mode() -> str:
        """auto: mock (بيئة) ← backend مفروض ← st ← api ← tfidf."""
        if os.getenv("EMBEDDING_MOCK_MODE") == "1":
            return "mock"
        forced = os.getenv("MAS_EMBEDDING_BACKEND")
        if forced:
            return forced
        try:  # noqa: SIM105 — استيراد فحص فقط
            import sentence_transformers  # noqa: F401

            return "sentence-transformers"
        except Exception:
            pass
        if os.getenv("MAS_EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY"):
            return "api"
        return "tfidf"

    @property
    def dim(self) -> int:
        """أبعاد المتجه — يعتمد على الوضع (TF-IDF = حجم المعجم)."""
        if self.mode == "mock":
            return MOCK_DIM
        if self.mode == "tfidf":
            self._ensure_tfidf()
            return len(self._tfidf.get_feature_names_out())
        if self.mode == "sentence-transformers":
            model = self._load_st()
            return int(model.get_sentence_embedding_dimension())
        raise ValueError(f"أبعاد غير معروفة للوضع '{self.mode}' — استخدم fetch أولاً")

    # ── الواجهة العامة ───────────────────────────────────────────────
    def embed(self, texts: list[str]) -> list[list[float]]:
        """يحوّل نصوصاً إلى متجهات (نفس الترتيب)."""
        if not texts:
            return []
        if self.mode == "mock":
            return [self._mock_vector(text) for text in texts]
        if self.mode == "sentence-transformers":
            model = self._load_st()
            vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
            return [np.asarray(v, dtype=np.float32).tolist() for v in vectors]
        if self.mode == "tfidf":
            self._ensure_tfidf()
            matrix = self._tfidf.transform(texts)
            dense = matrix.toarray().astype(np.float32)
            return [row.tolist() for row in dense]
        if self.mode == "api":
            return self._embed_api(texts)
        raise ValueError(f"وضع embeddings غير مدعوم: {self.mode}")

    def embed_single(self, text: str) -> list[float]:
        """متجه نص واحد — يُخدَم من تخزين LRU عند تكرار النص نفسه."""
        cache_key = f"{self.mode}:{text}"
        cached_vector = self._vector_cache.get(cache_key)
        if cached_vector is not None:
            return cached_vector
        vector = self.embed([text])[0]
        self._vector_cache.put(cache_key, vector)
        return vector

    def cache_stats(self) -> dict[str, Any]:
        """إحصاءات تخزين المتجهات (نسبة الإصابة + الحجم)."""
        return {
            "size": len(self._vector_cache),
            "hit_rate": self._vector_cache.hit_rate,
            "hits": self._vector_cache.hits,
            "misses": self._vector_cache.misses,
        }

    def _ensure_backend_available(self) -> None:
        """تراجع تلقائي موثق: ST/API غير قابلين للاستخدام ⇒ TF-IDF المحلي.

        الحالات: حزمة sentence-transformers غير مثبتة، أو مفتاح API غائب.
        يُسجَّل السبب في ``fallback_reason`` ليظهر في التقارير (لا تراجع صامت).
        """
        if self.mode == "sentence-transformers":
            try:
                import sentence_transformers  # noqa: F401
            except Exception as exc:  # حزمة ثقيلة غير مثبتة في هذه البيئة
                self.fallback_reason = (
                    f"sentence-transformers غير متاحة ({type(exc).__name__}) ⇒ TF-IDF"
                )
                self.mode = "tfidf"
        elif self.mode == "api":
            if not (os.getenv("MAS_EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY")):
                self.fallback_reason = "مفتاح Embedding API غائب ⇒ TF-IDF"
                self.mode = "tfidf"

    # ── الخلفيات ─────────────────────────────────────────────────────
    def _mock_vector(self, text: str) -> list[float]:
        """متجه عشوائي ثابت البذرة لكل نص (حتمي 100%)."""
        digest = hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest()
        seed = MOCK_SEED + int.from_bytes(digest, "big")
        rng = np.random.default_rng(seed)
        vector = rng.normal(0.0, 1.0, MOCK_DIM).astype(np.float32)
        norm = float(np.linalg.norm(vector)) or 1.0
        return (vector / norm).tolist()

    def _load_st(self) -> Any:
        """تحميل نموذج sentence-transformers مرة واحدة (كسول)."""
        if self._st_model_obj is None:
            from sentence_transformers import SentenceTransformer

            self._st_model_obj = SentenceTransformer(self.model_name or self.st_model)
        return self._st_model_obj

    def _ensure_tfidf(self) -> None:
        """يلائم TF-IDF على corpus قاعدة المعرفة مرة واحدة (وإلا على بداية فارغة).

        قرار التصميم: التلاؤم من جدول knowledge_base يجعل متجهات الاستعلام
        متسقة مع متجهات التحميل بلا حالة محفوظة على القرص. في البيئات بلا
        قاعدة يُلائم على أول دفعة يُمرَّرها المستدعي.
        """
        if self._tfidf is not None:
            return
        from sklearn.feature_extraction.text import TfidfVectorizer

        corpus = self._load_kb_corpus()
        if not corpus:
            corpus = ["(قاعدة معرفة فارغة)"]
        self._tfidf = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True)
        self._tfidf_matrix = self._tfidf.fit_transform(corpus)
        self._fitted_corpus = list(corpus)

    @staticmethod
    def _load_kb_corpus() -> list[str]:
        """نصوص قاعدة المعرفة (نفس تركيبة ingest — اتساق المتجهات)."""
        try:
            from sqlalchemy import select

            from db.connection import get_session
            from db.models import KnowledgeBase

            with get_session() as session:
                rows = session.scalars(select(KnowledgeBase).order_by(KnowledgeBase.id)).all()
                return [compose_kb_text(r) for r in rows]
        except Exception:
            return []

    def _embed_api(self, texts: list[str]) -> list[list[float]]:
        """خلفية API متوافقة مع OpenAI (تُستدعى فقط عند فرضها/توفر المفتاح)."""
        import requests

        api_key = os.getenv("MAS_EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("MAS_EMBEDDING_BASE_URL", "https://api.openai.com/v1")
        response = requests.post(
            f"{base_url}/embeddings",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": self.model_name or DEFAULT_API_MODEL, "input": texts},
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()["data"]
        return [item["embedding"] for item in sorted(payload, key=lambda d: d["index"])]


def compose_kb_text(row: Any) -> str:
    """تركيبة نص الصف — مصدر واحد للـ ingest والاستعلام (اتساق إجباري)."""
    return " | ".join(
        str(part)
        for part in (
            getattr(row, "ref_id", None) or "",
            getattr(row, "title", None) or "",
            getattr(row, "cwe_id", None) or "",
            getattr(row, "masvs_category", None) or "",
            getattr(row, "content", None) or "",
        )
        if part
    )
