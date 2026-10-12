"""اختبارات وحدة — RAG (خلفيات التضمين + المخزن المتجهي + جودة الاسترجاع + الفهرسة).

الطبقات المختبرة:
    1) EmbeddingEngine: ثبات وضع mock، سلامة TF-IDF، التراجع التلقائي الموثّق، LRU.
    2) نص تركيب الصف (compose_kb_text) — مصدر واحد للفهرسة والاستعلام.
    3) SqliteVecStore: الجولان، الأبعاد، إعادة الإنشاء عند تبديل الخلفية، البحث.
    4) KnowledgeRetriever: **الجودة الفعلية** — استعلامات أمنية معروفة يجب أن
       تُعيد الأنماط الصحيحة في المرتبة الأولى (مُتحقَّق منها يدوياً قبل التثبيت).
    5) ingest_knowledge_base: idempotent، وإعادة فهرسة قسرية.

عزل: كل اختبارات المخزن تستخدم ملفاً مؤقتاً (`tmp_path`) — لا تمسّ مخزن التطبيق
ولا تعتمد على أبعاد خلفية معيّنة، فلا تتأثر المجموعة بترتيب التنفيذ.
"""
from __future__ import annotations

import math
from pathlib import Path

import pytest


# =====================================================================
# 1) محرك التضمين
# =====================================================================
class TestEmbeddingEngine:
    def test_mock_mode_is_deterministic_and_normalized(self) -> None:
        """وضع mock: نفس النص ⇒ نفس المتجه، الأبعاد ثابتة، والطول 1."""
        from rag.embeddings import MOCK_DIM, EmbeddingEngine

        engine = EmbeddingEngine(mode="mock")
        first = engine.embed_single("تشفير ضعيف في التطبيق")
        second = engine.embed_single("تشفير ضعيف في التطبيق")
        assert first == second, "متجهات mock يجب أن تكون ثابتة (بذرة حتمية)"
        assert engine.dim == MOCK_DIM and len(first) == MOCK_DIM
        assert math.isclose(sum(v * v for v in first) ** 0.5, 1.0, rel_tol=1e-4)

    def test_mock_vectors_differ_between_texts(self) -> None:
        """نصوص مختلفة ⇒ متجهات مختلفة (وإلا فالاسترجاع بلا معنى)."""
        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine(mode="mock")
        assert engine.embed_single("SSL pinning") != engine.embed_single("root detection bypass")

    def test_tfidf_mode_works_offline(self) -> None:
        """TF-IDF: يعمل بلا حزم ثقيلة/شبكة، ويُنتج قيماً موجبة لمصطلحات معجمية."""
        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine(mode="tfidf")
        corpus = ["hardcoded API key in source code", "insecure data storage"]
        engine.embed(corpus)  # يبني المعجم
        vectors = engine.embed(["hardcoded API key in source code"])
        assert len(vectors[0]) == engine.dim > 0
        assert any(value > 0 for value in vectors[0])

    def test_fallback_to_tfidf_is_recorded_with_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """فرض ST بلا حزمة مثبتة ⇒ تراجع إلى TF-IDF **مع سبب مسجَّل** (لا صمت)."""
        from rag.embeddings import EmbeddingEngine

        monkeypatch.setenv("MAS_EMBEDDING_BACKEND", "sentence-transformers")
        monkeypatch.delenv("EMBEDDING_MOCK_MODE", raising=False)
        engine = EmbeddingEngine()
        assert engine.mode == "tfidf", "كان يجب التراجع إلى الخلفية المحلية"
        assert engine.fallback_reason, "سبب التراجع إلزامي للتدقيق"

    def test_lru_cache_serves_repeated_text(self) -> None:
        """LRU: النص المتكرر يُخدم من الذاكرة (إصابة مسجَّلة)."""
        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine(mode="mock")
        engine.embed_single("نص متكرر")
        engine.embed_single("نص متكرر")
        stats = engine.cache_stats()
        assert stats["hits"] >= 1 and stats["hit_rate"] > 0

    def test_batch_and_single_agree(self) -> None:
        """embed([x])[0] == embed_single(x) — تماسك الواجهة."""
        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine(mode="mock")
        text = "MASVS-NETWORK certificate pinning"
        assert engine.embed([text])[0] == engine.embed_single(text)


# =====================================================================
# 2) نص تركيب الصف
# =====================================================================
class TestKnowledgeText:
    def test_compose_kb_text_contains_all_semantic_fields(self) -> None:
        """نص الفهرسة يجمع المعرّف والعنوان وCWE والفئة والمحتوى (الترتيب ثابت)."""

        class _Row:
            """صف وهمي بنفس أسماء أعمدة knowledge_base."""

            ref_id = "MSTG-NETWORK-3"
            title = "SSL Pinning Missing"
            cwe_id = "CWE-295"
            masvs_category = "MASVS-NETWORK"
            content = "التطبيق لا يطبق SSL Pinning."

        from rag.embeddings import compose_kb_text

        text = compose_kb_text(_Row())
        for fragment in ("MSTG-NETWORK-3", "SSL Pinning Missing", "CWE-295", "MASVS-NETWORK"):
            assert fragment in text, f"حقل مفقود في نص الفهرسة: {fragment}"

    def test_compose_kb_text_skips_empty_fields(self) -> None:
        """الحقول الفارغة لا تُنتج فواصل زائدة (اتساق النص)."""

        class _Row:
            ref_id = "X-1"
            title = "T"
            cwe_id = None
            masvs_category = None
            content = "C"

        from rag.embeddings import compose_kb_text

        assert compose_kb_text(_Row()) == "X-1 | T | C"


# =====================================================================
# 3) المخزن المتجهي
# =====================================================================
class TestVectorStore:
    def test_roundtrip_count_dim_and_nearest(self, tmp_path: Path) -> None:
        """إدراج متجهات ⇒ العدّ صحيح، والأبعاد معلنة، والبحث يعيد أقرب جار."""
        from rag.store_sqlitevec import SqliteVecStore

        store = SqliteVecStore(db_path=str(tmp_path / "v.db"))
        store.init_schema(8)
        store.upsert(9_000_001, [1.0] + [0.0] * 7)
        store.upsert(9_000_002, [0.0, 1.0] + [0.0] * 6)
        assert store.count() == 2 and store.existing_dim() == 8
        hits = store.search([1.0] + [0.0] * 7, top_k=1)
        assert hits and hits[0][0] == 9_000_001

    def test_dimension_change_recreates_schema(self, tmp_path: Path) -> None:
        """عقد `init_schema`: False للإنشاء الأول/نفس الأبعاد، وTrue عند إعادة الإنشاء."""
        from rag.store_sqlitevec import SqliteVecStore

        store = SqliteVecStore(db_path=str(tmp_path / "v.db"))
        assert store.init_schema(6) is False, "الإنشاء الأول ليس «إعادة إنشاء»"
        assert store.init_schema(6) is False, "نفس الأبعاد ⇒ لا إعادة إنشاء"
        assert store.init_schema(9) is True, "اختلاف الأبعاد ⇒ إعادة إنشاء"
        assert store.existing_dim() == 9

    def test_zero_vector_returns_empty_without_crash(self, tmp_path: Path) -> None:
        """متجه استعلام صفري ⇒ نتائج فارغة بلا استثناء.

        عيب حقيقي أُصلح في المرحلة 8: كان sqlite-vec يعيد `distance = NULL`
        للمتجه الصفري فيسقط البحث بـ `TypeError` بدل إعلان «لا نتائج».
        """
        from rag.store_sqlitevec import SqliteVecStore

        store = SqliteVecStore(db_path=str(tmp_path / "v.db"))
        store.init_schema(4)
        store.upsert(1, [1.0, 0.0, 0.0, 0.0])
        assert store.search([0.0, 0.0, 0.0, 0.0], top_k=2) == []

    def test_allowed_ids_filter(self, tmp_path: Path) -> None:
        """قيد `allowed_ids` يحصر النتائج (يُستخدم لفلترة MASVS)."""
        from rag.store_sqlitevec import SqliteVecStore

        store = SqliteVecStore(db_path=str(tmp_path / "v.db"))
        store.init_schema(4)
        store.upsert(1, [1.0, 0.0, 0.0, 0.0])
        store.upsert(2, [0.9, 0.1, 0.0, 0.0])
        hits = store.search([1.0, 0.0, 0.0, 0.0], top_k=5, allowed_ids=[2])
        assert [kb_id for kb_id, _score in hits] == [2]


# =====================================================================
# 4) جودة الاسترجاع (المعيار الحقيقي لأي RAG)
# =====================================================================
class TestRetrievalQuality:
    @pytest.fixture(scope="class")
    def retriever(self, tmp_path_factory: pytest.TempPathFactory):
        """مسترجع معزول بخلفية TF-IDF (عمل بلا شبكة) + فهرسة كاملة.

        TF-IDF هو الخلفية الاحتياطية المُعلنة (لا نموذج مثبت في هذه البيئة)،
        وأرقام التشابه المتوقعة أدناه مأخوذة من تشغيل حقيقي موثّق.
        """
        from rag.embeddings import EmbeddingEngine
        from rag.ingest import ingest_knowledge_base
        from rag.retriever import KnowledgeRetriever
        from rag.store_sqlitevec import SqliteVecStore

        engine = EmbeddingEngine(mode="tfidf")
        store = SqliteVecStore(db_path=str(tmp_path_factory.mktemp("rag") / "vec.db"))
        report = ingest_knowledge_base(force=True, engine=engine, store=store)
        assert report["store_total"] == report["total_kb_rows"] > 0
        return KnowledgeRetriever(engine=engine, store=store, auto_ingest=False)

    @pytest.mark.parametrize(
        ("query", "expected_ref"),
        [
            ("SSL pinning bypass — certificate pinning not enforced", "MSTG-NETWORK-3"),
            ("hardcoded encryption key stored in source code", "MSTG-CRYPTO-1"),
            ("insecure data storage — sensitive data in shared preferences", "MSTG-STORAGE-1"),
            ("root detection missing — app runs on rooted device", "MSTG-RESILIENCE-1"),
        ],
    )
    def test_known_security_queries_hit_correct_pattern(
        self, retriever, query: str, expected_ref: str
    ) -> None:
        """أربعة استعلامات أمنية ⇒ النمط الصحيح في المرتبة الأولى (جودة مقيسة)."""
        hits = retriever.retrieve(query, top_k=3)
        assert hits, f"لا نتائج للاستعلام: {query}"
        assert hits[0]["ref_id"] == expected_ref, (
            f"المرتبة الأولى {hits[0]['ref_id']} بدل {expected_ref}"
        )
        scores = [float(row["similarity"]) for row in hits]
        assert scores == sorted(scores, reverse=True), "الترتيب ليس تنازلياً"

    def test_retrieved_rows_carry_required_fields(self, retriever) -> None:
        """كل نتيجة تحمل الحقول التي يعتمدها المستخرج والتقارير."""
        hits = retriever.retrieve("certificate pinning", top_k=2)
        assert hits
        for row in hits:
            for field in ("id", "ref_id", "title", "content", "masvs_category", "similarity"):
                assert field in row, f"حقل ناقص: {field}"
            assert 0.0 <= float(row["similarity"]) <= 1.0001

    def test_top_k_is_respected(self, retriever) -> None:
        """top_k يحدّ النتائج فعلياً."""
        assert len(retriever.retrieve("certificate pinning", top_k=1)) == 1
        assert len(retriever.retrieve("certificate pinning", top_k=3)) <= 3

    def test_query_without_lexical_match_returns_empty(self, retriever) -> None:
        """استعلام خارج معجم قاعدة المعرفة ⇒ [] بلا استثناء (سلوك معلن)."""
        assert retriever.retrieve("zzz-nonexistent-token-qqq", top_k=3) == []

    def test_masvs_filter_restricts_candidates(self, retriever) -> None:
        """فلترة الفئة تُبقي فئة واحدة فقط."""
        hits = retriever.retrieve("ssl pinning", top_k=5, masvs_filter="MASVS-NETWORK")
        assert hits and all(row["masvs_category"] == "MASVS-NETWORK" for row in hits)

    def test_retrieve_for_vulnerability_applies_category(self, retriever) -> None:
        """الاسترجاع الموجَّه بالثغرة يبني الاستعلام ويفلتر بفئتها."""
        vuln = {
            "title": "SSL Pinning Missing",
            "description": "لا يوجد pinning على قناة TLS",
            "masvs_category": "MASVS-NETWORK",
            "cwe_id": "CWE-295",
        }
        hits = retriever.retrieve_for_vulnerability(vuln, top_k=2)
        assert hits and hits[0]["ref_id"] == "MSTG-NETWORK-3"
        assert all(row["masvs_category"] == "MASVS-NETWORK" for row in hits)

    def test_context_prompt_carries_pattern_ids(self, retriever) -> None:
        """نص السياق المُرسل للـ LLM يحمل معرّفات قابلة للتتبع (لا نص حر)."""
        from rag.retriever import build_context_prompt

        hits = retriever.retrieve("certificate pinning", top_k=2)
        prompt = build_context_prompt(hits)
        assert hits[0]["ref_id"] in prompt
        assert "MASVS" in prompt


# =====================================================================
# 5) الفهرسة
# =====================================================================
class TestIngest:
    def test_ingest_is_idempotent(self, tmp_path: Path) -> None:
        """فهرسة ثانية بلا force ⇒ embedded=0 والعدد ثابت (بلا تكرار)."""
        from rag.embeddings import EmbeddingEngine
        from rag.ingest import ingest_knowledge_base
        from rag.store_sqlitevec import SqliteVecStore

        engine = EmbeddingEngine(mode="tfidf")
        store = SqliteVecStore(db_path=str(tmp_path / "ingest.db"))
        first = ingest_knowledge_base(force=True, engine=engine, store=store)
        assert first["embedded"] > 0
        second = ingest_knowledge_base(engine=engine, store=store)
        assert second["embedded"] == 0
        assert second["store_total"] == first["store_total"]

    def test_force_reembeds_everything(self, tmp_path: Path) -> None:
        """force=True يعيد تضمين كل الصفوف بنفس الأبعاد والعدد."""
        from rag.embeddings import EmbeddingEngine
        from rag.ingest import ingest_knowledge_base
        from rag.store_sqlitevec import SqliteVecStore

        engine = EmbeddingEngine(mode="tfidf")
        store = SqliteVecStore(db_path=str(tmp_path / "ingest.db"))
        result = ingest_knowledge_base(force=True, engine=engine, store=store)
        assert result["embedded"] == result["total_kb_rows"]
        assert result["dim"] > 0 and result["store_total"] == result["total_kb_rows"]
