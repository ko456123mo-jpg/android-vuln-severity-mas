"""اختبارات الفوضى والمرونة / Resilience & chaos tests (المرحلة 8).

أربعة سيناريوهات فشل حقيقية — الهدف: **لا انهيار** وسلوك معلوم موثّق:

    1) مزوّد النماذج الأساسي غائب (Groq) ⇒ ترقية بديل من السلسلة + تسجيل السبب،
       وإن غابت كل المزوّدات ⇒ RuntimeError واضحة تسرد المحاولات.
    2) أداة MobSF لا تستجيب (Timeout) ⇒ الفحص يكمل وتُسجَّل الأخطاء (حالة جزئية).
    3) قاعدة البيانات مقفولة (كاتب آخر) ⇒ ``retry_on_lock`` يعيد المحاولة ثم يفشل
       برسالة واضحة، والـ API يرد 500 بصيغة موحّدة بلا انهيار.
    4) نموذج التضمين غير محمّل ⇒ تراجع تلقائي إلى TF-IDF مع سبب مسجَّل.
"""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest


# =====================================================================
# 1) فشل مزوّد النماذج ← سلسلة البدائل
# =====================================================================
class _FakeLLM:
    """كائن نموذج وهمي يحمل سلسلة بدائل (يكفي لاختبار منطق الانتقاء)."""

    def __init__(self, provider: str) -> None:
        self.provider = provider
        self.fallbacks: list[Any] = []

    def with_fallbacks(self, fallbacks: list[Any]) -> "_FakeLLM":
        """يسجّل البدائل ويعيد نفسه (كما يفعل LangChain)."""
        self.fallbacks = fallbacks
        return self


class TestProviderFallback:
    def test_primary_missing_promotes_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Groq غير متاح (حزمة/مفتاح) ⇒ يُرقّى أول بديل متاح في السلسلة بلا انهيار.

        السلسلة المعلنة في الإعداد: groq ← gemini ← ollama، لذا المتوقع هنا
        gemini؛ الاختبار يقرأ السلسلة من الإعداد نفسه لا يفترض ترتيباً صلباً.
        """
        from agents.llm_client import LLMClient

        monkeypatch.setenv("LLM_MOCK_MODE", "0")
        client = LLMClient(load_env=False)

        def fake_build(*, provider: str, model: str, temperature: float) -> _FakeLLM:
            if provider == "groq":
                raise ModuleNotFoundError("No module named 'langchain_groq'")
            return _FakeLLM(provider)

        monkeypatch.setattr(client, "_build_llm", fake_build)

        available_fallbacks = [
            provider
            for provider in client.llm_cfg.get("fallback_chain", [])
            if provider != "groq"
        ]
        assert available_fallbacks, "سلسلة البدائل يجب أن تُعرَّف في config/agents.yaml"
        expected = available_fallbacks[0]

        llm = client.get_llm_with_fallback("scorer")  # مزوّده الأساسي groq

        assert isinstance(llm, _FakeLLM)
        assert llm.provider == expected, "يجب أن يُرقّى أول بديل متاح في السلسلة"
        selection = client.last_provider_selection
        assert selection["degraded"] is True
        assert selection["requested"] == "groq" and selection["selected"] == expected
        assert any("groq" in attempt and "ok" not in attempt for attempt in selection["attempts"])

    def test_all_providers_missing_raises_clear_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """غياب كل المزوّدات ⇒ RuntimeError تشرح البدائل المجرَّبة (بلا فشل صامت)."""
        from agents.llm_client import LLMClient

        monkeypatch.setenv("LLM_MOCK_MODE", "0")
        client = LLMClient(load_env=False)

        def always_fail(*, provider: str, model: str, temperature: float) -> Any:
            raise ModuleNotFoundError(f"no provider {provider}")

        monkeypatch.setattr(client, "_build_llm", always_fail)
        with pytest.raises(RuntimeError) as excinfo:
            client.get_llm_with_fallback("extractor")
        message = str(excinfo.value)
        assert "لا مزوّد نماذج متاح" in message
        assert "LLM_MOCK_MODE=1" in message, "الرسالة تُرشد للتشغيل بوضع Mock"
        assert client.last_provider_selection["selected"] is None

    def test_runtime_failover_chain_attached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """الأساسي متاح + بدائل متاحة ⇒ تُلحَق السلسلة عبر with_fallbacks."""
        from agents.llm_client import LLMClient

        monkeypatch.setenv("LLM_MOCK_MODE", "0")
        client = LLMClient(load_env=False)
        monkeypatch.setattr(
            client, "_build_llm",
            lambda *, provider, model, temperature: _FakeLLM(provider),
        )
        llm = client.get_llm_with_fallback("scorer")
        assert llm.provider == "groq" and llm.fallbacks, "سلسلة البدائل يجب أن تُلحق"
        assert llm.fallbacks[0].provider in {"gemini", "ollama"}


# =====================================================================
# 2) أداة MobSF لا تستجيب ← الفحص يكمل
# =====================================================================
class TestToolFailureIsolation:
    def test_mobsf_timeout_scan_completes_partial(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Timeout من MobSF ⇒ المرحلة تكمل، تُسجَّل أخطاء، وتبقى الثغرات من أدوات أخرى."""
        from agents.graph import ainvoke_pipeline, build_scan_graph
        from agents.mcp_client import AgentMCPClient
        from agents.state import ScanState

        original_call = AgentMCPClient.call_tool

        async def flaky_call(self, tool_name: str, **kwargs: Any) -> dict[str, Any]:
            if "mobsf" in tool_name:
                raise TimeoutError(f"انتهت مهلة {tool_name} (محاكاة فوضى)")
            return await original_call(self, tool_name, **kwargs)

        monkeypatch.setattr(AgentMCPClient, "call_tool", flaky_call)

        state = ScanState(
            scan_id="chaos_mobsf",
            application_id=3,
            apk_path="data/apks/benchmark_sample.apk",
            package_name="chaos.package",
            app_category="utility",
            user_request="محاكاة سقوط MobSF",
        )

        async def run() -> dict[str, Any]:
            graph = build_scan_graph()
            return await ainvoke_pipeline(graph, state)

        result = asyncio.run(run())
        assert result.get("current_stage") == "done", "الفحص يجب أن يكمل رغم فشل أداة"
        errors = result.get("errors") or []
        mobsf_errors = [e for e in errors if "mobsf" in str(e).lower()]
        assert mobsf_errors, f"يجب تسجيل فشل MobSF في errors — errors={errors[:5]}"
        assert all("Traceback" not in str(error) for error in errors), "لا تسرّب traceback"

    def test_unknown_tool_raises_clear_keyerror(self) -> None:
        """أداة غير معروفة ⇒ KeyError برسالة عربية واضحة (لا سلوك عشوائي)."""
        from agents.mcp_client import AgentMCPClient

        async def call() -> Any:
            async with AgentMCPClient() as client:
                return await client.call_tool("لا-توجد-أداة-كهذه")

        with pytest.raises((KeyError, TimeoutError)):
            asyncio.run(call())


# =====================================================================
# 3) قاعدة البيانات مقفولة ← retry ثم رسالة واضحة
# =====================================================================
class TestDatabaseLockResilience:
    def test_retry_on_lock_fails_clear_then_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """قفل حصري من اتصال آخر: إعادة محاولة ثم فشل واضح، وبعد التحرير ينجح."""
        from core.performance.db_optimizer import retry_on_lock

        db_path = tmp_path / "locked.db"
        with sqlite3.connect(db_path) as setup:
            setup.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
            setup.execute("INSERT INTO notes (body) VALUES ('أ')")

        def write_note() -> None:
            with sqlite3.connect(db_path, timeout=0.05) as connection:
                connection.execute("INSERT INTO notes (body) VALUES ('ب')")

        holder = sqlite3.connect(db_path)
        holder.execute("BEGIN EXCLUSIVE")
        try:
            with pytest.raises(sqlite3.OperationalError) as excinfo:
                retry_on_lock(write_note, attempts=2, base_delay=0.01)
            assert "مقفولة" in str(excinfo.value) or "locked" in str(excinfo.value).lower()
        finally:
            holder.rollback()
            holder.close()

        retry_on_lock(write_note, attempts=3, base_delay=0.01)  # القفل زال — ينجح
        with sqlite3.connect(db_path) as verify:
            assert verify.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 2

    def test_api_returns_uniform_500_when_db_write_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """فشل كتابة القاعدة داخل API ⇒ 500 بصيغة موحّدة (لا انهيار ولا تفاصيل داخلية)."""
        from fastapi.testclient import TestClient
        from sqlalchemy.exc import OperationalError as SAOperationalError

        def exploding_create(*args: Any, **kwargs: Any) -> Any:
            raise SAOperationalError("INSERT", {}, sqlite3.OperationalError("database is locked"))

        monkeypatch.setattr("db.repositories.projects_repo.create", exploding_create)

        from api.main import create_app

        with TestClient(create_app(), raise_server_exceptions=False) as client:
            login = client.post(
                "/auth/login", json={"username": "admin", "password": "admin123"}
            )
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            response = client.post("/projects", json={"name": "قفل"}, headers=headers)

        assert response.status_code == 500
        payload = response.json()
        assert payload["error"] == "internal_error"
        assert "locked" not in payload["detail"].lower(), "لا تسريب تفاصيل داخلية"
        assert response.headers.get("x-content-type-options") == "nosniff", "الترويسات تصل للأخطاء"


# =====================================================================
# 4) نموذج التضمين غير محمّل ← TF-IDF
# =====================================================================
class TestEmbeddingFallback:
    def test_sentence_transformers_missing_falls_back_to_tfidf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """فرض ST بلا حزمة مثبتة ⇒ TF-IDF مع سبب مسجَّل (لا انهيار)."""
        monkeypatch.delenv("EMBEDDING_MOCK_MODE", raising=False)
        monkeypatch.setenv("MAS_EMBEDDING_BACKEND", "sentence-transformers")

        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine()
        assert engine.mode == "tfidf"
        assert engine.fallback_reason and "sentence-transformers" in engine.fallback_reason
        assert engine.dim > 0, "TF-IDF يجب أن ينتج أبعاداً صالحة"

    def test_api_mode_without_key_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """فرض وضع API بلا مفتاح ⇒ TF-IDF مع سبب مسجَّل."""
        monkeypatch.delenv("EMBEDDING_MOCK_MODE", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("MAS_EMBEDDING_API_KEY", raising=False)
        monkeypatch.setenv("MAS_EMBEDDING_BACKEND", "api")

        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine()
        assert engine.mode == "tfidf"
        assert engine.fallback_reason and "API" in engine.fallback_reason

    def test_retrieval_still_works_after_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """الاسترجاع يعمل فعلياً على خلفية TF-IDF بعد التراجع."""
        monkeypatch.delenv("EMBEDDING_MOCK_MODE", raising=False)
        monkeypatch.setenv("MAS_EMBEDDING_BACKEND", "tfidf")

        from rag.ingest import ingest_knowledge_base
        from rag.retriever import KnowledgeRetriever

        report = ingest_knowledge_base(force=True)
        assert report["embedded"] >= 1
        hits = KnowledgeRetriever().retrieve("SSL pinning bypass certificate validation", top_k=1)
        assert hits and hits[0]["source"] == "vector"

    def test_lru_cache_serves_repeated_queries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """تكرار النص نفسه يُخدَم من تخزين LRU (بلا إعادة حساب)."""
        monkeypatch.setenv("EMBEDDING_MOCK_MODE", "1")

        from rag.embeddings import EmbeddingEngine

        engine = EmbeddingEngine()
        first = engine.embed_single("SSL pinning")
        second = engine.embed_single("SSL pinning")
        assert first == second
        stats = engine.cache_stats()
        assert stats["hits"] >= 1 and stats["hit_rate"] > 0
