"""حزمة RAG — التوليد المتجهي والاسترجاع (المرحلة 7).

المكونات:
    • EmbeddingEngine   — محرك التوليد المتجهي (4 أوضاع عمل)
    • SqliteVecStore    — مخزن المتجهات (sqlite-vec مع بديل Python كامل)
    • ingest_knowledge_base — تحميل knowledge_base إلى المخزن المتجهي
    • KnowledgeRetriever — الاسترجاع + توسيع البرومبت
"""
from rag.embeddings import EmbeddingEngine
from rag.ingest import ingest_knowledge_base
from rag.retriever import KnowledgeRetriever, build_context_prompt
from rag.store_sqlitevec import SqliteVecStore

__all__ = [
    "EmbeddingEngine",
    "SqliteVecStore",
    "ingest_knowledge_base",
    "KnowledgeRetriever",
    "build_context_prompt",
]
