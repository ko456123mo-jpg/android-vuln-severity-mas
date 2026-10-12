"""فهرسة قاعدة المعرفة في المخزن المتجهي (المرحلة 7).

    EMBEDDING_MOCK_MODE=1 python scripts/ingest_knowledge.py
    python scripts/ingest_knowledge.py --force          # إعادة فهرسة كاملة
    python scripts/ingest_knowledge.py --status         # عرض حالة المخزن فقط
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.embeddings import EmbeddingEngine  # noqa: E402
from rag.ingest import ingest_knowledge_base  # noqa: E402
from rag.store_sqlitevec import SqliteVecStore  # noqa: E402


def main() -> None:
    """نقطة الدخول: فهرسة أو عرض حالة."""
    parser = argparse.ArgumentParser(description="فهرسة knowledge_base متجهياً")
    parser.add_argument("--force", action="store_true", help="إعادة فهرسة كل الصفوف")
    parser.add_argument("--status", action="store_true", help="عرض الحالة بلا كتابة")
    args = parser.parse_args()

    engine = EmbeddingEngine()
    store = SqliteVecStore()
    print(f"◉ محرك التوليد: {engine.mode} | المخزن: {store.backend}")

    if args.status:
        print(f"  متجهات مخزنة: {store.count()} | البعد الحالي: {store.existing_dim()}")
        return

    summary = ingest_knowledge_base(force=args.force, engine=engine, store=store)
    print(f"✅ اكتملت الفهرسة: {summary['embedded']} مُفهرس، {summary['skipped']} متخطّى")
    print(f"  store_total={summary['store_total']} | dim={summary['dim']} | "
          f"backend={summary['backend']} | recreated={summary['recreated']}")


if __name__ == "__main__":
    main()
