#!/usr/bin/env python
"""اختبار الاتصال بمزوّدي LLM — Ollama / Groq / Gemini.

يعرض جدول نتائج ولا يفشل أبداً (ok=False مع سبب الخطأ بدلاً من التعطّل)،
ثم يعرض أيضاً التوزيع المعتمد لكل وكيل من settings.yaml.

Usage / الاستخدام:
    python scripts/test_llm_connection.py
"""
import sys
from pathlib import Path

# السماح بالاستيراد من جذر المشروع عند التشغيل المباشر
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agents.llm_client import LLMClient, SUPPORTED_PROVIDERS  # noqa: E402

AGENT_ORDER = ("orchestrator", "extractor", "scorer", "reviewer", "report")


def main() -> int:
    print("=" * 66)
    print("🔌 اختبار اتصال مزوّدي LLM / LLM providers connectivity test")
    print("=" * 66)

    client = LLMClient()

    # 1) التوزيع المعتمد لكل وكيل / Agent → model mapping
    print("\n📋 التوزيع المعتمد للوكلاء / Agent → model mapping:")
    for agent in AGENT_ORDER:
        try:
            cfg = client.get_agent_config(agent)
            print(f"  • {agent:<13} → {cfg['model']:<28} [{cfg['provider']}]")
        except KeyError as exc:
            print(f"  • {agent:<13} → ✗ {exc}")
    print(f"  • fallback_chain → {client.llm_cfg.get('fallback_chain', [])}")

    # 2) اختبار فعلي لكل مزوّد / Live test per provider
    print(f"\n🧪 اختبار الاتصال الفعلي ({' / '.join(SUPPORTED_PROVIDERS)}):")
    print(f"  {'provider':<8} {'model':<28} {'ok':<4} {'latency':<10} error")
    print("  " + "-" * 62)
    results = []
    for provider in SUPPORTED_PROVIDERS:
        rep = client.test_connection(provider)
        results.append(rep)
        ok = "✅" if rep["ok"] else "❌"
        latency = f"{rep['latency_ms']}ms" if rep["latency_ms"] is not None else "—"
        error = (rep["error"] or "")[:48]
        print(f"  {rep['provider']:<8} {rep['model']:<28} {ok:<4} {latency:<10} {error}")

    # 3) الخلاصة / Summary
    ok_any = any(r["ok"] for r in results)
    print("-" * 66)
    if ok_any:
        print("✅ مزوّد واحد على الأقل متاح — يمكن للنظام العمل عبر الـ Fallback.")
        return 0
    print("⚠️  لا يوجد أي مزوّد متاح حالياً في هذه البيئة.")
    print("   - Ollama: شغّل `ollama serve` وثبّت حزمة langchain-ollama.")
    print("   - Groq/Gemini: عيّن المفاتيح في .env (GROQ_API_KEY / GOOGLE_API_KEY).")
    return 0  # ليس خطأً في الكود — مجرد غياب خدمات في بيئة التطوير


if __name__ == "__main__":
    raise SystemExit(main())
