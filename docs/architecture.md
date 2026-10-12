# 🏛️ المعمارية / System Architecture

## الطبقات الخمس / Five Layers

```
┌────────────────────────────────────────────────────────────┐
│ L5 — العرض / Presentation: Streamlit UI (صفحات متعددة)      │
├────────────────────────────────────────────────────────────┤
│ L4 — الخدمات / Services: FastAPI + وركرات خلفية            │
├────────────────────────────────────────────────────────────┤
│ L3 — التنسيق / Orchestration (الوكلاء الخمسة + LangGraph): │
│      Orchestrator → Extractor → Scorer → Reviewer → Report │
│           ↑ Hallucination Guard + Human-in-the-Loop        │
├────────────────────────────────────────────────────────────┤
│ L2 — الأدوات / MCP Tool Servers:                           │
│      jadx (static) · mobsf (static) · frida · objection    │
│      (dynamic evidence + proofs-of-concept)                │
├────────────────────────────────────────────────────────────┤
│ L1 — البيانات / Data: SQLite (WAL, 14 جدولاً) + artifacts  │
│      + knowledge_base (RAG/embeddings)                     │
└────────────────────────────────────────────────────────────┘
```

## المبادئ التصميمية / Design Principles

1. **محتوى APK غير موثوق** — كل ما يخرج من الأدوات يُعقَّم عند حدود MCP قبل أي LLM.
2. **قابلية إعادة الإنتاج** — `assessments.rule_version` يربط كل تقييم بنسخة قاعدة محددة.
3. **الأدلة أولاً** — الحقيقة تُشتق من مخرجات الأدوات (artifact refs)، وLLM يفسّر فحسب.
4. **تدهور رشيق** — فشل أداة ديناميكية لا يوقف الفحص (scan `partial` + خفض evidence_score).
5. **Hybrid LLM بالتخصص** — نماذج محلية رخيصة للاستخراج، ونموذج قوي (Groq 70B) للتقييم والمراجعة، مع Fallback: Groq ← Gemini ← Ollama.

## تدفق فحص واحد / Per-scan data flow

```
APK (sha256) → Orchestrator يوزع أوامر MCP
    → findings خام في artifacts/<scan_id>/
    → Extractor يوحّد ويدمج (dedup_fingerprint)
    → Scorer: 0.6·base + 0.2·context + 0.2·evidence (+ confidence)
    → Reviewer: اتساق + Hallucination Guard
        ├─ confidence < 0.75 أو قرب حد الفئة → Human Review → corrections
        └─ سليم → assessments (review_status=approved)
    → Report: MD/HTML/PDF موثق بالأدلة
    → corrections يتحول إلى feedback_examples تُحقن في برومبت Scorer لاحقاً
```

## حالة المراحل / Phase status

| المرحلة | الوصف | الحالة |
|---------|-------|--------|
| 1 | التأسيس، DB (14 جدولاً)، البذر، llm_client | ✅ مكتملة |
| 2 | خوادم MCP الأربعة (+ Mock Mode، 38 اختبار وحدة ✅) | ✅ مكتملة |
| 3 | نواة الوكلاء: BaseAgent + Orchestrator + Extractor + LangGraph (69 اختبار ✅) | ✅ مكتملة |
| 4 | محرك التقييم (0.6/0.2/0.2) + Scorer/Reviewer + Guardrails الثلاثة (155 اختبار ✅) | ✅ مكتملة |
| 5 | Reporter (EN/AR × MD/HTML/PDF) + حلقة HITL + Feedback Loop + API (178 اختبار ✅) | ✅ مكتملة |
| 6 | API كاملة (`/auth` JWT · projects · applications · scans · findings · assessments · dashboard) + Streamlit (8 صفحات، i18n/RTL، AppTest) (220 اختبار ✅) | ✅ مكتملة |
| 7 | RAG + تقييم Kappa/AC1 + التصليب البحثي | ⬜ قادمة |
