# 🛡️ Android Vulnerability Severity MAS

**نظام متعدد الوكلاء لتقييم خطورة الثغرات في تطبيقات أندرويد**
*Multi-agent system for Android vulnerability severity assessment — OWASP MASVS aligned*

يدمج أربع أدوات أمنية (**JADX · MobSF · Frida · Objection**) عبر بروتوكول **MCP**، وتنسّق بينها خمسة وكلاء ذكاء اصطناعي (**Orchestrator, Extractor, Scorer, Reviewer, Report**) لتقييم خطورة الثغرات بمنطق موزون، مع حلقة تغذية راجعة بشرية (HITL) وتجربة قياس إحصائية (Weighted Cohen's Kappa + Gwet's AC1).

> 📌 **الحالة:** المرحلة 6 مكتملة — قاعدة البيانات ✓ · خوادم MCP ✓ · نواة الوكلاء (Orchestrator→Extractor→Scorer→Reviewer→Reporter) ✓ · محرك التقييم + الحمايات ✓ · حلقة HITL ✓ · **FastAPI كاملة (42 نقطة نهاية + JWT) + واجهة Streamlit (8 صفحات عربي/إنجليزي RTL)** ✓ — 220 اختباراً ناجحاً.
> للتصميم الكامل راجع `docs/01_design_and_plan.md`، ولتفاصيل الوكلاء `docs/agents_design.md`.

---

## ⚙️ التثبيت / Installation

```bash
# 1) بيئة افتراضية
python -m venv .venv && source .venv/bin/activate

# 2) الاعتماديات
pip install -e .            # أو: pip install -r requirements إن وُجد

# 3) متغيرات البيئة
cp .env.example .env        # ثم عيّن GROQ_API_KEY / GOOGLE_API_KEY
```

## 🗄️ تهيئة القاعدة والبذر / Database setup

```bash
make init-db        # ينشئ data/app.db (WAL) مع الجداول الـ14 من db/schema.sql
make seed           # admin + الأدوات الخمس + severity_rules v1.0 + أنماط MASVS الثمانية
```

بيانات الدخول الافتراضية: `admin / admin123` (⚠️ غيّرها فوراً في الإنتاج).

## 🧪 اختبار مزوّدي LLM / LLM connectivity

```bash
make test-llm       # يختبر Ollama وGroq وGemini ويعرض التوزيع المعتمد لكل وكيل
```

| الوكيل | النموذج | المزوّد |
|---------|---------|---------|
| Orchestrator | `llama3.2:3b` | Ollama |
| Extractor | `qwen2.5:14b` | Ollama |
| Scorer | `llama-3.3-70b-versatile` | Groq |
| Reviewer | `llama-3.3-70b-versatile` | Groq |
| Report | `qwen2.5:14b` | Ollama |

سلسلة البدائل: **Groq ← Gemini ← Ollama**.

## 🚀 التشغيل (المراحل القادمة) / Run

```bash
make run-api        # FastAPI — 42 نقطة نهاية (0.0.0.0:8000)
make run-ui         # Streamlit — 8 صفحات (0.0.0.0:8501)
make mobsf-up       # MobSF عبر Docker
make test           # pytest
make clean          # حذف القاعدة والكاش
```

## 🧮 منطق التقييم / Severity logic

```
final_score = 0.6·base_score + 0.2·context_score + 0.2·evidence_score
severity    = Critical ≥9.0 | High 7.0–8.9 | Medium 4.0–6.9 | Low <4.0
confidence  < 0.75  → تصعيد إلزامي للمراجعة البشرية (HITL)
```

## 📂 البنية / Structure

```
db/         schema.sql · connection.py · models.py (14 tables) · seed.py · repositories/
agents/     llm_client.py (Hybrid LLM + fallback) · prompts/
mcp_servers/  jadx · mobsf · frida · objection        (المرحلة 2)
core/       scoring · guardrails · correlation        (المراحل 4–5)
api/        FastAPI routers + JWT (42 endpoints)       (المرحلة 6)
ui/         Streamlit — 8 صفحات + مكوّنات              (المرحلة 6)
evaluation/ Kappa/AC1 experiment                      (المرحلة 7)
docs/       architecture · db_schema · security_guardrails
```
