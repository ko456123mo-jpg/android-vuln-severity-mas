# دليل المستخدم / User Manual — نظام تقييم خطورة ثغرات تطبيقات أندرويد

**الإصدار:** v1.0.0 · **التاريخ:** 2026-10-12 · **الترخيص:** MIT

دليل تشغيلي كامل من التثبيت إلى التقارير النهائية. موجّه إلى: الباحث، ومهندس
الأمن، ومشرف النظام، والمراجع البشري (خبير الأمن) الذي يصحّح نتائج النظام.

---

## 1) ما الذي يفعله النظام؟

يستقبل النظام ملف APK، يحلّله بأدوات ساكنة وديناميكية (jadx · MobSF · Frida ·
Objection)، يستخرج الثغرات بالذكاء الاصطناعي، يقيّم خطورتها وفق OWASP MASVS
بمعادلة منشورة وقابلة للتحقق، يمرّر النتيجة على وكيل مراجعة آلي، ثم **يعرضها على
مراجع بشري** للتصحيح، ويولّد تقريرين (فني + تنفيذي) بست صيغ. كل تصحيح بشري يغذّي
حلقة تعلّم (Few-Shot) تُحسّن الاستخلاص لاحقاً.

القيمة البحثية: كل نتيجة قابلة للتتبع إلى معادلة في الكود، وكل قرار تصميمي موثّق
في `docs/thesis/appendix_c_decision_log.md`.

---

## 2) المتطلبات

| المكوّن | الحد الأدنى | ملاحظة |
|---|---|---|
| Python | 3.11+ | 3.12 مدعوم |
| نظام التشغيل | Linux/macOS | Windows عبر WSL2 |
| RAM | 4 GB | 8 GB عند تشغيل MobSF محلياً |
| Docker | 24+ (اختياري) | لتشغيل api/ui/mobsf معاً |
| مفاتيح نماذج | اختيارية | بلا مفاتيح يعمل النظام كاملاً في **وضع Mock** |

لا يحتاج تقييم النظام إلى إنترنت إذا شُغّل بوضع Mock (`LLM_MOCK_MODE=1`,
`MCP_MOCK_MODE=1`, `EMBEDDING_MOCK_MODE=1`) — وهو الوضع المستخدم في كل اختباراتنا.

---

## 3) التثبيت من الصفر

```bash
git clone <repo-url> android-vuln-severity-mas
cd android-vuln-severity-mas

python -m venv .venv && source .venv/bin/activate
pip install -e .                # أو: make install

cp .env.example .env            # املأ المفاتيح إن توفّرت (وإلا اتركها فارغة)
make init-all                   # قاعدة البيانات + البذر + فهرسة RAG
```

`make init-all` ينفّذ ثلاثاً: إنشاء المخطط (14 جدولاً)، بذر المستخدم/الأدوات/قواعد
الخطورة/قاعدة المعرفة، وفهرسة قاعدة المعرفة في متجهات (TF-IDF احتياطاً عند غياب
نموذج التضمين).

تحقّق سريع:

```bash
python -c "import sqlite3;print(sorted(r[0] for r in sqlite3.connect('data/app.db').execute(\"select name from sqlite_master where type='table'\")))"
python scripts/final_checklist.py --skip-tests   # 12 بنداً
```

---

## 4) الإعداد — متغيرات البيئة

انسخ `.env.example` إلى `.env`. القيم الفارغة مقبولة في التطوير.

| المتغيّر | الافتراضي | الأثر |
|---|---|---|
| `LLM_MOCK_MODE` | `0` | `1` = نماذج وهمية بلا شبكة (اختبارات/عروض) |
| `MCP_MOCK_MODE` | `0` | `1` = أدوات فحص وهمية (`mcp_servers/mocks`) |
| `EMBEDDING_MOCK_MODE` | `0` | `1` = متجهات ثابتة البذرة |
| `MAS_EMBEDDING_BACKEND` | (تلقائي) | `sentence-transformers` / `api` / `tfidf` |
| `GROQ_API_KEY` · `GOOGLE_API_KEY` · `ANTHROPIC_API_KEY` | — | مزوّدو النماذج (بالترتيب، مع سلسلة بدائل) |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | المزوّد المحلي |
| `MOBSF_URL` · `MOBSF_API_KEY` | `http://localhost:8000` | خدمة MobSF |
| `DATABASE_PATH` | `./data/app.db` | قاعدة SQLite |
| `MAS_SECRET_KEY` | مفتاح تطويري | **إلزامي في الإنتاج** (≥ 32 حرفاً) |
| `MAS_ENV` | `development` | `production` ⇒ تشديد الأسرار + HSTS |
| `MAS_ADMIN_PASSWORD` | `admin123` | **غيّرها في أي بيئة مشتركة** |
| `MAS_CORS_ORIGINS` | `*` | قائمة أصول مفصولة بفواصل |
| `MAS_RATE_LIMIT_ENABLED` / `MAS_RATE_LIMIT_PER_MINUTE` | `1` / `60` | حدّ المعدل |
| `MAS_HSTS` | `0` | فرض HSTS بلا `MAS_ENV=production` |

قبل الإنتاج راجع `docs/security_hardening.md §10` (قائمة تشغيل آمن كاملة).

---

## 5) التشغيل

### 5.1 محلياً

```bash
make run-api      # FastAPI على http://localhost:8000  (Swagger: /docs)
make run-ui       # Streamlit على http://localhost:8501
```

### 5.2 عبر Docker (api + ui + mobsf)

```bash
make docker-build     # بناء صور api و ui (multi-stage، مستخدم غير جذري)
make docker-up        # تشغيل الخدمات في الخلفية
make docker-ps        # الحالة + فحوص الصحة
make docker-logs      # متابعة السجلات
make docker-shell     # shell داخل حاوية api
make docker-down      # إيقاف
```

الخدمات: `api` (8000) · `ui` (8501) · `mobsf` (شبكة داخلية فقط — لا منفذ عام) ·
`ollama` (ملف تعريف اختياري `--profile ollama`). البيانات في `./data` والنتائج في
`./results` (مجلّدان مُثبَّتان كأحجام).

### 5.3 الدخول الأول

المستخدم المزروع: `admin / admin123`. الأدوار:

| الدور | يستطيع |
|---|---|
| `admin` | كل شيء: المستخدمون، لوحة المعلومات، كل المشاريع، المراجعة |
| `analyst` | مشاريعه فقط: إنشاء/رفع/فحص/تقارير/تصحيح تقييمات مشاريعه |
| `reviewer` | حلقة المراجعة (`/reviews`, `/assessments`) عبر المشاريع + تصحيح النتائج |

> **مهم:** `admin123` افتراضية للتطوير. في الإنتاج اضبط `MAS_ADMIN_PASSWORD`
> بمتغير البيئة، وإلا **يرفض النظام الإقلاع** (`docs/security_hardening.md §6`).

---

## 6) سير عمل كامل — من APK إلى التقرير

### الخطوة 1 — إنشاء مشروع
الواجهة: صفحة **المشاريع والتطبيقات** → «مشروع جديد». أو:

```bash
curl -X POST http://localhost:8000/projects -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"تقييم بنكي 2026"}'
```

### الخطوة 2 — رفع APK
صفحة **رفع وفحص** → اختر المشروع والملف. النظام يتحقق من الامتداد والحجم، يحسب
SHA-256، ويخزّن الملف باسم البصمة (`data/apks/<sha256>.apk`). رفع نفس الملف في
**نفس المشروع** يعيد السجل القائم (`deduplicated: true`)، وفي **مشروع آخر** يعيد
409 بلا أي بيانات عن السجل القائم (منع تسريب بالبصمة).

### الخطوة 3 — بدء الفحص
اختر `scan_type`:

| النوع | ما ينفّذه |
|---|---|
| `static` | jadx → MobSF |
| `dynamic` | Frida → Objection |
| `comprehensive` | كليهما (الافتراضي) |

```bash
curl -X POST http://localhost:8000/scans/start -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"application_id": 1, "scan_type": "comprehensive"}'
# → 202 {"scan_id": 4, "status": "pending"}
```

الفحص يعمل **كمهمة خلفية**: الـ API يرد فوراً، والتقدّم يُتابَع بالاستقصاء.

### الخطوة 4 — متابعة التقدّم
صفحة **رفع وفحص** تعرض النسبة والوكيل/الأداة الحالية تلقائياً. أو:

```bash
watch -n2 "curl -s http://localhost:8000/scans/4/status -H \"Authorization: Bearer $TOKEN\""
```

الحالات النهائية: `success` (بلا أخطاء) · `partial` (اكتمل مع أخطاء أدوات مسجَّلة)
· `failed` (لم تُنتج ثغرات ولا اكتمل). فشل أداة واحدة لا يُسقط الفحص.

### الخطوة 5 — قراءة النتائج
- صفحة **الثغرات**: قائمة/بحث مع الفئة والخطورة.
- صفحة **تفاصيل التقييم**: المعادلة كاملة بمكوّناتها (`base_score`, `context_score`,
  `evidence_score`, `confidence_factor`, `final_score`) + الأدلة لكل أداة + التصحيحات.

```bash
curl -s "http://localhost:8000/scans/4/vulnerabilities" -H "Authorization: Bearer $TOKEN" | head -40
```

### الخطوة 6 — المراجعة البشرية (HITL)
صفحة **قائمة المراجعة**: تظهر التقييمات الموسومة `pending` (ترتيبها بدرجة الخطورة
تنازلياً). راجع الأدلة ثم:

| الحقل | المدى | ملاحظات |
|---|---|---|
| `corrected_severity` | Critical/High/Medium/Low | فئة الخبير |
| `corrected_score` | 0–10 | درجة الخبير (**إلزامية**) |
| `reason` | ≥ 3 أحرف | سبب التصحيح (يُدرَج في التقرير) |

```bash
curl -X POST http://localhost:8000/reviews/12/correct -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"corrected_severity":"Critical","corrected_score":9.2,"reason":"تشفير ضعيف على بيانات اعتماد"}'
```

**ثابت لا يتغيّر:** التصحيح يضبط `severity = corrected_severity` و
`review_status = approved` ويولّد `feedback_example` تلقائياً، **ولا يمسّ
`final_score`** (يبقى مخرج المعادلة كما هو للمقارنة والقياس).

### الخطوة 7 — التقارير
صفحة **التقارير** → «توليد». الملفات الستة في `data/reports/<scan_id>/`:

| الصيغة | الجمهور |
|---|---|
| `technical_md` · `technical_html` · `technical_pdf` | مهندس الأمن (إنجليزي + أدلة) |
| `executive_md` · `executive_html` · `executive_pdf` | الإدارة (عربي، بلا تفاصيل تقنية) |

```bash
curl -X POST http://localhost:8000/reports/4/generate -H "Authorization: Bearer $TOKEN"
curl -s -o /tmp/tech.pdf "http://localhost:8000/reports/4/download/technical_pdf" \
  -H "Authorization: Bearer $TOKEN" && file /tmp/tech.pdf
```

### الخطوة 8 — لوحة المعلومات والتقييم
- صفحة **لوحة المعلومات** (admin): مؤشرات كلية، توزيع الخطورة، آخر الفحوص، الاتجاهات.
- صفحة **التقييم** (admin/reviewer): نتائج تجربة الموثوقية (κ, AC1, P/R/F1) مع القيود
  والاستنتاجات — من `results/summary.json` فقط، ولا تُعرض أرقام قبل وجود الحقيقة
  المرجعية (`evaluation/ground_truth.py` بحالة `filled: false`).

---

## 7) سطر الأوامر — الواجهات المفيدة

| الأمر | الوظيفة |
|---|---|
| `make help` | قائمة كل الأوامر |
| `make init-all` | تهيئة كاملة |
| `make test` | كل الاختبارات (Mock، بلا إنترنت) |
| `make security-check` | فحص التصليب الأمني |
| `make benchmark` | قياس الأداء → `results/benchmark.md` |
| `make load-test` | اختبار الحمل → `results/load_test.md` |
| `make optimize-db` | `PRAGMA optimize` + `ANALYZE` |
| `make diagrams` | رسوم Mermaid → SVG |
| `make release` | أرشيف الإصدار + بصمة SHA-256 |
| `make final-check` | الفحص النهائي الشامل (12 بنداً) |

سكربتات مباشرة: `scripts/run_api.py` · `scripts/run_ui.py` · `scripts/seed_all.py` ·
`scripts/test_llm_connection.py` · `scripts/ingest_knowledge.py` ·
`scripts/generate_report.py` · `scripts/benchmark.py` · `scripts/load_test.py` ·
`scripts/render_diagrams.py` · `scripts/final_checklist.py` · `scripts/make_release.py`.

---

## 8) الأعطال الشائعة وحلولها

| العرض | السبب المرجّح | الحل |
|---|---|---|
| `لا مزوّد نماذج متاح للوكيل … LLM_MOCK_MODE=1` | لا مفاتيح ولا Ollama | اضبط مفتاحاً في `.env` أو شغّل `LLM_MOCK_MODE=1` |
| 401 على كل طلب | توكن غائب/منتهٍ (60 دقيقة) | أعد الدخول: `POST /auth/login` |
| 403 «لا تملك صلاحية الوصول» | المورد لمشروع مستخدم آخر | اطلب من المالك مشاركته، أو استخدم حساب admin |
| 429 «تجاوز حدّ الطلبات» | أكثر من 60 طلباً/دقيقة | انتظر حسب `Retry-After` أو ارفع `MAS_RATE_LIMIT_PER_MINUTE` |
| 409 عند رفع APK | بصمة الملف مسجَّلة (مشروع آخر) | ارفع نسخة مختلفة أو استخدم السجل القائم في مشروعه |
| الفحص `partial` | أداة فشلت (MobSF/Frida) | راجع `scans.error_message` وسجلات الأدوات؛ النتائج الأخرى سليمة |
| «قاعدة البيانات مقفولة» | كتابة متزامنة | يُعاد المحاولة آلياً؛ عند التكرار شغّل `make optimize-db` وتأكد من WAL |
| الواجهة لا تجد البيانات | API غير مشغّل | `make run-api` أولاً (الواجهة تقرأ الـ API) |
| PDF فارغ/غريب | خطوط عربية ناقصة | ثبّت خطوط Noto على النظام (مضمّنة في صورة Docker) |

---

## 9) النسخ الاحتياطي والترقية

- **احتياط:** أوقف الخدمة وانسخ `data/app.db` (القاعدة)، `data/apks/` (الملفات)،
  `data/reports/` (التقارير المولّدة)، و`results/` (نتائج القياس).
- **استعادة:** أعِد الملفات ثم `make optimize-db` والتحقق بـ `GET /health`.
- **ترقية:** `git pull && pip install -e . && make init-all && make test` — المخطط
  إضافي/متوافق ولا يحذف جداول؛ راجع `CHANGELOG.md` لأي تغيير سلوكي.

---

## 10) الخصوصية والأمن للمستخدم

- ملفات APK تُخزَّن محلياً في `data/apks/` — لا تُرسل لأي طرف ثالث، لكن **نصوص
  المقتطفات** المرسلة لمزوّد النماذج تخرج من جهتك عند استخدام مزوّد سحابي؛
  للسرّية الكاملة شغّل Ollama محلياً (`--profile ollama`).
- مخرجات الأدوات تمرّ عبر درع حقن البرومبت قبل أي نموذج
  (`docs/security_guardrails.md`)، وتُسجَّل المحاولات في `agent_logs`.
- كل طلب موثّق بتوكن ويخضع لتفويض الملكية وحدّ المعدل
  (`docs/security_hardening.md`).

---

## 11) الاستشهاد والترخيص

الاستشهاد الجاهز في `CITATION.cff` (صيغة CFF 1.2.0):

```bibtex
@software{android_vuln_severity_mas_2026,
  title  = {Multi-Agent System for Android Vulnerability Severity Assessment},
  year   = {2026},
  version= {1.0.0},
  license= {MIT},
}
```

الترخيص: **MIT** (`LICENSE`). ملاحظة تشغيلية: MobSF وjadx وFrida تخضع لتراخيصها
الخاصة عند استخدامها فعلياً (لا تُحزَّم مع النظام).

---

## 12) عن المطوّر / About the Developer

| البند | القيمة |
|---|---|
| الاسم (عربي) | **المهندس محمد منير** |
| الاسم (إنجليزي) | **Engineer Mohammed Moneer** |
| البريد الإلكتروني | [moh123mon456@gmail.com](mailto:moh123mon456@gmail.com) |
| GitHub | [@ko456123mo-jpg](https://github.com/ko456123mo-jpg) |
| المستودع | [android-vuln-severity-mas](https://github.com/ko456123mo-jpg/android-vuln-severity-mas) |

**حقوق النشر:** © 2026 Engineer Mohammed Moneer — رخصة MIT.
لطلبات الدعم أو الإبلاغ عن مشكلة: افتح Issue في المستودع أو راسل البريد أعلاه.
