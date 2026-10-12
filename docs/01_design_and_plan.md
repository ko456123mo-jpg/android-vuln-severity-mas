# وثيقة التصميم والتخطيط
## نظام متعدد الوكلاء لتقييم خطورة ثغرات تطبيقات أندرويد (OWASP MASVS)

- **الاسم المقترح للمشروع:** `android-vuln-severity-mas`
- **الحالة:** مرحلة التخطيط فقط — لم يبدأ أي تنفيذ.
- **التاريخ:** 2026-10-12

---

## 1. تحليل المتطلبات

### 1.1 قرارات تصميمية محورية
1. **محتوى الـ APK غير موثوق**: كل مخرجات JADX/MobSF (أسماء أصناف، strings، Manifest) تُعامل كبيانات معادية محتملة. الحماية من Prompt Injection توضع عند حدود MCP قبل أن تصل أي بيانات إلى LLM.
2. **فصل المسؤوليات**: FastAPI كطبقة خدمات، Streamlit كواجهة، خوادم MCP معزولة لكل أداة. هذا يمنع اقتران الواجهة بدورة حياة الفحوص الطويلة.
3. **قابلية إعادة الإنتاج**: قواعد التقييم مُصدَّرة (versioned) في `severity_rules`، وكل `assessment` يخزن `rule_version`. بدون ذلك تصبح تجربة Kappa/AC1 غير قابلة للتكرار.
4. **الأدلة أولاً (Evidence-first)**: `evidence_score` يكافئ التأكيد الديناميكي (Frida/Objection PoC) فوق الاشتباه الساكن، ويكافئ تأكيد أكثر من أداة لنفس الثغرة (correlation).
5. **Confidence Factor للتوجيه لا للتشويه**: يُستخدم أساساً لتوجيه الحالات منخفضة الثقة للمراجعة البشرية (واختيارياً لتعديل طفيف ±10%)، حتى لا يصبح مصدر تحيز صامت.
6. **Dedup قبل التقييم**: بصمة (fingerprint) لكل finding تمنع عدّ نفس الثغرة من 4 أدوات كأربع ثغرات.

### 1.2 تحليل قاعدة البيانات (14 جدولاً)
| # | الجدول | الغرض | أعمدة مفتاحية | العلاقات |
|---|--------|-------|----------------|----------|
| 1 | users | المستخدمون والأدوار | id, username, password_hash, role(admin/analyst/reviewer) | ← projects, corrections |
| 2 | projects | تجميع تنظيمي للتطبيقات | id, name, owner_id | → applications |
| 3 | applications | بيانات الـ APK | id, project_id, package_name, version, sha256, file_path | → app_context, scans, vulnerabilities |
| 4 | app_context | السياق التجاري (مدخل context_score) | app_id (1:1), data_sensitivity, industry, user_base_size, internet_facing, business_criticality | → applications |
| 5 | tools | سجل أدوات MCP | name(jadx/mobsf/frida/objection), version, mcp_endpoint, capabilities(json), enabled | → findings, scans |
| 6 | scans | جلسات الفحص | id, app_id, status, tools_used(json), rule_version, started_at/finished_at, error | → findings, agent_logs |
| 7 | vulnerabilities | الثغرة الموحدة (بعد الدمج) | id, app_id, cwe_id, masvs_category, dedup_fingerprint(unique), status | ← findings, → assessments |
| 8 | vulnerability_findings | الأدلة الخام لكل أداة | vulnerability_id, scan_id, tool, location, evidence_type(static/dynamic), artifact_ref | → vulnerabilities |
| 9 | severity_rules | قواعد التقييم المُصدَّرة | version, weights(json), context_params(json), thresholds(json), active | → assessments |
| 10 | assessments | نتائج التقييم | base_score, context_score, evidence_score, confidence_factor, final_score, severity, rationale, rule_version | ← corrections |
| 11 | corrections | التصحيحات البشرية (HITL) | assessment_id, reviewer_id, original_severity, corrected_severity, reason | → feedback_examples |
| 12 | feedback_examples | أمثلة few-shot المستخلصة من التصحيحات | correction_id, example_type, prompt_payload(json), embedding, active | — |
| 13 | agent_logs | تدقيق شامل | scan_id, agent_name, action, llm_model, tokens_in/out, latency_ms, status, error | → scans |
| 14 | knowledge_base | معرفة RAG (MASVS/CWE) | source, ref_id, title, content, embedding(blob), version | — |

ملاحظات: تفعيل WAL + `PRAGMA foreign_keys=ON` + فهارس على (app_id, scan_id, dedup_fingerprint). تخزين المتجهات عبر `sqlite-vec`.

### 1.3 الوكلاء الخمسة — التدفق
```
Orchestrator ──(MCP tools: JADX/MobSF/Frida/Objection)──► Raw Artifacts
     │                                                        │
     ▼                                                        ▼
Extractor (توحيد + dedup + CWE/MASVS mapping عبر RAG) ──► vulnerabilities + findings
     ▼
Scorer (base 0.6 + context 0.2 + evidence 0.2 + confidence) ──► assessments
     ▼
Reviewer (اتساق + Hallucination Guard + قرار تصعيد) ── yes ──► Human Review Queue
     │ no                                                     │ (corrections → feedback_examples)
     ▼◄──────────────── feedback أمثلة ────────────────────────┘
Report Agent ──► تقرير MD/HTML/PDF
```

### 1.4 منطق التقييم المقترح (قابل للضبط عبر severity_rules)
```
final_score = 0.6·base + 0.2·context + 0.2·evidence        (0–10)
severity    = Critical≥9.0 | High 7–8.9 | Medium 4–6.9 | Low 0.1–3.9
confidence c ∈ [0.5–1.0]  →  توجيه للمراجعة البشرية إذا c<τ (مثلاً 0.75)
                             أو قرب حد الفئة (±0.5) أو Critical بثقة <0.9
```
- **base_score**: من متجه CVSS (يحسب برمجياً، وLLM يقترح المقاييس فقط ثم يُتحقق منه) + تصنيف الأداة + مستوى MASVS.
- **context_score**: قواعد حسابية (لا LLM) من app_context: حساسية البيانات 40%، قاعدة المستخدمين 20%، انكشاف الإنترنت 20%، الأهمية التجارية 20%.
- **evidence_score**: أداة واحدة=4، أداتان=7، ثلاث+=9؛ إثبات ديناميكي (Frida PoC) يرفع إلى 10؛ نمط ساكن بدون مسار كود يُخفض.
- **confidence**: اتساق تقييمات الأدوات + صحة الاستشهادات + نجاح التحقق من أول محاولة.

### 1.5 الحمايات الثلاث — مواضع التطبيق
| الحماية | الموقع | الآلية |
|---------|--------|--------|
| Prompt Injection Protection | عند حدود MCP (قبل LLM) | تعقيم المخرجات، عزلها بوسوم XML، canary tokens، حد أقصى للطول، منع تنفيذ أي تعليمات مستخرجة |
| Output Validation | بعد كل استدعاء LLM | نماذج Pydantic v2 صارمة + حلقة إصلاح (retry-with-error) + Structured Outputs |
| Hallucination Guard | داخل Reviewer + Scorer | خزانة مغلقة لمعرفات CWE/MASVS من knowledge_base، إلزام استشهاد (file:line أو artifact_ref)، كشف التناقض |

### 1.6 تصميم التجربة الإحصائية
- العينة: ~20–25 تطبيقاً (DIVA, InsecureBankv2, UnCrackable L1 + تطبيقات حقيقية)، خبيران أو ثلاثة يقيّمون الخطورة على 5 فئات ترتيبية.
- **Weighted Cohen's Kappa** (أوزان تربيعية) — يعاقب الخلافات الكبيرة بين الفئات المجاورة.
- **Gwet's AC1** — ضروري لأن التوزع سيكون منحازاً (أغلب الثغرات Medium/High) وهنا يحدث Kappa Paradox؛ AC1 مستقر أمامه.
- تجربة A/B: النظام بدون feedback_examples مقابل معها، لقياس أثر حلقة التغذية الراجعة.
- فواصل ثقة 95% عبر Bootstrap (10k إعادة معاينة).

---

## 2. شجرة الملفات

```
android-vuln-severity-mas/
├── README.md                        # نظرة عامة + التثبيت + التشغيل السريع
├── pyproject.toml                   # الحزم والاعتماديات (uv/Poetry)
├── .env.example                     # مفاتيح LLM، مسارات الأدوات، الإعدادات
├── .gitignore
├── Makefile                         # init-db, seed, run-api, run-ui, test, mcp-servers
├── docker-compose.yml               # MobSF (Docker) + خدمات مساعدة
│
├── config/
│   ├── settings.yaml                # النموذج، الحرارة، المهلات، المسارات
│   ├── scoring.yaml                 # أوزان 0.6/0.2/0.2، عتبات الثقة والفئات
│   └── tools.yaml                   # تعريف خوادم MCP الأربعة وقدراتها
│
├── data/                            # (gitignored)
│   ├── app.db                       # SQLite بوضع WAL
│   ├── apks/                        # APKs باسم SHA256
│   ├── artifacts/<scan_id>/         # مخرجات الأدوات الخام لكل فحص
│   └── reports/
│
├── db/
│   ├── schema.sql                   # DDL للجداول الـ14 (مرجع بشري)
│   ├── connection.py                # محرك SQLAlchemy + WAL + PRAGMAs
│   ├── models.py                    # ORM للجداول الـ14
│   ├── migrations/                  # Alembic
│   ├── repositories/                # CRUD منظم (projects/apps/scans/findings/
│   │                                #   assessments/feedback/logs)
│   └── seed.py                      # severity_rules + tools + admin
│
├── mcp_servers/
│   ├── common/
│   │   ├── base_server.py           # FastMCP: تسجيل الأدوات وأخطاء موحدة
│   │   ├── process_runner.py        # تشغيل CLI بمهلات وإلغاء آمن
│   │   ├── artifact_store.py        # حفظ مخرجات الأدوات وإرجاع مراجع بدل النص الكامل
│   │   └── schemas.py               # عقود Pydantic لأدوات MCP
│   ├── jadx_server/                 # decompile, get_manifest, search_code, get_class, list_permissions
│   │   ├── server.py
│   │   └── jadx_wrapper.py
│   ├── mobsf_server/                # upload, start_scan, get_report, get_findings (REST)
│   │   ├── server.py
│   │   └── mobsf_client.py
│   ├── frida_server/                # spawn_app, run_hook, capture_crypto, capture_network
│   │   ├── server.py
│   │   ├── session_manager.py       # إدارة الجهاز/الجلسات
│   │   └── scripts/                 # سكربتات JS جاهزة (crypto trace, ssl-unpinning...)
│   └── objection_server/            # explore_storage, dump_keystore, bypass_pinning, root_bypass
│       ├── server.py
│       └── objection_wrapper.py
│
├── agents/
│   ├── base_agent.py                # LLM call + logging + tokens/cost + retry
│   ├── llm_client.py                # تجريد موحد (Claude/OpenAI/محلي) + Structured Output
│   ├── orchestrator.py              # تخطيط الفحص وإرسال أوامر MCP وإدارة الحالة
│   ├── extractor.py                 # توحيد المخرجات + dedup + ربط CWE/MASVS
│   ├── scorer.py                    # الحساب الموزون + الثقة + فئة الخطورة
│   ├── reviewer.py                  # الاتساق + Hallucination Guard + قرار التصعيد
│   ├── report_agent.py              # تقارير MD/HTML/PDF موثقة بالأدلة
│   ├── graph.py                     # مخطط LangGraph + نقاط التوقف البشري (interrupts)
│   ├── state.py                     # ScanState المتدفق بين الوكلاء
│   ├── mcp_client.py                # عميل MCP موحد (MultiServerMCPClient)
│   └── prompts/                     # orchestrator.j2 / extractor.j2 / scorer.j2 / reviewer.j2 / report.j2
│
├── core/
│   ├── config.py                    # pydantic-settings
│   ├── logging_config.py            # structlog → agent_logs
│   ├── scoring/
│   │   ├── engine.py                # تنفيذ المعادلة + التحويل لفئات
│   │   ├── base_score.py            # اشتقاق من CVSS/الأداة/MASVS
│   │   ├── context_score.py         # من app_context (قواعد، لا LLM)
│   │   ├── evidence_score.py        # أوزان الأدلة متعددة الأدوات/الديناميكية
│   │   ├── confidence.py            # حساب Confidence Factor
│   │   └── bands.py                 # عتبات Critical/High/Medium/Low
│   ├── guardrails/
│   │   ├── injection_shield.py      # تعقيم مخرجات الأدوات + canary
│   │   ├── schemas.py               # نماذج Pydantic لمخرجات الوكلاء
│   │   ├── output_validator.py      # تحقق + حلقة إصلاح
│   │   └── hallucination_guard.py   # تحقق CWE/MASVS والاستشهادات
│   ├── correlation/
│   │   ├── dedup.py                 # دمج findings المتكررة
│   │   └── fingerprints.py          # بصمة (package/class/sink/source/cwe)
│   └── mappings/
│       ├── cwe_masvs.py             # جداول CWE ↔ MASVS v2
│       └── cvss_utils.py            # حسابات CVSS
│
├── rag/
│   ├── ingest.py                    # تحميل MASVS/CWE إلى knowledge_base
│   ├── embeddings.py                # sentence-transformers محلي أو API
│   ├── store_sqlitevec.py           # متجهات داخل SQLite
│   └── retriever.py                 # استرجاع السياق للوكلاء
│
├── api/
│   ├── main.py                      # FastAPI app + CORS
│   ├── deps.py / auth.py            # DB session + JWT (جدول users)
│   ├── routers/                     # projects / applications(+upload) / scans / findings /
│   │                                #   assessments / feedback / reports / evaluation
│   └── workers/scan_worker.py       # تنفيذ pipeline الوكلاء بمهام خلفية
│
├── ui/streamlit_app/
│   ├── app.py                       # دخول + تنقّل
│   ├── api_client.py                # عميل REST
│   ├── pages/
│   │   ├── 01_dashboard.py          # مؤشرات عامة
│   │   ├── 02_projects_apps.py      # إدارة + app_context
│   │   ├── 03_upload_scan.py        # رفع APK + تشغيل + متابعة حية
│   │   ├── 04_findings.py           # جدول الثغرات وفلاتر MASVS/الخطورة
│   │   ├── 05_assessment_detail.py  # تفكيك النقاط الثلاث + الثقة + الأدلة
│   │   ├── 06_review_queue.py       # المراجعة البشرية والتصحيح
│   │   ├── 07_reports.py            # تصدير التقارير
│   │   └── 08_evaluation.py         # Kappa/AC1 والرسوم
│   └── components/
│       ├── score_breakdown.py       # رسم تفكيك المعادلة
│       └── diff_view.py             # مقارنة النظام بالتصحيح البشري
│
├── evaluation/
│   ├── protocol.md                  # العينة، الخبراء، تعليمات التقييم
│   ├── dataset/apps.yaml + ground_truth/
│   ├── run_experiment.py            # تشغيل العينة وتجميع النتائج
│   ├── metrics.py                   # Weighted Kappa + Gwet AC1 + Bootstrap CIs
│   ├── analyze_feedback.py          # أثر حلقة التغذية (A/B قبل/بعد)
│   └── notebooks/results_analysis.ipynb
│
├── scripts/
│   ├── init_db.py / seed_all.py
│   ├── setup_android_env.sh         # AVD مروّت + frida-server + MobSF
│   └── smoke_test_tools.py          # اختبار الأدوات الأربع على DIVA
│
├── tests/
│   ├── unit/ (scoring, guardrails, dedup, metrics)
│   ├── integration/ (MCP + pipeline على APK عينة)
│   ├── e2e/ (رفع→فحص→تقييم→تقرير)
│   └── fixtures/
│
└── docs/
    ├── architecture.md
    ├── mcp_design.md                # عقود أدوات MCP الأربعة
    ├── severity_model.md            # توثيق المعادلة والقواعد
    ├── security_guardrails.md
    └── db_schema.md
```

---

## 3. جدول التقنيات

| المكوّن | الاختيار الأساسي | البديل | المبرر |
|---------|------------------|--------|--------|
| اللغة | Python 3.11+ | — | كل الأدوات الأربعة قابلة للبرمجة من بايثون |
| Backend | FastAPI + Uvicorn | — | API نظيف، Async، يفصل الواجهة عن الفحوص الطويلة |
| مهام خلفية | arq / asyncio tasks | Celery+Redis | كافٍ بلا بروكر خارجي في V1 |
| Frontend | Streamlit (+ streamlit-authenticator) | Gradio | مطلوب بالمواصفات؛ صفحات متعددة ورسوم Plotly |
| Database | SQLite (WAL) + SQLAlchemy 2.0 + Alembic | — | مطلوب بالمواصفات؛ WAL يخفف قفل الكاتب الواحد |
| Vector store | sqlite-vec داخل SQLite | Chroma | يبقي كل شيء في قاعدة واحدة |
| Agents | LangGraph + LangChain | CrewAI / OpenAI Agents SDK | مخطط صريح، HITL interrupts، checkpointing على SQLite |
| LLM | Claude / GPT-4o عبر API (t=0) | Ollama محلي | Scorer/Reviewer يحتاجان نموذجاً قوياً؛ Extractor يمكن بنموذج أرخص |
| MCP | Python SDK الرسمي (FastMCP) + langchain-mcp-adapters | — | stdio للأدوات المحلية، HTTP/SSE لـ MobSF |
| Validation | Pydantic v2 | instructor | مطلوب بالمواصفات؛ Structured Outputs |
| JADX | jadx CLI | — | تحليل ساكن/تفكيك الكود |
| MobSF | MobSF Docker + REST API | — | إطار تحليل شامل |
| Frida | frida-tools + frida-server على AVD مروّت | جهاز فيزيائي | proof-of-concept ديناميكي |
| Objection | objection CLI (فوق Frida) | — | فحوص runtime جاهزة سريعة |
| Scoring | مكتبة cvss + قواعد مخصصة | — | قابلية تفسير وإعادة إنتاج |
| Evaluation | scikit-learn (cohen_kappa_score, weights='quadratic') + irrcac أو تطبيق AC1 يدوياً + NumPy bootstrap | statsmodels | Kappa جاهز؛ AC1 لا يوجد في المكتبات القياسية |
| Reports | Jinja2 → Markdown/HTML، PDF عبر WeasyPrint | ReportLab | قوالب عربية/إنجليزية مرنة |
| Config/Logs | pydantic-settings + YAML، structlog | loguru | تدقيق في agent_logs |
| Test/Dev | pytest، ruff، pre-commit، uv | Poetry | سرعة وثبات |

---

## 4. خطة العمل — 8 مراحل (~12 أسبوعاً)

| # | المرحلة | الوصف | مخرجات الخروج |
|---|---------|-------|----------------|
| 1 | التأسيس والبيئة | هيكل المشروع، DDL للجداول الـ14 + Alembic، بذر severity_rules، تجهيز بيئة أندرويد (AVD مروّت، frida-server، MobSF Docker، JADX) واختبار دخان على DIVA | قاعدة تعمل + الأدوات الأربع تستجيب |
| 2 | خوادم MCP | بناء خوادم JADX/MobSF/Frida/Objection بعقود Pydantic، مخزن artifacts، مهلات وإلغاء، تسجيلها في جدول tools | كل أداة تُستدعى عبر MCP وتُعيد نتائج منظمة |
| 3 | نواة الوكلاء والمنسق | BaseAgent + llm_client، برومبتات، LangGraph (state/graph)، Orchestrator يخطط ويرسل أوامر MCP ويسجل في agent_logs | فحص كامل ينتج Raw Findings من البداية للنهاية |
| 4 | الاستخراج والربط | Extractor: توحيد مخرجات الأدوات، dedup بالبصمات، ربط CWE/MASVS مع RAG (بذر knowledge_base + sqlite-vec) | vulnerabilities موحدة وأدلة مترابطة من عدة أدوات |
| 5 | التقييم والحمايات | محرك المعادلة الموزونة (base/context/evidence)، Confidence Factor، إصدارات القواعد؛ injection_shield + output_validator + hallucination_guard | assessments دقيقة وقابلة للتفسير + حمايات مفعّلة مع اختبارات |
| 6 | المراجعة البشرية والتقارير | Reviewer: فحص الاتساق وقرار التصعيد، قائمة مراجعة، corrections → feedback_examples وإعادة حقنها في البرومبتات؛ Report Agent | حلقة HITL كاملة + تقرير MD/PDF |
| 7 | الـ API والواجهة | FastAPI routers + auth، مهام خلفية؛ Streamlit بصفحاته الثمانية (رفع، متابعة، تفكيك النقاط، مراجعة، تقارير، تقييم) | منتج قابل للاستخدام طرف-لطرف |
| 8 | التقييم التجريبي والتصليب | بروتوكول التجربة، تشغيل العينة، جمع تقييمات الخبراء، Weighted Kappa + AC1 + A/B للتغذية الراجعة، اختبارات e2e، توثيق نهائي | نتائج Kappa/AC1 بفواصل ثقة + إصدار v1.0 |

---

## 5. المخاطر التقنية والتخفيف

| # | المخاطرة | الأثر | الاحتمال | التخفيف |
|---|----------|-------|----------|---------|
| 1 | هشاشة بيئة التحليل الديناميكي (عدم توافق frida-server/العميل، كشف الجهاز المروّت/الأدوات من التطبيقات) | فشل فحوص Frida/Objection فتنهار evidence_score | مرتفع | تثبيت نسخ pinned، صورة جهاز ذهبية (AVD snapshot)، أداة healthcheck في tools، وضع تدهور رشيق (static-only) مع خفض evidence_score علناً |
| 2 | هلوسة LLM (معرفات CWE/MASVS مختلقة أو أدلة وهمية) | تقييمات باطلة ونتائج تجربة مضللة | متوسط | خزانة مغلقة للمعرفات من knowledge_base، إلزام استشهاد قابل للتحقق (file:line/artifact_ref)، تحقق Reviewer، حرارة 0، عزل الحالات الفاشلة |
| 3 | حقن البرومبت عبر محتوى الـ APK (strings/أسماء أصناف خبيثة) | تسريب تعليمات النظام أو تزوير التقييم | متوسط-مرتفع | معاملة كل مخرجات الأدوات كغير موثوقة: تعقيم + عزل بوسوم XML + canary + حد طول + عدم تنفيذ أي تعليمات مستخرجة؛ اختبارات عدائية بـ APKs مسممة |
| 4 | عنق زجاجة SQLite (كاتب واحد مع وكلاء متوازين + واجهة) | Database locked وفشل فحوص | متوسط | وضع WAL، معاملات قصيرة، كاتب متسلسل واحد (queue)، عدم إبقاء استدعاءات LLM داخل معاملات، مسار ترقية موثق إلى PostgreSQL عبر SQLAlchemy |
| 5 | عدم استقرار الأدوات عبر MCP (فحوص MobSF الثقيلة، تعليق خطافات Frida) | مهلات متتالية وتعطل الـ pipeline | مرتفع | مهلة لكل أداة + retry/backoff + circuit breaker، نموذج مهام غير متزامن مع polling لحالة scan، نتائج جزئية قابلة للتقييم، استئناف من artifacts محفوظة |

**مخاطرة إضافية (إحصائية):** انحياز توزع العينة نحو Medium/High يسبب Kappa Paradox فيخدعنا مقدار الاتفاق — لهذا اعتُمد Gwet's AC1 بجانب Kappa، مع الإبلاغ عن prevalence وفواصل ثقة Bootstrap.
