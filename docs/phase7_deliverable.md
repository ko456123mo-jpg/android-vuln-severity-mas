# تسليم المرحلة 7 — RAG + تجربة القياس الإحصائي
### تقرير إتمام قابل للتحقق اليدوي · مولّد من مخرجات حقيقية

> **كل رقم في هذا الملف مأخوذ حرفياً من تنفيذ فعلي على هذا المستودع.**
> لا توجد نتائج تجريبية مُصطنعة: ملفات الحقيقة المرجعية قوالب فارغة (`filled: false`)
> تُملأ يدوياً من خبيرين + مراجع ثالث، وحتى ذلك الحين تُصرّح الأدوات بـ `metrics: null`.

---

## ✅ قائمة تحقق سريعة (8 خطوات تحقق)

| # | الخطوة (الأمر) | النتيجة المرصودة | الدليل |
|---|---|---|---|
| 1 | `EMBEDDING_MOCK_MODE=1 python -m pytest tests/unit/test_rag.py -q` | **27 passed** | `results/evidence/01_rag_tests.txt` |
| 2 | `python -m pytest tests/unit/test_metrics.py -q` | **36 passed** | `results/evidence/02_metrics_tests.txt` |
| 3 | `python scripts/ingest_knowledge.py --force` | **8 مُفهرس** / dim=234 / idempotent | `results/evidence/03a_ingest_force.txt` |
| 4 | `python scripts/ingest_knowledge.py --status` | متجهات مخزنة: 8 | `03b_ingest_status.txt` |
| 5 | استرجاع «SSL pinning bypass» | Top-1 = **MSTG-NETWORK-3** (0.478) | `04_retrieval_top3.txt` |
| 6 | E2E: `build_scan_graph()` + `ainvoke_pipeline` | 9 ثغرات، 9 تقييمات، 0 أخطاء، RAG مرفق | `05_e2e_pipeline.txt` |
| 7 | تجربة جافة × 4 أوضاع | 4/4 أوضاع `stage=done` · ثم تقارير بلا أرقام مصطنعة | `06_dryrun_all_modes.txt` · `06b` · `07` |
| 8 | `python -m pytest -q` (مجموعة كاملة) | **283 passed** | `08_full_suite.txt` |

---

## (1) قائمة الملفات وأحجامها

```
المجموعة                  الملف                                                      بايت
--------------------------------------------------------------------------------------------
RAG (جديد)                rag/__init__.py                                             824
RAG (جديد)                rag/embeddings.py                                          8725
RAG (جديد)                rag/store_sqlitevec.py                                    12672
RAG (جديد)                rag/ingest.py                                              3116
RAG (جديد)                rag/retriever.py                                           7035
RAG (جديد)                scripts/ingest_knowledge.py                                1858
                          — مجموع المجموعة                                          34230
التجربة (جديد)            evaluation/__init__.py                                      110
التجربة (جديد)            evaluation/metrics.py                                     12871
التجربة (جديد)            evaluation/protocol.md                                     9243
التجربة (جديد)            evaluation/dataset/apps.yaml                               6464
التجربة (جديد)            evaluation/run_experiment.py                              16463
التجربة (جديد)            evaluation/analyze_results.py                             20208
التجربة (جديد)            evaluation/analyze_feedback.py                            14102
التجربة (جديد)            evaluation/notebooks/results_analysis.ipynb                6086
                          — مجموع المجموعة                                          85547
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/androgoat.json              662
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/diva.json                   687
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/dvba.json                   679
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/insecure-shop.json          669
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/insecurebankv2.json         672
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/mstg-hacking-playground.json      690
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/ovaa.json                   689
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/sieve.json                  684
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/uncrackable-l1.json         683
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/uncrackable-l2.json         683
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/uncrackable-l3.json         683
الحقيقة المرجعية (قوالب)  evaluation/dataset/ground_truth/vuldroid.json               660
                          — مجموع المجموعة                                           8141
الواجهة                   ui/streamlit_app/pages/08_evaluation.py                    9777
الواجهة                   ui/streamlit_app/i18n.py                                  14516
                          — مجموع المجموعة                                          24293
الاختبارات                tests/unit/test_rag.py                                    14719
الاختبارات                tests/unit/test_metrics.py                                12991
                          — مجموع المجموعة                                          27710
التوثيق                   docs/rag_architecture.md                                   8796
التوثيق                   docs/evaluation_protocol.md                               13067
                          — مجموع المجموعة                                          21863
وكلاء/إعدادات (معدّلة)    agents/state.py                                            4232
وكلاء/إعدادات (معدّلة)    agents/extractor.py                                       12028
وكلاء/إعدادات (معدّلة)    agents/scorer.py                                          11700
وكلاء/إعدادات (معدّلة)    agents/prompts/scorer.j2                                   1622
وكلاء/إعدادات (معدّلة)    agents/graph.py                                           17514
وكلاء/إعدادات (معدّلة)    tests/conftest.py                                          1663
وكلاء/إعدادات (معدّلة)    config/settings.yaml                                       1394
                          — مجموع المجموعة                                          50153
--------------------------------------------------------------------------------------------
الإجمالي                                                                           251937 bytes (246.0 KB)
```

إضافات توليدية (منفصلة عن الكود): `results/REPORT.md` · `results/summary.json` ·
`results/feedback_ab_test.md|json` · `results/dry_run/<mode>/*.json` (8 ملفات) ·
`results/evidence/*.txt` (10 ملفات).

## (2) مخرج اختبارات RAG — 27 اختباراً

```
...........................                                              [100%]
27 passed in 1.82s
```

**ما يثبته:** حتمية mock embeddings · خلفيتا التخزين (sqlite-vec / python) · تشابه
جيبي محسوب يدوياً (تطابق تام ≈1.0 و`cos=0.99862`) · فهرسة idempotent (force ⇒ 8،
بلا force ⇒ 0 مُفهرس) · ترتيب الاسترجاع ومصادره · فلتر MASVS (فئة معروفة/مجهولة/
مخزن فارغ ⇒ fallback كامل) · إرفاق `retrieved_patterns` في Extractor · رفض `vec0`
مع خلفية python · إعادة الإنشاء عند تغيّر الأبعاد.

## (3) مخرج اختبارات المقاييس — 36 اختباراً (كل مقياس بمثال محسوب يدوياً)

```
....................................                                     [100%]
36 passed in 3.70s
```

**أمثلة محسوبة يدوياً مثبّتة كاختبارات** (النص الحسابي مكتوب داخل كل اختبار):

| المقياس | المدخل | الحساب اليدوي | القيمة |
|---|---|---|---|
| Precision/Recall/F1 | TP=8, FP=2, FN=4 | P=8/10 · R=8/12 · F1=8/11 | 0.8 / 0.6667 / 0.7273 |
| Percent Agreement | 5 أزواج، 3 متوافقة | 3/5 | 0.6 |
| Weighted κ | 3 فئات، r1=[0,0,1,1,2,2]، r2=[0,1,1,1,2,2] | D_o=1/24، D_e=7/24 ⇒ 1−1/7 | 6/7 = 0.8571 |
| Gwet AC1 | r1=[1,1,2,2]، r2=[1,2,2,2] | P_o=0.75، P_e'=30/64 ⇒ 0.28125/0.53125 | 9/17 = 0.5294 |
| العقوبة التربيعية | خطأ خطوة واحدة مقابل 3 خطوات من 4 | 1−(1/36)/(2/9) مقابل 1−(1/4)/(5/18) | 0.875 > 0.1 |
| Cohen's d مزدوج | a=[1,1,2,2]، b=[2,3,3,4] | فرق=1.5، sd=0.5774 | ≈2.598 |
| Landis-Koch | 0.19/0.40/0.61/0.80 | دسّ الحدود | ضعيف جداً/متوسط/جيد/ممتاز |

**تصحيحات هذا الدور على المقاييس** (بعد فشل حقيقي في أول تشغيل):
1. `weighted_cohens_kappa` كانت تُعيد `NaN` لمتقيّم ثابت (0/0 في sklearn) → معالجة
   صريحة موثقة: تطابق تام ⇒ 1.0 وإلا 0.0 (عبر `manual_quadratic_kappa`).
2. اختبار العقوبة التربيعية كان يستخدم سلسلتين ثابتتين (κ=0.0 دائماً) → أُعيد
   تصميمه بسلسلتين فيهما 3 توافقات وخطأ واحد (0.875 مقابل 0.1).
3. `paired_test` لم يُخرج `mean_diff` (KeyError) → أُضيف من `cohens_d_paired`.
4. تحذير Wilcoxon على الفروق الصفرية → كُتم داخل المدى الموثق (الحالة معالَجة كـ«بلا فروق»).

## (4) نتيجة الفهرسة (المتوقع: 8 embeddings)

```
◉ محرك التوليد: tfidf | المخزن: sqlite-vec
✅ اكتملت الفهرسة: 8 مُفهرس، 0 متخطّى
  store_total=8 | dim=234 | backend=sqlite-vec | recreated=False
◉ محرك التوليد: tfidf | المخزن: sqlite-vec
  متجهات مخزنة: 8 | البعد الحالي: 234
```

- الخلفية المعروضة: **tfidf** (محلية، بلا إنترنت) — الأبعاد 234 = حجم معجم
  قاعدة المعرفة، والمخزن `sqlite-vec`.
- تشغيل mock embeddings (384 بعداً) مُثبت أيضاً في الاختبارات
  (`ingest force → embedded 8, dim 384`).
- إعادة التشغيل بـ `--force` لا تُنتج صفوفاً مكررة (نفس `kb_id` يُحدَّث).

## (5) الاسترجاع Top-3 لعبارة «SSL pinning bypass certificate validation»

```
query: SSL pinning bypass certificate validation

  1. MSTG-NETWORK-3   | SSL Pinning Missing        | sim=0.4780 | vector
  2. MSTG-AUTH-1      | Weak Authentication        | sim=0.0000 | vector
  3. MSTG-PLATFORM-1  | Exported Components        | sim=0.0000 | vector

build_context_prompt (مختصر):
- MSTG-NETWORK-3 | SSL Pinning Missing | CWE-295 | MASVS-NETWORK: التطبيق لا يطبق SSL Pinning — قناة TLS معرضة لهجمات MITM. [تشابه 0.478]
- MSTG-AUTH-1 | Weak Authentication | CWE-287 | MASVS-AUTH: ضعف في المصادقة — آليات تحقق غير كافية يمكن تجاوزها. [تشابه 0.000]
- MSTG-PLATFORM-1 | Exported Components | CWE-926 | MASVS-PLATFORM: مكونات مُصدَّرة (Activities/Services/Receivers) بدون حماية بأذونات. [تشابه 0.000]
```

## (6) خط الأنابيب الكامل مع RAG (E2E)

```
stage=done | vulns=9 | assessments=9 | errors=0

الثغرات وأنماط RAG المسترجعة لكل واحدة:
  - Hardcoded Encryption Key               [MASVS-CRYPTO] retrieved=['MSTG-CRYPTO-1', 'MSTG-CRYPTO-4']
  - Weak Cryptography                      [MASVS-CRYPTO] retrieved=['MSTG-CRYPTO-4', 'MSTG-CRYPTO-1']
  - Insecure Logging                       [MASVS-CODE] retrieved=['MSTG-CODE-3']
  - Exported Components                    [MASVS-PLATFORM] retrieved=['MSTG-PLATFORM-1']
  - Insecure Data Storage                  [MASVS-STORAGE] retrieved=['MSTG-STORAGE-1']
  - SSL Pinning Missing                    [MASVS-NETWORK] retrieved=['MSTG-NETWORK-3']
  - Root Detection Absent                  [MASVS-RESILIENCE] retrieved=['MSTG-RESILIENCE-1']
  - Weak Authentication                    [MASVS-AUTH] retrieved=['MSTG-AUTH-1']
  - Cleartext HTTP Traffic                 [MASVS-NETWORK] retrieved=['MSTG-NETWORK-3']
```

> كل ثغرة استرجعت نمط MASVS الصحيح لها (تشفير→CRYPTO، شبكة→NETWORK-3، تخزين→STORAGE-1...)
> و`retrieved_patterns` مُصدَّر في نتائج التجربة كدليل تدقيق يمكن قياسه.

## (7) التجربة الجافة — 4 أوضاع (بلا أرقام تجريبية مُختلقة)

```
═══════════ mode: full ═══════════
◉ DRY-RUN: Mock كامل (LLM/MCP/Embeddings) — سباكة فقط بلا نتائج حقيقية
◉ الوضع: dry_run | التطبيقات: ['diva', 'insecurebankv2']
  ✓ diva                     stage=done     vulns=9   assessments=9   errors=0 metrics=— (3020ms)
  ✓ insecurebankv2           stage=done     vulns=9   assessments=9   errors=0 metrics=— (730ms)
✅ حُفظت النتائج الخام في: /home/user/android-vuln-severity-mas/results/dry_run/full (2 ملف)
⚠️  الحقيقة المرجعية غير مُملأة — المقاييس ستكون null حتى الإملاء اليدوي

═══════════ mode: scorer_only ═══════════
◉ DRY-RUN: Mock كامل (LLM/MCP/Embeddings) — سباكة فقط بلا نتائج حقيقية
◉ الوضع: dry_run | التطبيقات: ['diva', 'insecurebankv2']
  ✓ diva                     stage=done     vulns=9   assessments=9   errors=0 metrics=— (2982ms)
  ✓ insecurebankv2           stage=done     vulns=9   assessments=9   errors=0 metrics=— (682ms)
✅ حُفظت النتائج الخام في: /home/user/android-vuln-severity-mas/results/dry_run/scorer_only (2 ملف)
⚠️  الحقيقة المرجعية غير مُملأة — المقاييس ستكون null حتى الإملاء اليدوي

═══════════ mode: no_rag ═══════════
◉ DRY-RUN: Mock كامل (LLM/MCP/Embeddings) — سباكة فقط بلا نتائج حقيقية
◉ الوضع: dry_run | التطبيقات: ['diva', 'insecurebankv2']
  ✓ diva                     stage=done     vulns=9   assessments=9   errors=0 metrics=— (2884ms)
  ✓ insecurebankv2           stage=done     vulns=9   assessments=9   errors=0 metrics=— (663ms)
✅ حُفظت النتائج الخام في: /home/user/android-vuln-severity-mas/results/dry_run/no_rag (2 ملف)
⚠️  الحقيقة المرجعية غير مُملأة — المقاييس ستكون null حتى الإملاء اليدوي

═══════════ mode: no_feedback ═══════════
◉ DRY-RUN: Mock كامل (LLM/MCP/Embeddings) — سباكة فقط بلا نتائج حقيقية
◉ الوضع: dry_run | التطبيقات: ['diva', 'insecurebankv2']
  ✓ diva                     stage=done     vulns=9   assessments=9   errors=0 metrics=— (2994ms)
  ✓ insecurebankv2           stage=done     vulns=9   assessments=9   errors=0 metrics=— (713ms)
✅ حُفظت النتائج الخام في: /home/user/android-vuln-severity-mas/results/dry_run/no_feedback (2 ملف)
⚠️  الحقيقة المرجعية غير مُملأة — المقاييس ستكون null حتى الإملاء اليدوي
```

```
✅ REPORT.md: results/REPORT.md
✅ summary.json: results/summary.json
   أوضاع: ['full', 'no_feedback', 'no_rag', 'scorer_only'] | رسوم: 0
```

```
✅ التصحيحات: 1 | فوج A: 1 | فوج B: 0
✅ التقرير: /home/user/android-vuln-severity-mas/results/feedback_ab_test.md
⚠️  لا تصحيحات بعد العتبة — الاختبار المزدوج غير متاح (بيانات غير كافية)
```

- `REPORT.md` و`feedback_ab_test.md` **يرفضان** إخراج أي F1/Kappa قبل إملاء الحقيقة
  المرجعية، ويصرّحان بذلك نصاً («GT غير مُملأة» / «بيانات غير كافية»).
- الوضعان `scorer_only` و`no_rag` و`no_feedback` تعمل فعلياً: في `scorer_only`
  لا قرار مراجعة آلي (كل الحقول `requires_human_review = null`) بينما في `full`
  القرار يعمل — انظر `results/dry_run/*/diva.json`.

## (8) المجموعة الكاملة

```
........................................................................ [ 25%]
........................................................................ [ 50%]
........................................................................ [ 76%]
...................................................................      [100%]
283 passed in 29.93s
```

**283 = 220 (المراحل 1–6) + 27 (RAG) + 36 (المقاييس)** — بلا أي إسقاط أو تعطيل اختبار.

## (9) الأخطاء والإصلاحات (سجل شفاف)

| # | العلة | الأثر | الإصلاح |
|---|---|---|---|
| 1 | `_mock_vector` عبر `rng` كان يُعطي متجهات **تتغير بين العمليات** في أول تصميم | فشل حتمية mock | بذرة = `20260712 + blake2b(text)` — نفس النص ⇒ نفس المتجه |
| 2 | `CREATE VIRTUAL TABLE ... vec0(v BLOB)` | `Unknown table option` | صيغة مطبوعة `embedding float[N]` + `distance_metric=cosine` |
| 3 | `PRAGMA table_info` على جدول vec0 بلا الإضافة | `no such module: vec0` | قراءة DDL من `sqlite_master` حصراً (`existing_schema`) |
| 4 | ملف SQLite واحد بخلفيتين | تخريب بنيوي محتمل | `RuntimeError` واضح + عزل ملفات الاختبار لكل خلفية |
| 5 | اختبار مساعد داخل صنف `parametrize` بلا الوسيط | فشل تجميع pytest | نُقل إلى مستوى الوحدة |
| 6 | تشابه متوقع 1.0 لمتجه «قريب» | فشل تأكيد | حُسب يدوياً: `cos([0.95,0.05,0,0],[1,0,0,0])=0.99862` وفُصل تأكيد التطابق التام |
| 7 | `cohen_kappa_score` تُعيد NaN لسلسلة ثابتة | فشل اختبار + خطر تمرير NaN | معالجة 0/0 موثقة (1.0 / 0.0) |
| 8 | عقوبة تربيعية على سلاسل ثابتة = κ 0.0 دائماً | اختبار غير مميّز | أُعيد التصميم (0.875 مقابل 0.1) |
| 9 | `paired_test` بلا `mean_diff` | KeyError | أُضيف من `cohens_d_paired` |
| 10 | تحذير Wilcoxon (فروق صفرية) | ضجيج في المخرجات | كُتمت داخل المدى المعالَج صراحةً |
| 11 | `python evaluation/run_experiment.py` من أي cwd | `ModuleNotFoundError: evaluation` | بوتستراب `sys.path` في كل سكربتات `evaluation/` |
| 12 | `build_scan_graph()` خارج حلقة الأحداث | `RuntimeError: no running event loop` (AsyncSqliteSaver) | البناء داخل `async def _run()` |
| 13 | تشغيل جاف لوضعين يكتب نفس الملف | تصادم نتائج | فصل `results/dry_run/<mode>/` + `rglob` |
| 14 | **`from db.connection import get_database_path`** (اسم غير موجود) | الاسترجاع كان يفشل **بصمت** (يُلتقط الاستثناء ويُكمل!) ⇒ `retrieved_patterns=[]` | الاسم الصحيح `get_db_path` + تسجيل `retrieval_error` في الثغرة بدل الابتلاع الصامت — ثم أُعيد التحقق: كل الثغرات استرجعت أنماطها |
| 15 | تغيّر أبعاد mock(384)/tfidf(234) على نفس الملف | إعادة إنشاء الجدول (سلوك مصمم) | فُحصت الحالة قبل العرض وثُبّتت الخلفية tfidf المتسقة |

## (10) التأكيد النهائي

| المعيار | الحالة | الدليل |
|---|---|---|
| RAG يعمل في Mock Mode بلا إنترنت | ✅ | 27 اختباراً + تشغيل mock (dim 384) |
| RAG يعمل بخلفية محلية حقيقية بلا API | ✅ | tfidf (8 متجهات، استرجاع دلالي صحيح) |
| SqliteVecStore بخلفيتين + fallback | ✅ | اختبارات vec/python + قاعدة حقيقية |
| Extractor يستهلك top-k بدل القائمة الكاملة | ✅ | `05_e2e_pipeline.txt` + `disable_rag` يبدّل للكتلة الكاملة |
| Scorer few-shot من التصحيحات | ✅ | `_fewshot_block` + وضع `no_feedback` يعمل |
| كل مقياس إحصائي مُختبَر بقيم محسوبة يدوياً | ✅ | 36 اختباراً (القسم 3) |
| Boootstrap 10,000 / seed 42 / نسبة ثقة 95% | ✅ | `evaluation/metrics.py` + اختبارات الاحتواء والحتمية |
| Weighted κ بأوزان تربيعية | ✅ | مطابقة يدوية + تقاطع sklearn |
| Gwet's AC1 يدوية (خارج sklearn) | ✅ | تنفيذ numpy كامل + 4 اختبارات |
| Landis-Koch بالعربية (5 نطاقات) | ✅ | `interpret_kappa` + اختبار الحدود |
| A/B باختبار مزدوج (t أو Wilcoxon) + d | ✅ | `analyze_feedback.py` (يرفض الأرقام مع n<3) |
| Ground truth قوالب تُملأ يدوياً وليست مُختلقة | ✅ | 12 ملف `filled:false` |
| لا أرقام مصطنعة في `results/` | ✅ | التقارير تُصرّح بالنقص بدل التخمين |
| توثيق كل قرار إحصائي | ✅ | `docs/evaluation_protocol.md` (§3 سجل قرارات + بدائل مرفوضة) |
| الواجهة صفحة 08 تعرض النتائج الحقيقية | ✅ | 3 تبويبات + تفسير + تنزيلات + حالة «بلا نتائج» |
| لا TODOs في الكود الجديد | ✅ | فُحص بالبحث النصي |
| المجموعة الكاملة خضراء | ✅ | **283 passed** |

### الخطوة التالية لك (خارج نطاق الكود)
1. ضع ملفات APK في `data/apks/` ثم املأ `evaluation/dataset/ground_truth/*.json`
   بتقييم خبيرين + مراجع ثالث واضبط `filled: true`.
2. شغّل الأوضاع الأربعة على التطبيقات الـ12 ثم `analyze_results.py` ⇒ تقرير بأرقام
   RQ1–RQ4 حقيقية، وبعد 20+ تصحيحاً بشرياً شغّل `analyze_feedback.py` لاختبار RQ5.
