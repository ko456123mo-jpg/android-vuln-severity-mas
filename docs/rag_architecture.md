# معمارية RAG — التوليد المعزّز بالاسترجاع (المرحلة 7، مُصلَّبة في 8)

**الحالة:** مُنفَّذ ومُختبر · **الاختبارات:** `tests/unit/test_rag.py` (24 اختباراً)
**القرار الأصلي:** `docs/thesis/appendix_c_decision_log.md` (قرارات المرحلة 7)

---

## 1) لماذا RAG في هذا النظام؟

قبل المرحلة 7 كان **كل** صفوف `knowledge_base` تُحقن في برومبت المستخرج
(`agents/extractor.py::_full_knowledge_block`) — مع 8 أنماط حالياً هذا مقبول، لكنه
لا يتوسّع: 200 نمط ⇒ تضخّم البرومبت، تكلفة أعلى، وتشتيت للنموذج. الحل: استرجاع
`top_k = 3` أنسب نمط لكل استعلام، **مع إبقاء الكتلة الكاملة كبديل احتياطي** حتى لا
ينهار الاستخراج إذا فشلت طبقة الاسترجاع.

المكسب المقيس (وضع Mock، `results/benchmark.md`): استعلام RAG واحد ≈ **1.1 ms**
وفهرسة 8 صفوف ≈ **20 ms** — أي أن الطبقة كاملة أرخص من استدعاء نموذج واحد بمراحل.

---

## 2) المكوّنات

| الملفّ | المسؤولية |
|---|---|
| `rag/embeddings.py` | `EmbeddingEngine` — واجهة موحّدة لأربع خلفيات + LRU + `compose_kb_text` |
| `rag/store_sqlitevec.py` | `SqliteVecStore` — تخزين المتجهات في SQLite (امتداد `sqlite-vec` أو بديل python) |
| `rag/ingest.py` | `ingest_knowledge_base(force)` — فهرسة صفوف `knowledge_base` (idempotent) |
| `rag/retriever.py` | `KnowledgeRetriever.retrieve / retrieve_for_vulnerability` + `build_context_prompt` |
| `db/seed.py::seed_knowledge_base` | مصدر الأنماط الثمانية (MSTG/CWE/MASVS) |
| `agents/extractor.py` | المستهلك: كتلة سياق في البرومبت + `retrieved_patterns` لكل ثغرة |
| `evaluation/run_experiment.py` | تشغيل الفحص بأربعة أوضاع تقييم (`--mode full\|scorer_only\|no_rag\|no_feedback`)، ومنها `no_rag` (لقياس أثر الطبقة) |

---

## 3) مسار البيانات

```
knowledge_base (8 صفوف: ref_id · title · content · cwe_id · masvs_category)
        │  compose_kb_text() → "ref_id | title | cwe | category | content"
        ▼
EmbeddingEngine.embed(texts)          ← الخلفية المختارة تلقائياً (جدول §4)
        ▼
SqliteVecStore.upsert → جدول kb_vectors (بُعد = أبعاد الخلفية)
        ▲                                   │
        │                                   ▼
استعلام: نص مخرجات أداة (أو عنوان ثغرة)   store.search(qvec, top_k, allowed_ids)
        │                                   │
        └── EmbeddingEngine.embed_single ◄──┘  ← [(kb_id, cosine)] تنازلياً
                                            ▼
                          KnowledgeRetriever.retrieve() → صفوف KB + similarity
                                            ▼
             build_context_prompt() → كتلة نصية في برومبت extractor.j2
                                            ▼
                ExtractedVuln.retrieved_patterns = [ref_id, …]  (للتدقيق)
```

الأمران التشغيليان:

```bash
python scripts/ingest_knowledge.py --force          # إعادة فهرسة كاملة
python scripts/ingest_knowledge.py                  # فهرسة الناقص فقط
```

---

## 4) خلفيات التضمين — الاختيار والتراجع

`EmbeddingEngine._resolve_mode()` بالأولوية:

| # | الوضع | الشرط | الأبعاد | الاستعمال |
|---|---|---|---|---|
| 1 | `mock` | `EMBEDDING_MOCK_MODE=1` | 384 | اختبارات/عروض بلا شبكة (حتمية بالبذرة) |
| 2 | `sentence-transformers` | `MAS_EMBEDDING_BACKEND=sentence-transformers` | 384 | الجودة الأعلى عربياً/إنجليزياً |
| 3 | `api` | `MAS_EMBEDDING_BACKEND=api` + مفتاح | مزوّد | نشر بلا حزم ثقيلة |
| 4 | `tfidf` | الافتراضي عند غياب 1–3 | حجم المعجم (234 حالياً) | **احتياطي محلي** يعمل بلا إنترنت |

**سياسة التراجع (قرار المرحلة 7، مُصلَّب في 8):** إذا فُرضت `sentence-transformers`
أو `api` وتعيَّر التحميل (حزمة/مفتاح مفقود)، ينتقل المحرك تلقائياً إلى `tfidf`
ويسجّل السبب في **`fallback_reason`** — لا تراجع صامت. الاختبار:
`test_fallback_to_tfidf_is_recorded_with_reason`.

> **ملاحظة بيئة:** في بيئة التسليم لا حزمة `sentence-transformers` ولا مفتاح API،
> لذا فالخلفية الفعلية في كل أرقام هذا المستند هي **TF-IDF** (أرقام التشابه أدناه
> TF-IDF حقيقةً). أرقام وضع `mock` لا تُستشهد بها في الجودة — متجهاتها شبه-عشوائية
> عمداً، ويقتصر استعمالها على اختبارات ثبات الواجهة.

**أبعاد وتبديل الخلفية:** البُعد جزء من عقد المخزن. تغييره ⇒ `init_schema` يُسقط
الجدول ويعيد إنشاءه (`recreated=True`) ويجب إعادة الفهرسة الكاملة — لذلك تُعيد
دالة الفهرسة عند إعادة الإنشاء كتابة **كل** الصفوف لا الصفوف الناقصة فقط
(اختبار: `test_dimension_change_recreates_schema` + `test_force_reembeds_everything`).

---

## 5) الاسترجاع

| البند | القيمة/السلوك |
|---|---|
| `top_k` | 3 من `config/settings.yaml → rag.retrieval_top_k` |
| المسافة | جيب التمام (تُخزَّن كمسافة cosine في `sqlite-vec` ⇒ `similarity = 1 − distance`) |
| فلترة | `masvs_filter` ⇒ قيد `allowed_ids` على الصفوف (فئة الثغرة نفسها) |
| استعلام الثغرة | تركيب `title | description | cwe_id | masvs_category | sub_category` |
| لا نتائج | `[]` صراحةً (لا استثناء) — والمُستدعي يتصرف |
| فشل الطبقة | المستخرج يتراجع إلى الكتلة الكاملة (المرحلة 3) ويُبقى الفحص سليماً |
| التدقيق | كل ثغرة تحمل `retrieved_patterns` (معرّفات) و`retrieval_error` عند الفشل |

**فشل الاسترجاع لا يُبتلع:** `_attach_retrieved_patterns` يسجّل `retrieval_error`
داخل مدخل الثغرة (درس المرحلة 7: «لا فشل صامت»)، و`retrieval` نفسها تُعيد `[]` ولا
ترفع استثناءً في المسار العادي.

---

## 6) تحقق يدوي من الجودة (الأساس الذي بُنيت عليه الاختبارات)

قبل تثبيت أي اختبار جودة، نُفّذت الاستعلامات يدوياً على المخزن الحقيقي بخلفية
TF-IDF. النتائج (أرقام فعلية، `python` مباشر — لا تخمين):

| الاستعلام | المرتبة 1 | التشابه | المرتبة 1 المتوقعة |
|---|---|---|---|
| `SSL pinning bypass — certificate pinning not enforced` | **MSTG-NETWORK-3** | 0.4620 | ✓ |
| `hardcoded encryption key stored in source code` | **MSTG-CRYPTO-1** | 0.3666 | ✓ |
| `insecure data storage — sensitive data in shared preferences` | **MSTG-STORAGE-1** | 0.4339 | ✓ |
| `root detection missing — app runs on rooted device` | **MSTG-RESILIENCE-1** | 0.2545 | ✓ |

هذه الأربعة ثُبّتت في `TestRetrievalQuality.test_known_security_queries_hit_correct_pattern`
كاختبار انحدار: أي تراجع في الجودة يُسقط الاختبار بدل أن يمرّ بصمت.

---

## 7) عيوب اكتُشفت وأُصلحت (المرحلة 8)

| العيب | الأثر | الإصلاح |
|---|---|---|
| متجه استعلام صفري (TF-IDF بلا تطابق معجمي) ⇒ `distance = NULL` من `sqlite-vec` ⇒ `TypeError` | سقوط الاسترجاع بدل إعلان «لا نتائج» | عودة مبكرة `[]` عند `‖q‖ = 0` + تخطّي أي `distance IS NULL` (اختبار `test_zero_vector_returns_empty_without_crash`) |
| فشل الاسترجاع داخل المُستخرج يضع `retrieved_patterns = []` بلا سبب | عيب صامت | إضافة `retrieval_error` (موثّقة) وتُظهر في تدقيق الحالة |
| أرقام الجودة غير موثّقة قبل الاختبارات | خطر اعتماد أرقام «مُتخيّلة» | جدول §6 + تثبيتها كاختبارات |

---

## 8) الأثر على التجربة (مقياس RQ)

`evaluation/run_experiment.py` يشغّل أربعة أوضاع على نفس التطبيقات (`--mode`)، وله تجربة جافّة بلا كتابة نتائج (`--dry-run`):
`full` · `no_rag` · `no_feedback` · `scorer_only`. الفرق بين `full` و`no_rag` هو
المقياس التجريبي لأثر طبقة RAG على جودة التقييم — ويُحسب على **الحقيقة المرجعية
اليدوية** (`evaluation/ground_truth.py`، 12 مدخلاً بحالة `filled: false`) لا على
الافتراض. أي رقم يُنشر يجب أن يأتي من `evaluation/analyze_results.py` بعد تعبئة
الحقيقة المرجعية يدوياً.

---

## 9) حدود وقيود

1. **TF-IDF يعتمد على تطابق المعجم**: استعلام بلا مصطلحات مشتركة مع النص لا يُعيد
   شيئاً (سلوك معلن ومُختبر). المقايضة مقصودة: عمل كامل بلا إنترنت بتكلفة جودة أقل
   من نموذج تضمين حقيقي — وهذا **موضوع قياس** في الأطروحة لا ادّعاء محسوم.
2. **قاعدة معرفة صغيرة (8 أنماط)**: النتائج على هذا الحجم تسمح بتضمين كل شيء؛
   الاختبارات تثبّت الجودة الحالية لا سقف الأداء.
3. **لا تقسيم للنصوص الطويلة**: مخرجات الأدوات تُقتطع عند 6000 حرف قبل الاستعلام،
   ولا تُقطَّع إلى مقاطع متعددة (chunking). مبرَّر: KB قصيرة-وصفية؛ التوسّع القادم
   يحتاج chunking + إعادة ترتيب بـ cross-encoder.
4. **لا قياس precision@k بمعزل**: دقة الاسترجاع تُقاس أعلاه بمرتبة أولى معروفة
   (ground truth صغير يدوي)، لا بمجموعة تقييم كاملة.
5. **الكلفة الثابتة لـ `retrieve`**: يحمّل صفوف KB في كل نداء (مقبول لحجم 8؛
   يحتاج كاش عند النمو).

خطة التطوير المقترحة: (أ) cross-encoder لإعادة ترتيب أعلى 20، (ب) تخزين مؤقت
للمتجهات على القرص، (ج) توسيع KB إلى ≥ 50 نمطاً مع مجموعة استعلامات مُسمّاة
لقياس precision@k، (د) chunking لمخرجات الأدوات الطويلة.
