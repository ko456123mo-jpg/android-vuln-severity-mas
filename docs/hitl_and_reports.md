# حلقة المراجعة البشرية (HITL) + محرك التقارير — المرحلة 5

> يغطي هذا المستند: حلقة التصحيح البشري الكاملة (corrections → feedback_examples)،
> بنية التقارير الفنية/التنفيذية، واجهات API، وكل قرار تصميمي مؤثر —
> مكمّلاً `docs/scoring_logic.md` (المرحلة 4).

---

## 1. المخطط الموسَّع / Graph (المرحلة 5)

```
orchestrator → run_*_tools → extractor_* → scorer → reviewer
                                          → persist_scores → reporter → finalize → END
```

- **persist_scores** (عقدة جديدة): تحفظ الثغرات + الأدلة + التقييمات + الأدوات
  *قبل* التقارير. بدونها تعمل تقارير أول فحص على قاعدة فارغة، لأن الحفظ كان في
  finalize (بعد reporter). كل عملياتها **idempotent**:
  - `create_vulnerability` — get-or-create بالبصمة (كانت كذلك منذ المرحلة 3).
  - `create_finding` — **صار idempotent على ثلاثية (vulnerability_id, scan_id, tool_id)**
    (تعديل المرحلة 5 — يعيد السجل القائم عند التكرار).
  - `upsert_by_vuln` — تقييم واحد لكل ثغرة.
  - `update_tools_used` — كتابة مباشرة للعمود.
- **reporter**: يولّد التقريرين؛ فشل إنتاج التقارير لا يسقط الفحص (يُسجَّل
  failed action ويُضاف للأخطاء، وتكتمل finalize).

## 2. محرك التقارير (`core/reports/`)

### 2.1 البيانات
مصدرها الوحيد قاعدة البيانات (`compute_scan_statistics + collect_data`): ثغرات
التطبيق مع تقييماتها مرتبة بـ `final_score` تنازلياً + الأدلة لكل ثغرة
(dynamic يعني `is_confirmed=True`) + إحصائيات الفحص.

### 2.2 التقريران
| التقرير | اللغة | الاتجاه | القالب | الجمهور |
|---|---|---|---|---|
| Technical | EN | LTR | `templates/technical_report.md.j2` | مهندسون |
| Executive | AR | RTL (`report-rtl`, `lang="ar"`) | `templates/executive_report.md.j2` | الإدارة |

- الملخصات التنفيذية العربية للثغرات Critical/High عبر LLM
  (`prompts/report_agent.j2` → مخطط `ReportOutput`) مع **بديل حتمي** عند التعذّر.
- قاعدة المحتوى: الملخصات **لا تذكر CWE/MASVS** ولا تخترع أرقاماً
  (يُختبر آليّاً في `test_report_generator.py::test_no_technical_tokens_in_summary`).
- حقل Recommendation محتوى إرشادي مشتق من خريطة ثابتة `RECOMMENDATIONS`
  (CWE→نص) — ليس حقلاً في القاعدة (موثّق هنا التزاماً بقاعدة عدم اختراع الحقول).

### 2.3 الصيغ
ستة ملفات لكل فحص في `data/reports/<scan_id>/`:
`technical_report.{md,html,pdf}` + `executive_report.{md,html,pdf}`.
PDF عبر **WeasyPrint** من الـ HTML المولّد (تنسيقات `report_styles.css` مضمّنة؛
يدعم العربية RTL). استيراد weasyprint كسول داخل `export_pdf` حتى لا تعتمد
بقية الصيغ على مكتبات النظام.

### 2.4 CLI
```bash
python scripts/generate_report.py --scan-id 4 --format all --output ./data/reports/
```
(بقية الصيغ: technical/executive/md/html/pdf — التنفيذي هنا يستخدم ملخصاً
حتمياً فارغاً لأن CLI لا يستدعي LLM؛ للتقرير الكامل المدعوم LLM استخدم
`POST /reports/{scan_id}/generate` أو مسار الـ pipeline).

> ملاحظة تشغيلية: مسارات التقارير مفتاحية بـ `scan_id` فقط — عند وجود قواعد
> متعددة (قاعدة اختبار + إنتاج) قد تتشارك الأرقام. سلوك تطويري مقبول موثق؛
> يُعالج في المرحلة 6 إن لزم بإضافة مساحة اسم لكل قاعدة.

## 3. حلقة HITL (`core/feedback/`)

### 3.1 دورة التصحيح الواحدة — `CorrectionManager.submit_correction()`
```
① corrections row: (original_severity/score ← من التقييم، corrected_*، reason، reviewer_id)
② assessments: severity ← المصحَّحة · review_status ← 'approved' · reviewed_by ← reviewer
     final_score لا يُمَس إطلاقاً (يبقى قيمة المحرك — سلامة المعادلة من المرحلة 4)
③ feedback_examples row: مثال few-shot نشط يُستخرج تلقائياً
```
تحققات صارمة: severity ∈ {Critical,High,Medium,Low} · سبب نصّي ≥ 3 أحرف
· درجة ∈ [0,10] · تقييم موجود — الرفض `ValueError` (وAPI يحوّله 404/422).

### 3.2 مثال Few-Shot (`feedback_extractor.py`)
`prompt_payload` المنظم:
```json
{
  "vuln_pattern": "Hardcoded API Key…",
  "masvs_category": "MASVS-CRYPTO",
  "cwe_id": "CWE-321",
  "context_summary": "أول سطرين من rationale المحرك",
  "original_severity": "High", "original_score": 8.2,
  "corrected_severity": "Critical", "corrected_score": 9.5,
  "reason": "سبب المراجع البشري"
}
```
`select_fewshot_examples(masvs_category, limit=5)`: نفس الفئة + `active=True`
+ الأحدث أولاً + حد أقصى 5 — تُحقن لاحقاً في برومبتات Scorer/Reviewer
(تحسين مستمر بلا إعادة تدريب؛ الحقن الفعلي تحسين مستقبلي موثق).

### 3.3 قائمة المراجعة
- `list_pending_reviews(limit, severity)` — pending مرتبة بخطورتها.
- `get_assessment_details(id)` — تقييم + ثغرة + تاريخ تصحيحات كامل.
- `get_review_queue_stats()` — عدادات (pending/approved/rejected +
  pending_by_severity + corrections_total + feedback_examples_total).

## 4. API (FastAPI — `api/`)

| Endpoint | الوظيفة |
|---|---|
| `GET /reviews/pending?limit&severity` | قائمة المعلّقة |
| `GET /reviews/{id}` | تفاصيل التقييم + التصحيحات |
| `POST /reviews/{id}/correct` | إرسال تصحيح (CorrectionInput) |
| `GET /reviews/stats` | إحصائيات القائمة |
| `POST /reports/{scan_id}/generate` | توليد الستة ملفات |
| `GET /reports/{scan_id}/technical` | تقرير فني (JSON) |
| `GET /reports/{scan_id}/executive` | تنفيذي (JSON) |
| `GET /reports/{scan_id}/download/{format}` | تنزيل md/html/pdf |

- تجميع: `api/main.py::create_app()` (جاهز لـ uvicorn وTestClient).
- **الهوية**: `api/deps.get_current_user` يعيد admin المزروع (users.id=1) —
  تطبيق محدود موثق لغاية نظام JWT الكامل في المرحلة 6؛ توقيع الاعتماد ثابت.

## 5. الاختبارات المرجعية

| الملف | العدد | يثبت |
|---|---|---|
| `tests/unit/test_report_generator.py` | 9 | إحصائيات دقيقة + ترتيب + RTL + تصدير MD/HTML/PDF |
| `tests/unit/test_feedback_loop.py` | 12 | دورة التصحيح + الرفض + القائمة + few-shot/filters |
| `tests/integration/test_full_pipeline_with_reports.py` | 2 | تقارير من الـ pipeline + جولة HITL كاملة |

المجموعة الكلية بعد المرحلة 5: **178/178**، صفر تحذيرات.

## 6. أخطاء عولجت أثناء البناء (للأطروحة)

1. **settings.yaml**: وكيل reporter احتاج مفتاح `llm.agents.reporter`
   (KeyError) — أُضيف (مع إبقاء مفتاح `report` التاريخي).
2. **ترتيب الفقرات الاختبارية**: بناء CompiledGraph (وSaver) يجب أن يبقى
   داخل حلقة الأحداث — نمط المرحلتين 3–4 نفسه (RuntimeError: no running event loop).
3. **هندسة الحفظ**: الفحص الأول كان ينتج تقارير فارغة المقاييس لأن الحفظ في
   finalize — حُلّ بإسقاف الحفظ إلى persist_scores + جعل الأدلة idempotent.
4. تحذير `datetime.utcnow()` المهمل — استُبدل بـ timezone-aware naive UTC.
