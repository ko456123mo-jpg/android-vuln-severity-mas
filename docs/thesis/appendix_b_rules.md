# الملحق (ب) — القواعد والمعادلات والأوزان / Appendix B: Rules & Weights

> **كل رقم في هذا الملحق مستخرَج من كود فعلي** (`core/scoring/*`, `agents/reviewer.py`)
> أو من صف قاعدة التقييم النشط (`severity_rules` إصدار `v1.1`)، وكل جدول له نظير
> قابل للتشغيل: `tests/unit/test_scoring_engine.py` · `tests/unit/test_reviewer.py`
> · `scripts/reachability_report.py` → `results/reachability.md`.

---

## ب-1) معادلة الخطورة النهائية

```
final_score = 0.6 · base_score
            + 0.2 · context_score
            + 0.2 · evidence_score            ثم: round(…, 4)

evidence_score = 3.0 + 7.0 × confidence_factor
confidence     = 0.4·tool_count + 0.3·evidence_quality + 0.2·tool_reliability + 0.1·reproducibility
```

| الوزن | القيمة | المصدر | التبرير الموثّق |
|---|---|---|---|
| base | 0.60 | `severity_rules.weights.base` | الخطر الفئوي محرّك الترتيب الأول |
| context | 0.20 | `…weights.context` | تخصيص النتيجة للحالة الواقعية |
| evidence | 0.20 | `…weights.evidence` | القوة من الدليل المؤكَّد |

## ب-2) أوزان فئات MASVS (`base_score`)

| الفئة | الوزن | التبرير |
|---|---|---|
| `MASVS-CRYPTO` | 9.0 | انكشاف البيانات بغضّ النظر عن بقية الطبقات |
| `MASVS-STORAGE` | 8.0 | تسريب مباشر عبر الجهاز/النسخ الاحتياطي |
| `MASVS-NETWORK` | 7.5 | اعتراض/تلاعب بالنقل |
| `MASVS-AUTH` | 7.0 | تجاوز مصادقة/تفويض |
| `MASVS-PLATFORM` | 6.0 | سوء استخدام مكوّنات المنصّة (IPC/WebView/Permissions) |
| `MASVS-RESILIENCE` | 5.0 | شرط مُمكِّن (ضعف مقاومة التحليل) لا ضرر مباشر |
| `MASVS-CODE` | 4.0 | جودة كود وسوء ممارسة |
| غير معروفة | 5.0 | وسط المدى **صراحةً**؛ تُظهر كـ«غير مصنّفة» في التفسير |

**إفصاح لازم:** هذه الأوزان **مُصمَّمة داخل هذا المشروع** بأسباب مكتوبة (أعلاه)،
وهي **ليست** أرقاماً رسمية من OWASP — MASVS تصنيف، وليس نظام تقييم كمّي. يُبنى
عليها كإطار قابل للمعايرة (v2)، لا كبديل عن CVSS.

- لا توجد أوزان لمستوى `sub_category` في v1.1: الحقل محجوز ولا يغيّر النتيجة —
  «لا نخترع أوزاناً» (قرار المرحلة 4).
- المصدر الفعلي للقراءة: `context_params.masvs_weights`، مع جدول احتياط مطابق في الكود.

## ب-3) معاملات السياق (`context_score`)

```
context_score = 5.0 + 0.4·data_sensitivity + 0.2·user_base_size
              + 0.2·internet_facing + 0.2·business_criticality      → قيد [1.0, 10.0]
```

| المعامل | الوزن | القيم |
|---|---|---|
| `data_sensitivity` | 0.4 | `LOW:3` · `MEDIUM:6` · `HIGH:10` |
| `user_base_size` | 0.2 | `small:4` · `medium:6` · `large:9` |
| `internet_facing` | 0.2 | `true:10` · `false:4` |
| `business_criticality` | 0.2 | `LOW:3` · `MEDIUM:6` · `HIGH:10` |

| الحالة | الناتج |
|---|---|
| أدنى سياق | `5 + 3×0.4 + 4×0.2 + 4×0.2 + 3×0.2` = **8.4** |
| سياق افتراضي | `5 + 2.4 + 1.2 + 2.0 + 1.2 = 11.8 → قيد` = **10.0** |
| أقصى سياق | `5 + 4 + 1.8 + 2 + 2 = 14.8 → قيد` = **10.0** |

المجال الحسابي 8.4–14.8 ⇒ بعد القيد **8.4–10**، أي أن أثر السياق الأقصى في
الدرجة النهائية = `0.2 × 1.6 = 0.32` درجة. قرار معروف ومُعلَن (انظر ب-7).

## ب-4) سلالم عامل الثقة

| `tool_count` | القيمة | | `evidence_quality` | القيمة |
|---|---|---|---|---|
| 0 | 0.0 | | `none` | 0.0 |
| 1 | 0.4 | | `general` | 0.3 |
| 2 | 0.7 | | `raw` | 0.6 |
| ≥3 | 1.0 | | `specific` | 0.9 |
| | | | `code_and_repro` | 1.0 |

| `reproducibility` | القيمة | الشرط |
|---|---|---|
| `not_tested` | 0.0 | أداة واحدة ثابتة |
| `once` | 0.6 | ≥2 أدوات مستقلة |
| `twice` | 1.0 | `is_confirmed` (PoC ديناميكي) |

`tool_reliability` = متوسط موثوقيات الأدوات الراصدة (من جدول `tools`)؛
`evidence_quality` و`reproducibility` **تصنيفان حتميان** بقواعد نصية/منطقية، لا بنموذج لغوي.

## ب-5) عتبات الفئات والمسافة الحدّية

| الفئة | المدى | المُشغِّل |
|---|---|---|
| Critical | 9.0 – 10.0 | `score ≥ 9.0` |
| High | 7.0 – 8.9 | `score ≥ 7.0` |
| Medium | 4.0 – 6.9 | `score ≥ 4.0` |
| Low | 0.0 – 3.9 | ما دونها |

`distance_to_band_edge(s) = min(|s − حد|)` لأقرب حد بين فئتين، مع ضمّ `10.0`
(مثال: `8.6 → 0.4`). تُستخدم في معيار «المنطقة الحدّية» للتصعيد البشري.

## ب-6) قواعد المراجعة الثمانية (حرفية من `agents/reviewer.py`)

المجموع المطبَّق يُقيَّد في `[1.0, 10.0]`، و`final_severity` يُعاد تصنيفه
**فقط** إذا وُجد تعديل واحد على الأقل.

| # | المعرّف | الشرط | التعديل | السبب (نص عربي كما في الكود) |
|---|---|---|---|---|
| R1 | `R1-weak-evidence-critical` | `Critical` ∧ `evidence < 5` | −1.5 | أدلة ضعيفة لا تكفي لاعتماد Critical |
| R2 | `R2-strong-evidence-low` | `Low` ∧ `evidence > 8` | +1.5 | أدلة قوية جداً تتعارض مع Low |
| R3 | `R3-high-context-low` | `context > 8` ∧ `Low` | +1.0 | سياق شديد الحساسية يستبعد Low |
| R4 | `R4-low-context-critical` | `context < 4` ∧ `Critical` | −1.0 | سياق منخفض الحساسية لا يسوّغ Critical |
| R5 | `R5-crypto-medium-floor` | `MASVS-CRYPTO` ∧ `Medium` | +1.0 | تصنيف تشفير «متوسط» مُحجَّم تقليدياً |
| R6 | `R6-code-quality-critical-cap` | `MASVS-CODE` ∧ `Critical` | −1.0 | جودة الكود نادراً تستحق Critical |
| R7 | `R7-low-confidence-critical` | `confidence < 0.4` ∧ `Critical` | −1.0 | ثقة منخفضة لا تدعم Critical |
| R8 | `R8-high-confidence-low` | `confidence > 0.9` ∧ `Low` | +0.5 | ثقة عالية جداً على Low تستدعي رفعاً طفيفاً |

**معايير التصعيد البشري الثلاثة** (`needs_human_review`):

| المعيار | العتبة |
|---|---|
| ثقة < عتبة المراجعة | `confidence < 0.75` |
| منطقة حدّية | `distance_to_band_edge(score) ≤ 0.5` |
| Critical هشّ | `Critical` ∧ `confidence < 0.90` |

## ب-7) نتيجة تحليل الشمولية — الفجوة المُقاسة والمُعلَنة

شُغِّل مسح استنزافي (144 تركيبة = 8 فئات × 6 سيناريوهات أدلة × 3 سياقات) عبر
المحرك نفسه: `python scripts/reachability_report.py` → **`results/reachability.md`**.

| الفئة | مُتاحة؟ | السبب البنيوي |
|---|---|---|
| Critical | نعم (7 حالات) | تحتاج `evidence ≥ 8` |
| High | نعم (71) | — |
| Medium | نعم (66) | — |
| **Low** | **لا (0)** | `final ≥ 0.6×4.0 + 0.2×8.4 + 0.2×3.0 = 4.68` ⇒ Medium على الأقل |

مدى الدرجة الفعلي: **[4.68 … 9.3394]** بدل [0 … 10]. ونتيجة مباشرة: **لا تُطلق أي
من القواعد R1–R8 تلقائياً** على مُخرَجات المحرك (مثال: R1 تشترط `evidence < 5`
بينما أي `Critical` يستلزم `evidence ≥ 8`). القواعد:

1. **منفَّذة ومُختبرة** (8/8 لها اختبار في `tests/unit/test_reviewer.py`)،
2. تعمل كـ**حواجز نطاق (range guards)** تحمي عند معايرة الأوزان في v2،
3. وتظلّ **موثّقة كخامدة في v1.1** — لا تُخفى ولا تُدّعى فعالية غير قائمة.

المعالجة الكاملة (إحياء القواعد عبر معايرة الأرضيات والأوزان) في
`limitations_and_future_work.md` §2.1.

## ب-8) مثال حسابي مركّز (تحقّق يدوي كامل)

ثغرة `MASVS-CRYPTO` — مفتاح AES صلب في الكود، رصدتها `jadx` و`mobsf`، مؤكَّدة
ديناميكياً، وسياق `HIGH/large/true/HIGH`:

| الخطوة | الحساب | الناتج |
|---|---|---|
| base | جدول ب-2 | 9.0 |
| context | `5 + 10×0.4 + 9×0.2 + 10×0.2 + 10×0.2` | 10.0 (بعد القيد) |
| tool_count | أداتان | 0.7 |
| evidence_quality | كود مشخّص + تأكيد | `code_and_repro` = 1.0 |
| reliability | `(0.85+0.80)/2` | 0.825 |
| reproducibility | `is_confirmed` | `twice` = 1.0 |
| confidence | `0.4×0.7 + 0.3×1.0 + 0.2×0.825 + 0.1×1.0` | 0.845 |
| evidence | `3.0 + 7.0×0.845` | 8.915 |
| final | `0.6×9.0 + 0.2×10.0 + 0.2×8.915` | **9.183** |
| severity | `9.183 ≥ 9.0` | **Critical** |
| المراجعة | لا قاعدة تنطبق | `adjustments = []`, `reviewed = 9.183` |
| التصعيد البشري | حدّية 0.183 ≤ 0.5 ∧ Critical بثقة 0.845 < 0.9 | **True** |

هذه الأرقام قابلة لإعادة الإنتاج حرفياً: شغّل `pytest tests/unit/test_scoring_engine.py -q`.

## ب-9) حُكْم الإصدارات (Versioning)

| البند | v1.0 | v1.1 (النشط) |
|---|---|---|
| `masvs_weights` في `context_params` | غائب (يُقرأ من جدول الكود الاحتياطي) | **مضمَّن** (7 أوزان + فئة مجهولة 5.0) |
| `thresholds.confidence` | `{review_threshold, critical_min}` | يضيف `review` (اسم بديل متوافق) |
| الأوزان 0.6/0.2/0.2 | نفسها | نفسها |
| الأثر | نفس النتائج حسابياً | نفس النتائج + مصدر بيانات صريح |

قاعدة الإصدار: **أي تغيير في أي وزن أو عتبة ⇒ صف `severity_rules` جديد**؛
التقييمات المخزَّنة تحمل `rule_version`، فلا تتغيّر نتائج قديمة عند إعادة القراءة.

## ب-10) خريطة التتبّع (رقم ← كود ← اختبار)

| الرقم | الكود | الاختبار |
|---|---|---|
| أوزان الفئات | `core/scoring/base_score.py` | `test_scoring_engine.py::TestBaseScore` |
| معاملات السياق | `core/scoring/context_score.py` | `…::TestContextScore` |
| سلالم الثقة | `core/scoring/confidence.py` | `…::TestConfidence` |
| نقاط الأدلة | `core/scoring/evidence_score.py` | `…::TestEvidenceScore` |
| العتبات والمسافة | `core/scoring/bands.py` | `…::TestBands` |
| القواعد الثمانية | `agents/reviewer.py::REVIEW_RULES` | `test_reviewer.py::TestReviewRules` |
| معايير التصعيد | `agents/reviewer.py::needs_human_review` | `…::TestHumanReviewCriteria` |
| الشمولية | `scripts/reachability_report.py` | `results/reachability.md` |
