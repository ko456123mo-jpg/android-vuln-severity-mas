# نتائج القياس / Generated Results

هذا المجلد مخصّص لمخرجات القياس والتجربة. **معظم محتواه مُولَّد ولا يُرفع إلى Git**
(انظر `.gitignore`)، باستثناء ملفات قليلة مُثبَّتة عمداً حتى تكون الأرقام المذكورة
في `README.md` **قابلة للتحقق**.

## الملفات المُثبَّتة (مُتتبَّعة في Git)

| الملف | المصدر | لماذا مُثبَّت |
|---|---|---|
| `reachability.md` | `python scripts/reachability_report.py` | README يستشهد بمدى الدرجات `[4.68 … 9.34]` وغياب فئة `Low` — التقرير هو الدليل |
| `reachability.json` | نفس السكربت | البيانات الخام لإعادة الرسم والتدقيق |

## إعادة التوليد

```bash
python scripts/reachability_report.py     # → reachability.md + reachability.json
```

المسح استنزافي (144 تركيبة) عبر المحرك الحتمي نفسه، بلا عشوائية وبلا نموذج لغوي —
أي أن النتيجة **خاصية رياضية للنظام**، ويجب أن تتطابق حرفياً عند إعادة التشغيل.

## الملفات غير المُثبَّتة (تُولَّد محلياً)

| الملف | الأمر |
|---|---|
| `benchmark.md` | `python scripts/benchmark.py` |
| `load_test.md` | `python scripts/load_test.py` |
| `final_checklist.md` | `python scripts/final_checklist.py` |
| `*.json` (تقارير المراحل) | `evaluation/run_experiment.py` |

> **ملاحظة منهجية:** لا يُنشر أي رقم جودة قبل تعبئة الحقيقة المرجعية (Ground Truth)
> يدوياً. النظام مهندَس ليقول **«غير معلوم»** بدل أن يخمّن — وهذا مقصود.
