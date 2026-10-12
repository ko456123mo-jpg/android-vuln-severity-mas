# خطوط الهوية — لأغراض إعادة التوليد فقط / Brand fonts (regeneration only)

هذه الخطوط **ليست جزءاً من الشعار المُصدَّر**: كل النصوص في ملفات SVG محوّلة إلى
**مسارات متجهية** (`scripts/build_logo.py` ← `text_to_path`). الخطوط موجودة هنا فقط
لإعادة توليد الشعار بوزن وحجم مختلفين، وكلها بترخيص **SIL Open Font License 1.1**
(يسمح بالاستخدام والتعديل والتوزيع مع إبقاء الإسناد).

| الملف | العائلة | الوزن المستخدم | المصدر (Google Fonts · OFL 1.1) |
|---|---|---|---|
| `SpaceGrotesk.ttf` | Space Grotesk | 700 (اسم المشروع) | `github.com/google/fonts/ofl/spacegrotesk` |
| `JetBrainsMono.ttf` | JetBrains Mono | 500/600 (الشعاري والأقواس) | `github.com/google/fonts/ofl/jetbrainsmono` |
| `Inter.ttf` | Inter | 400/600 (مستندات/واجهات) | `github.com/google/fonts/ofl/inter` |
| `Cairo.ttf` | Cairo | 400/600/700 (كل النص العربي) | `github.com/google/fonts/ofl/cairo` |

ملاحظات:
- الملفات المذكورة أعلاه بخطوط **متغيّرة (Variable)**؛ السكربت يثبّت الوزن المطلوب
  عبر `fontTools.varLib.instancer` قبل التحويل إلى مسارات.
- الخطوط العربية (Cairo) تُستخدم في الواجهة والمستندات، **ولا** تُحضَّر في الشعار
  (تفادياً لمشكلات Bidi في مُصيّرات المتجهات) — انظر `BRAND_GUIDE.md` §4.
- لإضافة وزن جديد: عدّل معامل `weight` في نداء `text_to_path` وأعد التوليد:

```bash
python scripts/build_logo.py     # يعيد بناء كل ملفات الهوية بما فيها الأطروحة
```
