# تقرير توليد الرسوم (Mermaid → SVG/PNG)

- الأدوات: mermaid-cli عبر /usr/bin/npx --yes @mermaid-js/mermaid-cli
- الصيغة المطلوبة: png
- المصادر: `docs/thesis/figures/*.mmd` (5 رسوم)

| الرسم | المصدر | الحالة | التفصيل |
|---|---|---|---|
| architecture | architecture.mmd | ✓ | architecture.png (106,856 بايت) |
| dataflow | dataflow.mmd | ✓ | dataflow.png (28,910 بايت) |
| state_machine | state_machine.mmd | ✓ | state_machine.png (192,034 بايت) |
| scoring_flow | scoring_flow.mmd | ✓ | scoring_flow.png (531,088 بايت) |
| db_erd | db_erd.mmd | ✓ | db_erd.png (164,251 بايت) |

## كيف تُنتج SVG على جهازك
```bash
# الطريقة 1 — mermaid-cli مباشرة (يحتاج Node + Chromium)
npm install -g @mermaid-js/mermaid-cli
python scripts/render_diagrams.py --format svg

# الطريقة 2 — npx بلا تثبيت دائم
npx --yes @mermaid-js/mermaid-cli -i docs/thesis/figures/architecture.mmd \
    -o docs/thesis/figures/architecture.svg -b white

# الطريقة 3 — VS Code: إضافة Markdown Preview Mermaid Support
#             ثم افتح docs/thesis/figures/preview_*.md وصدّر الرسم
```

> الرسوم مصممة للطباعة بالأبيض والأسود: تعتمد الصناديق والنصوص (labels) لا الألوان المميزة، ويُذكر كل رقم/معادلة داخل الشكل نفسه.
