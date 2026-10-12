#!/usr/bin/env python
"""تقرير شمولية محرك التقييم / Scoring reachability report (المرحلة 8).

    python scripts/reachability_report.py

يجيب سؤالاً تحليلياً للأطروحة: **ما الفئات التي يستطيع المحرك إنتاجها فعلاً،
وما مدى درجات كل فئة، وهل تُطلق قواعد المراجعة الثمانية من تلقائها؟**

الطريقة: مسح **استنزافي** لكل تركيبات (فئة MASVS × سيناريو أدلة × سياق تطبيق)
عبر محرك التقييم الحتمي نفسه (`core/scoring/engine.py` + `agents/reviewer.py`)،
بلا أي عشوائية وبلا نموذج لغوي — فالنتيجة خاصية رياضية للنظام لا قياس تجربة بشرية.

المخرجات: `results/reachability.md` (جدول + خلاصة) و`results/reachability.json`
(البيانات الخام لإعادة الرسم). **تُعلَن الحدود:** هذا تحليل بنيوي لمدى القيم، وليس
نتيجة جودة مقابل حقيقة مرجعية.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import product
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.reviewer import REVIEW_RULES, apply_review_rules  # noqa: E402
from agents.scorer import load_active_rule_cached  # noqa: E402
from core.scoring.bands import SEVERITY_BANDS  # noqa: E402
from core.scoring.confidence import calculate_confidence_factor  # noqa: E402
from core.scoring.engine import ScoringEngine  # noqa: E402

OUT_MD = PROJECT_ROOT / "results" / "reachability.md"
OUT_JSON = PROJECT_ROOT / "results" / "reachability.json"

CATEGORIES = [
    "MASVS-CRYPTO", "MASVS-STORAGE", "MASVS-NETWORK", "MASVS-AUTH",
    "MASVS-PLATFORM", "MASVS-RESILIENCE", "MASVS-CODE", "UNKNOWN-CATEGORY",
]
# سيناريوهات الأدلة: (عدد الأدوات المستقلة، دليل مشخّص؟، مُؤكَّد ديناميكياً؟)
EVIDENCE_SCENARIOS = [
    (0, False, False, "بلا أدوات ولا دليل"),
    (1, False, False, "أداة واحدة — وصف عام"),
    (1, True, False, "أداة واحدة — دليل مشخّص"),
    (2, True, False, "أداتان — دليل مشخّص"),
    (2, True, True, "أداتان — كود + تأكيد ديناميكي"),
    (3, True, True, "ثلاث أدوات — كود + تأكيد"),
]
CONTEXTS = [
    ({"data_sensitivity": "LOW", "user_base_size": "small", "internet_facing": False, "business_criticality": "LOW"}, "أدنى سياق"),
    ({"data_sensitivity": "MEDIUM", "user_base_size": "medium", "internet_facing": True, "business_criticality": "MEDIUM"}, "سياق افتراضي"),
    ({"data_sensitivity": "HIGH", "user_base_size": "large", "internet_facing": True, "business_criticality": "HIGH"}, "أقصى سياق"),
]
TOOL_RELIABILITIES = {"jadx": 0.85, "mobsf": 0.80, "frida": 0.70, "objection": 0.75}


def run_sweep() -> dict[str, Any]:
    """ينفّذ المسح الاستنزافي ويعيد البيانات الخام + الملخصات."""
    rule = load_active_rule_cached()
    engine = ScoringEngine(rule)

    severity_counts: Counter[str] = Counter()
    rule_firings: Counter[str] = Counter()
    per_category: dict[str, dict[str, float]] = defaultdict(lambda: {"min": 99.0, "max": 0.0})
    finals: list[float] = []
    combinations = 0

    for category, (tool_count, has_code, confirmed, _label), (context, _ctx_label) in product(
        CATEGORIES, EVIDENCE_SCENARIOS, CONTEXTS
    ):
        discovered = ["jadx", "mobsf", "frida"][:tool_count]
        vuln: dict[str, Any] = {
            "title": "حالة مسح",
            "masvs_category": category,
            "discovered_by": discovered,
            "is_confirmed": confirmed,
        }
        if has_code:
            vuln["evidence_by_tool"] = {
                tool: f'String key = "…"; // MainActivity.java:42 (tool={tool})' for tool in discovered
            }
        elif discovered:
            vuln["evidence_by_tool"] = {tool: "وصف عام بلا مقتطف كود" for tool in discovered}

        result = engine.score(vuln, context, TOOL_RELIABILITIES)
        combinations += 1
        finals.append(result["final_score"])
        severity_counts[result["severity"]] += 1
        stats = per_category[category]
        stats["min"] = min(stats["min"], result["final_score"])
        stats["max"] = max(stats["max"], result["final_score"])

        # هل يُطلق قرار المراجعة الحتمي أي قاعدة على هذه الحالة؟
        review = apply_review_rules({**result, "masvs_category": category})
        for adjustment in review["adjustments"]:
            rule_firings[adjustment["rule_id"]] += 1

    confidence_values = sorted(
        {
            calculate_confidence_factor(tool_count, quality, 0.85, repro)
            for tool_count in (0, 1, 2, 3)
            for quality in ("none", "general", "raw", "specific", "code_and_repro")
            for repro in ("not_tested", "once", "twice")
        }
    )

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "rule_version": rule.get("version", "?"),
        "combinations": combinations,
        "final_min": round(min(finals), 4),
        "final_max": round(max(finals), 4),
        "severity_counts": dict(severity_counts),
        "reachable_bands": sorted(severity_counts, key=lambda s: SEVERITY_BANDS.get(s, (0, 0))[0], reverse=True),
        "unreachable_bands": [band for band in SEVERITY_BANDS if band not in severity_counts],
        "per_category": {cat: {"min": round(v["min"], 4), "max": round(v["max"], 4)} for cat, v in per_category.items()},
        "rules_defined": [r["id"] for r in REVIEW_RULES],
        "rules_fired": dict(rule_firings),
        "dormant_rules": [r["id"] for r in REVIEW_RULES if r["id"] not in rule_firings],
        "confidence_values": confidence_values,
        "context_floor_note": "أدنى context_score = 8.4 وأدنى evidence_score = 3.0 (الأرضيات تُرفع الحد الأدنى للدرجة النهائية)",
    }


def render_markdown(data: dict[str, Any]) -> str:
    """يبني تقرير Markdown من بيانات المسح."""
    lines = [
        "# تقرير شمولية محرك التقييم / Scoring Reachability Report",
        "",
        f"- **وُلِّد آلياً:** {data['generated_at']} بواسطة `scripts/reachability_report.py`",
        f"- **إصدار قاعدة التقييم:** `{data['rule_version']}`",
        f"- **عدد التركيبات الممسوحة:** {data['combinations']} (استنزافي: فئة × أدلة × سياق)",
        f"- **مدى الدرجة النهائية الفعلي:** [{data['final_min']} .. {data['final_max']}] من أصل [0 .. 10]",
        "",
        "> **نوع هذا التقرير:** تحليل **بنيوي** لقدرة المحرك الحتمي على إنتاج الفئات،",
        "> وليس قياس جودة مقابل حقيقة مرجعية. لا يُقرأ كبديل عن نتائج التجربة (المعلّقة",
        "> على تعبئة `filled:false`).",
        "",
        "## 1) الفئات القابلة للوصول (نتيجة مباشرة للمسح)",
        "",
        "| الفئة | عدد الحالات في المسح | مُتاحة؟ |",
        "|---|---|---|",
    ]
    for band in ("Critical", "High", "Medium", "Low"):
        count = data["severity_counts"].get(band, 0)
        lines.append(f"| {band} | {count} | {'نعم' if count else '**لا**'} |")

    lines += [
        "",
        "**الخلاصة (١):** الفئة `Low` **غير قابلة للوصول** في إصدار القاعدة الحالي:",
        f"أدنى درجة يمكن إنتاجها هي **{data['final_min']}** لأن `context_score` له أرضية",
        "8.4 و`evidence_score` له أرضية 3.0، وأدنى وزن فئة معروفة 4.0 (MASVS-CODE).",
        "الناتج أدنى قيمة = 0.6·4 + 0.2·8.4 + 0.2·3.0 = 4.68 ⇒ «Medium» على الأقل.",
        "",
        "## 2) مدى الدرجة لكل فئة MASVS",
        "",
        "| الفئة | أدنى درجة في المسح | أقصى درجة في المسح | الفئات المُنتَجة |",
        "|---|---|---|---|",
    ]
    for category, stats in data["per_category"].items():
        produced = sorted(
            {band for band, (lo, hi) in SEVERITY_BANDS.items() if lo <= stats["max"] and hi >= stats["min"]},
            key=lambda b: SEVERITY_BANDS[b][0],
            reverse=True,
        )
        lines.append(f"| `{category}` | {stats['min']} | {stats['max']} | {' · '.join(produced)} |")

    lines += [
        "",
        "## 3) قواعد المراجعة الثمانية: معرَّفة مقابل فعّالة",
        "",
        "كل القواعد الثمانية **منفَّذة ومُختبرة** (`agents/reviewer.py`, `tests/unit/test_reviewer.py`)،",
        "لكن السؤال التحليلي: هل تُطلق قواعد من تلقائها عند إدخال أي تقييم قابل للإنتاج؟",
        "",
        "| القاعدة | أُطلقت في المسح؟ | التفسير البنيوي |",
        "|---|---|---|",
    ]
    reasons = {
        "R1-weak-evidence-critical": "`Critical` مشروط بـ `final ≥ 9` ⇒ `evidence ≥ 8` ⇒ لا يمكن أن يكون `< 5`",
        "R2-strong-evidence-low": "`Low` غير قابل للوصول أصلاً (شرط لازم ساقط)",
        "R3-high-context-low": "`Low` غير قابل للوصول أصلاً",
        "R4-low-context-critical": "يدخل بـ `context < 4` و`context_score` له أرضية 8.4",
        "R5-crypto-medium-floor": "لا يمكن أن يقع CRYPTO في Medium: أدنى درجة له 7.68 ⇒ High على الأقل",
        "R6-code-quality-critical-cap": "لا يمكن أن يقع CODE في Critical: أقصى درجة له 6.34",
        "R7-low-confidence-critical": "`Critical` مشروط بـ `evidence ≥ 8` ⇒ `confidence ≥ 0.714` ⇒ لا يمكن أن يكون `< 0.4`",
        "R8-high-confidence-low": "`Low` غير قابل للوصول أصلاً",
    }
    for rule_id in data["rules_defined"]:
        fired = rule_id in data["rules_fired"]
        lines.append(f"| `{rule_id}` | {'نعم' if fired else '**لا**'} | {reasons.get(rule_id, '—')} |")

    lines += [
        "",
        "**الخلاصة (٢):** في إصدار القاعدة الحالي، **لا تُطلق أي من القواعد الثمانية**",
        "على التقييمات التي يولّدها المحرك — لأن قيم المكوّنات التي تنتج عنها الفئات",
        "تقع خارج الشروط التي كُتبت القواعد لأجلها. هذا **لا يعني موت طبقة المراجعة**،",
        "بل يعني أنها تعمل كـ **شبكة أمان للتحقق من النطاق (range guards)**: تحمي من",
        "تغيّر أوزان الفئات أو أرضيات المكوّنات في إصدارات قادمة، ومختبرة على مدخلات",
        "اصطناعية لذلك الغرض. الإصلاح المقترح v2 موثّق في",
        "`docs/thesis/limitations_and_future_work.md` (معايرة الأرضيات لتفعيل المدى الكامل).",
        "",
        "## 4) قيم عامل الثقة الممكنة",
        "",
        f"- عدد القيم الفريدة الممكنة: **{len(data['confidence_values'])}** بمدى "
        f"[{data['confidence_values'][0]} .. {data['confidence_values'][-1]}]",
        "- المدخلات الثلاثة عشرة ({0,1,2,3+} × {none..code_and_repro} × {not_tested,once,twice})",
        "  تُنتج شبكة قيم منفصلة لا سلّماً متصلاً — مفيد للتفسير: العتبات (0.75 / 0.9)",
        "  تقع بين قيم شبكة معروفة، فلا يوجد «قريب من العتبة» بلا معنى.",
        "",
        "## 5) كيف تُعاد هذه النتائج؟",
        "",
        "```bash",
        "python scripts/reachability_report.py     # يُعيد توليد .md و .json",
        "```",
        "",
        "البيانات الخام (لكل تركيبة) محفوظة في `results/reachability.json`.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    """يشغّل المسح ويكتب المخرجين (md + json)."""
    data = run_sweep()
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(render_markdown(data), encoding="utf-8")
    OUT_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✅ {OUT_MD.relative_to(PROJECT_ROOT)}")
    print(f"✅ {OUT_JSON.relative_to(PROJECT_ROOT)}")
    print(
        f"   تركيبات={data['combinations']} · مدى=[{data['final_min']}..{data['final_max']}] · "
        f"فئات={data['severity_counts']} · قواعد أُطلقت={data['rules_fired'] or 'لا شيء'}"
    )


if __name__ == "__main__":
    main()
