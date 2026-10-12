"""تحليل حلقة التغذية الراجعة (A/B) — المرحلة 7.

    python evaluation/analyze_feedback.py \
        --exclude-corrections 20 \
        --post-out results/feedback_ab_test.md

المبدأ: أول 20 تصحيحاً بشرياً = فترة «التأسيس» (خارج الاختبار):
    • الفوج A = تصحيحات ما قبل العتبة تعمل **بلا** few-shot
      (التقييم الأصلي قبل التصحيح = سلوك no_feedback).
    • الفوج B = تصحيحات ما بعد العتبة عملت **مع** few-shot
      (منها استُخرجت أمثلة قياسية — انظر Correction.is_example / retriever).

القياس (protocol.md §5-RQ5): Percent Agreement + Weighted κ (تربيعي) لكل فوج،
ثم اختبار مزدوج على الفروق: paired t-test + Wilcoxon signed-rank + Cohen's d.
نموذج «الزوج الموحّد»: بعد ترقيم التصحيحات زمنياً، نطابق التصحيحات حسب
الموضع cnt→cnt (المنطق: التصحيح رقم i قبل/بعد العتبة يقيس نفس الموضع النسبي).

★ بلا اختراع: إن كان الجدول فارغاً أو الفوج B < 3 تُطبع حالة «بيانات غير كافية»
  صراحةً ولا تُكتب أي قيمة إحصائية.
"""
from __future__ import annotations

import argparse
import json
import sys
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:  # يسمح باستيراد evaluation.metrics من أي cwd
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_EXCLUDE = 20
DEFAULT_OUTPUT = PROJECT_ROOT / "results" / "feedback_ab_test.md"
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def load_corrections() -> list[dict[str, Any]]:
    """قراءة التصحيحات البشرية زمنياً مع سياقها (assessment + الجدوى).

    ملاحظة: تصحيحات Phase 5 لا تحتوي عموداً صارخاً «هل كان few-shot مفعلاً»؛
    لذلك يُعتبر الفهرس الزمني هو المُميّز بدلالة العتبة (--exclude-corrections):
    ما قبل العتبة كان تشغيلاً تاريخياً بلا أمثلة (سلوك no_feedback)،
    وما بعدها كان مع أمثلة (منها استُخرجت أمثلة الحلقة).
    """
    from db.connection import get_session
    from db.models import Assessment, Correction, Vulnerability
    from sqlalchemy import select

    rows: list[dict[str, Any]] = []
    with get_session() as session:
        records = session.execute(
            select(Correction)
            .order_by(Correction.corrected_at.asc(), Correction.id.asc())
        ).scalars().all()
        for index, correction in enumerate(records, start=1):
            assessment = session.get(Assessment, correction.assessment_id)
            vulnerability = (
                session.get(Vulnerability, assessment.vulnerability_id)
                if assessment is not None and assessment.vulnerability_id is not None
                else None
            )
            rows.append(
                {
                    "index": index,
                    "correction_id": correction.id,
                    "original_severity": correction.original_severity,
                    "corrected_severity": correction.corrected_severity,
                    "is_example": bool(getattr(correction, "is_example", False)),
                    "corrected_at": str(correction.corrected_at),
                    "cwe_id": getattr(vulnerability, "cwe_id", None),
                    "title": getattr(vulnerability, "title", None),
                }
            )
    return rows


def build_cohorts(
    corrections: list[dict[str, Any]], exclude_first: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """فوج A (قبل العتبة = بلا أمثلة) وفوج B (بعد العتبة = مع أمثلة)."""
    cohort_a = corrections[:exclude_first]
    cohort_b = corrections[exclude_first:]
    return cohort_a, cohort_b


def cohort_agreement(cohort: list[dict[str, Any]]) -> dict[str, Any]:
    """مقاييس الاتفاق داخل فوج: نظام (original) مقابل بشري (corrected)."""
    from evaluation.metrics import (
        gwet_ac1,
        percent_agreement,
        weighted_cohens_kappa,
    )

    good = [row for row in cohort if row["original_severity"] and row["corrected_severity"]]
    if not good:
        return {"n": 0}
    left = [row["original_severity"] for row in good]
    right = [row["corrected_severity"] for row in good]
    return {
        "n": len(good),
        "percent_agreement": percent_agreement(left, right),
        "weighted_kappa": weighted_cohens_kappa(left, right),
        "gwet_ac1": gwet_ac1(left, right),
        "is_example_count": sum(1 for row in good if row["is_example"]),
    }


def _severity_ordinal(value: str | None) -> int | None:
    """تحويل الخطورة إلى ترتيب رقمي (وحدة الاختبار المزدوج: الخطوة لا الفئة)."""
    if value not in SEVERITY_ORDER:
        return None
    return SEVERITY_ORDER.index(value)


def paired_distances(cohort: list[dict[str, Any]]) -> list[float]:
    """مسافة كل تصحيح = |مرتبة النظام − مرتبة البشر| — قياس متصل للفوج."""
    distances: list[float] = []
    for row in cohort:
        left = _severity_ordinal(row["original_severity"])
        right = _severity_ordinal(row["corrected_severity"])
        if left is not None and right is not None:
            distances.append(float(abs(left - right)))
    return distances


def run_ab_test(
    cohort_a: list[dict[str, Any]], cohort_b: list[dict[str, Any]]
) -> dict[str, Any]:
    """الاختبار المزدوج: تباين الفوجين مقابل فرضية العدم (الفرق = 0)."""
    from evaluation.metrics import paired_test

    distances_a = paired_distances(cohort_a)
    distances_b = paired_distances(cohort_b)
    size = min(len(distances_a), len(distances_b))
    paired_a = distances_a[:size]
    paired_b = distances_b[:size]
    result: dict[str, Any] = {
        "paired_n": size,
        "mean_distance_pre": round(statistics.fmean(paired_a), 4) if paired_a else None,
        "mean_distance_post": round(statistics.fmean(paired_b), 4) if paired_b else None,
    }
    if size >= 3:
        paired = paired_test(paired_a, paired_b)
        result.update({f"paired_{key}": value for key, value in paired.items()})
    else:
        result["note"] = "الزوج المزدوج < 3 ملاحظات — لا اختبار استدلالي (protocol.md §5-RQ5)"
    return result


def build_report(
    corrections: list[dict[str, Any]],
    exclude_first: int,
    agreement_a: dict[str, Any],
    agreement_b: dict[str, Any],
    paired: dict[str, Any],
) -> str:
    """تقرير Markdown — بلا أرقام إن كانت البيانات غير كافية."""
    from evaluation.metrics import interpret_kappa

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# اختبار A/B لحلقة التغذية الراجعة (Phase 7 — RQ5)",
        f"\n**تاريخ التوليد:** {generated}",
        f"\n**إجمالي التصحيحات البشرية في القاعدة:** {len(corrections)}",
        f"**عتبة التأسيس المستثناة:** {exclude_first} تصحيحاً",
        "",
        "## الفوجان",
        f"- **A — بلا few-shot** (أول {min(exclude_first, len(corrections))} تصحيحاً): "
        "تقييم النظام في التشغيل الأصلي (قبل التصحيح) مقابل قرار الخبير.",
        "- **B — مع few-shot** (التصحيحات اللاحقة): التقييم في تشغيل استخدم أمثلة "
        "`feedback_examples` المستخرجة من تصحيحات الفوج A.",
        "",
        "## نتائج الاتفاق",
        "| الفوج | n | Percent Agreement | Weighted κ | Gwet's AC1 | (أمثلة مشتقة) |",
        "|---|---|---|---|---|---|",
    ]
    for label, state in (("A (بلا أمثلة)", agreement_a), ("B (مع أمثلة)", agreement_b)):
        if state.get("n"):
            lines.append(
                f"| {label} | {state['n']} | {state['percent_agreement']} | "
                f"{state['weighted_kappa']} | {state['gwet_ac1']} | "
                f"{state.get('is_example_count', 0)} |"
            )
        else:
            lines.append(f"| {label} | 0 | — | — | — | — |")

    if (agreement_a.get("n") or 0) < 3 or (agreement_b.get("n") or 0) < 3:
        lines.append(
            "\n> ℹ️ فوج بـ n<3: القيم المدوّنة أعلاه **إرشادية منحلّة** (قيم فردية) "
            "ولا تحمل دلالة إحصائية."
        )
    lines.append("\n## الاختبار المزدوج (على مسافة الخطورة |نظام − بشري|)")
    if paired.get("paired_n") and paired.get("paired_n", 0) >= 3:
        lines.append(
            "| المتغير | قيمة |\n|---|---|\n"
            f"| n المزدوج | {paired['paired_n']} |\n"
            f"| متوسط المسافة — A | {paired.get('mean_distance_pre')} |\n"
            f"| متوسط المسافة — B | {paired.get('mean_distance_post')} |\n"
            f"| فرق المتوسطات | {paired.get('paired_mean_diff')} |\n"
            f"| paired t — t | {paired.get('paired_t_stat')} |\n"
            f"| paired t — p | {paired.get('paired_t_pvalue')} |\n"
            f"| Wilcoxon — W | {paired.get('paired_wilcoxon_stat')} |\n"
            f"| Wilcoxon — p | {paired.get('paired_wilcoxon_pvalue')} |\n"
            f"| Cohen's d (مزدوج) | {paired.get('paired_cohens_d')} |"
        )
        effect = paired.get("paired_cohens_d")
        if effect is not None:
            if abs(effect) >= 0.8:
                size_text = "كبير"
            elif abs(effect) >= 0.5:
                size_text = "متوسط"
            elif abs(effect) >= 0.2:
                size_text = "صغير"
            else:
                size_text = "ضئيل"
            lines.append(f"\n> حجم الأثر (|d|={abs(effect)}): **{size_text}** — والمتوقع أن "
                         "يكون سالباً (قرب النظام من البشر يزيد مع الأمثلة ⇒ تنقص المسافة).")
    else:
        lines.append(
            f"> ⚠️ **بيانات غير كافية للاختبار المزدوج** — "
            f"n={paired.get('paired_n', 0)} (الحد الأدنى 3). "
            "شغّل حلقة المراجعة البشرية حتى ≥ 20 + 3 تصحيحات ثم أعد التحليل."
        )

    lines.append("\n## تفسير κ (Landis & Koch)")
    for label, state in (("A", agreement_a), ("B", agreement_b)):
        if state.get("weighted_kappa") is not None:
            lines.append(f"- الفوج {label}: κ={state['weighted_kappa']} ⇒ "
                         f"«{interpret_kappa(state['weighted_kappa'])}»")

    lines.append(
        "\n## قيود صريحة\n"
        "- الفصل A/B هنا تاريخي (زمني) لا عشوائي: يُقرأ كدليل تمهيدي لا كتجربة "
        "معشاة — انظر protocol.md §7.\n"
        "- عدد التصحيحات البشري الحقيقي هو العامل المحدد؛ لا نتائج مصطنعة.\n"
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    """CLI: يبني الفوجين، يقيس، يختبر، ويكتب التقرير ( أو حالته الصريحة)."""
    parser = argparse.ArgumentParser(description="A/B لحلقة التغذية الراجعة")
    parser.add_argument("--exclude-corrections", type=int, default=DEFAULT_EXCLUDE)
    parser.add_argument("--post-out", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    try:
        corrections = load_corrections()
    except Exception as exc:  # قاعدة غير مهيأة — تقرير حالة لا انهيار
        Path(args.post_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.post_out).write_text(
            "# اختبار A/B لحلقة التغذية الراجعة\n\n"
            f"> ⚠️ تعذّرت قراءة قاعدة البيانات: {exc}\n",
            encoding="utf-8",
        )
        print(f"⚠️  تعذّرت القراءة ({exc}) — كُتب تقرير حالة")
        return

    cohort_a, cohort_b = build_cohorts(corrections, args.exclude_corrections)
    agreement_a = cohort_agreement(cohort_a)
    agreement_b = cohort_agreement(cohort_b)
    paired = run_ab_test(cohort_a, cohort_b)

    report = build_report(corrections, args.exclude_corrections, agreement_a, agreement_b, paired)
    output = Path(args.post_out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")

    # ملخص JSON آلي للواجهة
    output.with_name("feedback_ab_test.json").write_text(
        json.dumps(
            {
                "total_corrections": len(corrections),
                "excluded": args.exclude_corrections,
                "cohort_a": agreement_a,
                "cohort_b": agreement_b,
                "paired": paired,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"✅ التصحيحات: {len(corrections)} | فوج A: {agreement_a.get('n', 0)} | "
          f"فوج B: {agreement_b.get('n', 0)}")
    print(f"✅ التقرير: {output}")
    if not agreement_b.get("n"):
        print("⚠️  لا تصحيحات بعد العتبة — الاختبار المزدوج غير متاح (بيانات غير كافية)")


if __name__ == "__main__":
    main()
