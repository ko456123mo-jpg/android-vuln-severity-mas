"""تحليل نتائج التجربة / Results analysis (المرحلة 7).

    python evaluation/analyze_results.py --input results/ --output results/REPORT.md

يقرأ كل <input>/<mode>/<app_id>.json (خام) ويُنتج:
    • results/summary.json   — ملخص آلي للواجهة (Streamlit)
    • results/figures/*.html — رسوم Plotly (PRF لكل تطبيق، مصفوفة التباس،
                                Kappa/AC1 مع فترات الثقة، منحنى التعلم)
    • REPORT.md              — تقرير Markdown بالجداول والاستشهادات

★ بلا اختراع: عند غياب الحقيقة المرجعية تُطبع صراحةً «غير مُملأة» ولا تُحسب
   أي قيمة مبدلة؛ ومع غياب ملفات النتائج يُكتب تقرير «شغّل التجربة أولاً».
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:  # يسمح باستيراد evaluation.metrics من أي cwd
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_INPUT = PROJECT_ROOT / "results"
DEFAULT_OUTPUT = PROJECT_ROOT / "results" / "REPORT.md"

MODE_LABELS = {
    "full": "الكامل (RAG + Reviewer + Few-Shot)",
    "scorer_only": "بلا Reviewer (RQ3)",
    "no_rag": "بلا RAG (RQ4)",
    "no_feedback": "بلا Few-Shot (RQ5)",
    "dry_run": "تشغيل جاف (Mock — سباكة فقط)",
}


# ---------------------------------------------------------------------
# التجميع
# ---------------------------------------------------------------------
def collect_runs(input_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """قراءة كل ملفات JSON الخام مجمّعة بالوضع."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(input_dir.rglob("*.json")):
        if path.name in ("summary.json", "feedback_ab_test.json"):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        mode = payload.get("mode") or path.parent.name
        grouped.setdefault(mode, []).append(payload)
    return grouped


def compute_mode_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """ملخص وضع واحد: اكتشاف + اتفاق + بووتستراب + ماكرو F1."""
    from evaluation.metrics import (
        bootstrap_ci,
        gwet_ac1,
        percent_agreement,
        weighted_cohens_kappa,
    )

    filled_runs = [r for r in runs if r.get("ground_truth_filled")]
    detection_rows = []
    for run in filled_runs:
        detection = (run.get("metrics") or {}).get("detection") or {}
        detection_rows.append({"app_id": run["app_id"], **detection})
    macro_f1 = (
        round(sum(row["f1"] for row in detection_rows) / len(detection_rows), 4)
        if detection_rows
        else None
    )

    # اتفاق مجمّع: الأزواج الخام (نظام، خبير) كما سجّلها run_experiment عند توفر GT
    pooled: list[tuple[str, str]] = []
    for run in filled_runs:
        pooled.extend(_pairs_from_run(run))

    agreement: dict[str, Any] = {}
    ci: dict[str, Any] = {}
    if pooled:
        left = [a for a, _ in pooled]
        right = [b for _, b in pooled]
        agreement = {
            "n_pairs": len(pooled),
            "percent_agreement": percent_agreement(left, right),
            "weighted_kappa": weighted_cohens_kappa(left, right),
            "gwet_ac1": gwet_ac1(left, right),
        }
        ci = {
            "weighted_kappa_ci95": bootstrap_ci(
                pooled,
                lambda sample: weighted_cohens_kappa(
                    [a for a, _ in sample], [b for _, b in sample]
                ),
            ),
            "gwet_ac1_ci95": bootstrap_ci(
                pooled, lambda sample: gwet_ac1([a for a, _ in sample], [b for _, b in sample])
            ),
            "percent_agreement_ci95": bootstrap_ci(
                pooled,
                lambda sample: percent_agreement([a for a, _ in sample], [b for _, b in sample]),
            ),
        }
    if macro_f1 is not None and detection_rows:
        f1_values = [row["f1"] for row in detection_rows]
        ci["macro_f1_ci95_across_apps"] = bootstrap_ci(f1_values, lambda s: sum(s) / len(s))

    return {
        "mode": runs[0].get("mode") if runs else None,
        "apps_total": len(runs),
        "apps_ground_truth_filled": len(filled_runs),
        "detection_per_app": detection_rows,
        "macro_f1": macro_f1,
        "agreement": agreement,
        "ci": ci,
        "runs": [
            {
                "app_id": r["app_id"],
                "counts": r.get("counts"),
                "duration_ms": r.get("duration_ms"),
                "pipeline_stage": r.get("pipeline_stage"),
                "ground_truth_filled": r.get("ground_truth_filled"),
            }
            for r in runs
        ],
    }


def _pairs_from_run(run: dict[str, Any]) -> list[tuple[str, str]]:
    """أزواج الاتفاق مخزّنة في JSON الخام (يضيفها run_experiment عند توفر GT)."""
    return [tuple(pair) for pair in (run.get("matched_pairs") or [])]  # type: ignore[misc]


# ---------------------------------------------------------------------
# الرسوم البيانية (Plotly → HTML دائماً؛ PNG عند توفر kaleido)
# ---------------------------------------------------------------------
def _write_figure(figure: Any, path_html: Path) -> str:
    """يحفظ الرسم HTML ويعيد المسار النسبي (وبمحاولة PNG اختيارية)."""
    path_html.parent.mkdir(parents=True, exist_ok=True)
    figure.write_html(str(path_html), include_plotlyjs="cdn")
    try:  # PNG اختياري (يحتاج kaleido — غير إلزامي)
        figure.write_image(str(path_html.with_suffix(".png")), scale=2)
    except Exception:
        pass
    return path_html.name


def build_figures(summaries: dict[str, dict[str, Any]], figures_dir: Path) -> list[str]:
    """يبني الرسوم المتوفرة حسب البيانات، ويعيد أسماء ملفات HTML."""
    import plotly.graph_objects as go  # noqa: PLC0415

    created: list[str] = []
    primary = summaries.get("full") or next(iter(summaries.values()), None)
    if primary is None:
        return created

    rows = primary["detection_per_app"]
    if rows:
        figure = go.Figure(
            data=[
                go.Bar(name="Precision", x=[r["app_id"] for r in rows], y=[r["precision"] for r in rows]),
                go.Bar(name="Recall", x=[r["app_id"] for r in rows], y=[r["recall"] for r in rows]),
                go.Bar(name="F1", x=[r["app_id"] for r in rows], y=[r["f1"] for r in rows]),
            ]
        )
        figure.update_layout(barmode="group", title="Precision / Recall / F1 لكل تطبيق")
        created.append(_write_figure(figure, figures_dir / "prf_per_app.html"))

    return created


def build_figure_for_matrix(matrix: list[list[int]], figures_dir: Path) -> str:
    """خريطة حرارية لمصفوفة الالتباس 4×4."""
    import plotly.graph_objects as go  # noqa: PLC0415

    categories = ["Low", "Medium", "High", "Critical"]
    figure = go.Figure(
        go.Heatmap(
            z=matrix,
            x=[f"الخبير: {c}" for c in categories],
            y=[f"النظام: {c}" for c in categories],
            text=matrix,
            texttemplate="%{text}",
            colorscale="Reds",
        )
    )
    figure.update_layout(title="مصفوفة الالتباس (النظام × الخبير) — مجمّعة", height=420)
    return _write_figure(figure, figures_dir / "confusion_matrix.html")


def build_figure_for_agreement(summary: dict[str, Any], figures_dir: Path) -> Optional[str]:
    """Kappa و AC1 مع فترات ثقة 95%."""
    import plotly.graph_objects as go  # noqa: PLC0415

    agreement = summary.get("agreement") or {}
    ci = summary.get("ci") or {}
    if not agreement:
        return None
    names = ["Weighted κ", "Gwet's AC1"]
    values = [agreement.get("weighted_kappa", 0.0), agreement.get("gwet_ac1", 0.0)]
    lows = [ci.get("weighted_kappa_ci95", (0.0, 0.0))[0], ci.get("gwet_ac1_ci95", (0.0, 0.0))[0]]
    highs = [ci.get("weighted_kappa_ci95", (0.0, 0.0))[1], ci.get("gwet_ac1_ci95", (0.0, 0.0))[1]]
    figure = go.Figure(
        go.Bar(
            x=names,
            y=values,
            error_y=dict(type="data", array=[hi - v for hi, v in zip(highs, values)],
                         arrayminus=[v - lo for lo, v in zip(lows, values)]),
            marker_color=["#1976d2", "#388e3c"],
        )
    )
    figure.update_layout(title="مقاييس الاتفاق مع فترة ثقة 95% (بووتستراب 10,000)", yaxis_range=[-0.2, 1.0])
    return _write_figure(figure, figures_dir / "agreement_ci.html")


def build_learning_curve_figure(figures_dir: Path) -> Optional[str]:
    """منحنى التعلم: اتفاق تراكمي (نظام مقابل تصحيح بشري) بترتيب التصحيحات."""
    import plotly.graph_objects as go  # noqa: PLC0415

    try:
        from db.connection import get_session
        from db.models import Assessment, Correction
        from sqlalchemy import select

        with get_session() as session:
            corrections = session.execute(
                select(Correction, Assessment)
                .join(Assessment, Assessment.id == Correction.assessment_id)
                .order_by(Correction.corrected_at.asc(), Correction.id.asc())
            ).all()
    except Exception:
        return None
    if len(corrections) < 2:
        return None

    cumulative: list[float] = []
    agreements = 0
    for index, (correction, _assessment) in enumerate(corrections, 1):
        if correction.original_severity == correction.corrected_severity:
            agreements += 1
        cumulative.append(agreements / index)
    figure = go.Figure(go.Scatter(x=list(range(1, len(cumulative) + 1)), y=cumulative, mode="lines+markers"))
    figure.update_layout(
        title="منحنى التعلم: اتفاق الخطورة التراكمي (نظام ↔ تصحيح بشري)",
        xaxis_title="عدد التصحيحات",
        yaxis_title="الاتفاق التراكمي",
        yaxis_range=[0, 1.05],
    )
    return _write_figure(figure, figures_dir / "learning_curve.html")


# ---------------------------------------------------------------------
# التقرير
# ---------------------------------------------------------------------
def _agreement_markdown(summary: dict[str, Any]) -> str:
    """جدول الاتفاق + التفسير."""
    from evaluation.metrics import interpret_kappa  # noqa: PLC0415

    agreement = summary.get("agreement") or {}
    if not agreement:
        return "> لا أزواج مطابقة بعد — الحقيقة المرجعية غير مُملأة.\n"
    ci = summary.get("ci") or {}
    lines = [
        "| المقياس | القيمة | فترة ثقة 95% | التفسير |",
        "|---|---|---|---|",
        f"| Percent Agreement | {agreement.get('percent_agreement')} | "
        f"{ci.get('percent_agreement_ci95')} | — |",
        f"| Weighted κ (تربيعي) | {agreement.get('weighted_kappa')} | "
        f"{ci.get('weighted_kappa_ci95')} | {interpret_kappa(agreement.get('weighted_kappa', 0))} |",
        f"| Gwet's AC1 | {agreement.get('gwet_ac1')} | {ci.get('gwet_ac1_ci95')} | "
        f"{interpret_kappa(agreement.get('gwet_ac1', 0))} |",
        f"\nعدد الأزواج المطابقة: **{agreement.get('n_pairs')}**.",
    ]
    return "\n".join(lines) + "\n"


def write_report(
    summaries: dict[str, dict[str, Any]],
    raw_runs: dict[str, list[dict[str, Any]]],
    figures: list[str],
    output_path: Path,
) -> None:
    """يولّد REPORT.md — أو تقرير «شغّل التجربة أولاً» بلا ملفات."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if not summaries:
        output_path.write_text(
            "# تقرير تجربة القياس — المرحلة 7\n\n"
            f"**تاريخ التوليد:** {generated}\n\n"
            "> ⚠️ لا توجد نتائج بعد — شغّل التجربة أولاً:\n>\n"
            "> ```bash\n"
            "> LLM_MOCK_MODE=1 MCP_MOCK_MODE=1 EMBEDDING_MOCK_MODE=1 \\\n"
            ">   python evaluation/run_experiment.py --mode full --apps diva --dry-run\n"
            "> python evaluation/run_experiment.py --mode full --apps diva,insecurebankv2\n"
            "> ```\n",
            encoding="utf-8",
        )
        return

    sections: list[str] = [
        "# تقرير تجربة القياس — المرحلة 7",
        f"\n**تاريخ التوليد:** {generated}\n",
        "## 1) ملخص الأوضاع\n",
        "| الوضع | التطبيقات | GT مُملأة | F1 ماكروي | Weighted κ | Gwet's AC1 |",
        "|---|---|---|---|---|---|",
    ]
    for mode, summary in sorted(summaries.items()):
        agreement = summary.get("agreement") or {}
        macro = summary.get("macro_f1")
        sections.append(
            f"| {MODE_LABELS.get(mode, mode)} | {summary['apps_total']} | "
            f"{summary['apps_ground_truth_filled']} | "
            f"{'—' if macro is None else macro} | "
            f"{agreement.get('weighted_kappa', '—')} | {agreement.get('gwet_ac1', '—')} |"
        )

    sections.append("\n## 2) RQ1 — دقة الكشف (Precision/Recall/F1)\n")
    primary = summaries.get("full") or next(iter(summaries.values()))
    if primary["detection_per_app"]:
        sections.append("| التطبيق | TP | FP | FN | Precision | Recall | F1 |")
        sections.append("|---|---|---|---|---|---|---|")
        for row in primary["detection_per_app"]:
            sections.append(
                f"| {row['app_id']} | {row['tp']} | {row['fp']} | {row['fn']} | "
                f"{row['precision']} | {row['recall']} | {row['f1']} |"
            )
        ci = primary.get("ci") or {}
        if ci.get("macro_f1_ci95_across_apps"):
            sections.append(
                f"\n**F1 ماكروي:** {primary['macro_f1']} "
                f"(فترة 95% عبر التطبيقات: {ci['macro_f1_ci95_across_apps']})"
            )
    else:
        sections.append(
            "> ⚠️ **الحقيقة المرجعية غير مُملأة** — لا تُحسب Precision/Recall/F1. "
            "املأ `evaluation/dataset/ground_truth/*.json` (filled=true) ثم أعد التشغيل.\n"
        )

    sections.append("\n## 3) RQ2 — اتفاق الخطورة مع الخبير\n")
    sections.append(_agreement_markdown(primary))

    sections.append("\n## 4) RQ3/RQ4 — مقارنة الأوضاع\n")
    for mode, summary in sorted(summaries.items()):
        if mode == "full":
            continue
        agreement = summary.get("agreement") or {}
        sections.append(
            f"- **{MODE_LABELS.get(mode, mode)}:** "
            f"κ={agreement.get('weighted_kappa', '—')} · AC1={agreement.get('gwet_ac1', '—')} · "
            f"F1 ماكروي={summary.get('macro_f1', '—')}"
        )
    sections.append(
        "\n> الفروق تُفسَّر وصفياً مع 12 تطبيقاً؛ تُوصى اختبارات مزدوجة عند توسيع العينة "
        "(انظر protocol.md §7 — قيود إحصائية)."
    )

    sections.append("\n## 5) RQ5 — منحنى التعلم و A/B\n")
    sections.append(
        "منحنى التعلم يُبنى من جدول التصحيحات (`analyze_feedback.py` للاختبار المزدوج):"
    )
    if "learning_curve.html" in figures:
        sections.append("\n📈 [learning_curve.html](figures/learning_curve.html)\n")
    else:
        sections.append(
            "\n> لا يوجد عدد كافٍ من التصحيحات البشرية (<2) — شغّل حلقة HITL أولاً.\n"
        )

    sections.append("\n## 6) الرسوم البيانية\n")
    for name in figures:
        sections.append(f"- [figures/{name}](figures/{name})")

    sections.append("\n## 7) الملاحظات التشغيلية\n")
    for mode, runs in sorted(raw_runs.items()):
        missing_apk = [run["app_id"] for run in runs if not run.get("apk_file_present")]
        if missing_apk:
            sections.append(
                f"- الوضع `{mode}`: ملفات APK غير موجودة لـ {missing_apk} "
                "(مقبول في Mock؛ مطلوب للأدوات الحقيقية)."
            )
    sections.append(
        "- الأرقام المذكورة أعلاه مولّدة آلياً من ملفات `results/*/*.json` عبر "
        "`analyze_results.py` — لا يدخل أي رقم يدوي في التقرير."
    )

    output_path.write_text("\n".join(sections) + "\n", encoding="utf-8")


def main() -> None:
    """نقطة الدخول: تجميع → رسوم → summary.json → REPORT.md."""
    parser = argparse.ArgumentParser(description="تحليل نتائج التجربة")
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_path = Path(args.output)
    raw = collect_runs(input_dir)
    summaries = {mode: compute_mode_summary(runs) for mode, runs in raw.items()}

    figures_dir = input_dir / "figures"
    figures: list[str] = []

    # مصفوفة التباس مجمّعة (اتحاد مصفوفات الأوضاع المُملأة — الوضع الأساسي full أولاً)
    import numpy as np  # noqa: PLC0415

    pooled_matrix = np.zeros((4, 4), dtype=int)
    has_matrix = False
    primary_mode = "full" if "full" in raw else None
    for mode in ([primary_mode] if primary_mode else list(raw)):
        for run in raw.get(mode) or []:
            matrix = (((run.get("metrics") or {}).get("agreement") or {}).get("confusion_matrix"))
            if matrix:
                pooled_matrix += np.asarray(matrix, dtype=int)
                has_matrix = True
    if has_matrix:
        figures.append(build_figure_for_matrix(pooled_matrix.tolist(), figures_dir))
    figures.extend(build_figures(summaries, figures_dir))
    if summaries:
        primary = summaries.get("full") or next(iter(summaries.values()))
        name = build_figure_for_agreement(primary, figures_dir)
        if name:
            figures.append(name)
        name = build_learning_curve_figure(figures_dir)
        if name:
            figures.append(name)

    write_report(summaries, raw, figures, output_path)

    # summary.json للواجهة
    summary_path = input_dir / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(
            {
                "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "modes": summaries,
                "figures": figures,
                "confusion_matrix_pooled": (
                    pooled_matrix.tolist() if has_matrix else None
                ),
                "ground_truth_ready": any(
                    run.get("ground_truth_filled") for runs in raw.values() for run in runs
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"✅ REPORT.md: {output_path}")
    print(f"✅ summary.json: {summary_path}")
    print(f"   أوضاع: {sorted(summaries)} | رسوم: {len(figures)}")
    if not summaries:
        print("⚠️  لا نتائج خام — التقرير يشرح خطوات التشغيل")


if __name__ == "__main__":
    main()
