"""الصفحة 08 — التقييم البحثي: نتائج التجربة + A/B + الحلقة الحية (المرحلة 7).

ثلاثة تبويبات:
    1) نتائج التجربة — من results/summary.json (يولّده analyze_results.py)
    2) اختبار A/B    — من results/feedback_ab_test.json (يولّده analyze_feedback.py)
    3) الحلقة الحية   — بيانات HITL الحالية عبر الـ API (كما في المرحلة 6)

ملاحظة نشر: ملفات results/ تُقرأ من نفس مضيف تشغيل الواجهة (تُنتَج محلياً
بسكربتات evaluation/)، وبيانات الحلقة الحية عبر الـ API — الواجهة لا تكتب شيئاً.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from i18n import t  # noqa: E402
from ui_common import page_setup, show_error  # noqa: E402

client = page_setup("evaluation")
st.title("📈 " + t("page_evaluation"))
st.caption(t("evaluation_intro"))

RUN_COMMANDS = (
    "# 1) فهرسة RAG\n"
    "EMBEDDING_MOCK_MODE=1 python scripts/ingest_knowledge.py\n\n"
    "# 2) فحص تجريبي (Mock — سباكة فقط)\n"
    "LLM_MOCK_MODE=1 MCP_MOCK_MODE=1 EMBEDDING_MOCK_MODE=1 \\\n"
    "  python evaluation/run_experiment.py --mode full --apps diva --dry-run\n\n"
    "# 3) إملاء الحقيقة المرجعية يدوياً ثم:\n"
    "python evaluation/analyze_results.py --input results/ --output results/REPORT.md"
)


def _project_root() -> Path:
    """جذر المشروع: أول أب يحتوي مجلد evaluation أو results."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "evaluation").exists() or (parent / "results").exists():
            return parent
    return Path(__file__).resolve().parents[3]


PROJECT_ROOT = _project_root()
RESULTS_DIR = PROJECT_ROOT / "results"


def _load_json(path: Path) -> dict[str, Any] | None:
    """قراءة JSON بأمان (None عند الغياب/التلف)."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _interpret(value: Any) -> str:
    """تفسير Landis-Koch (بتحميل كسول لوحدة المقاييس)."""
    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from evaluation.metrics import interpret_kappa  # noqa: PLC0415

        return interpret_kappa(float(value))
    except Exception:  # noqa: BLE001 — الواجهة لا تنكسر لعيب تفسيري
        return "—"


def _download_button(label: str, path: Path, mime: str, key: str) -> None:
    """زر تنزيل لملف محلي إن وُجد."""
    if not path.exists():
        return
    st.download_button(
        label, data=path.read_bytes(), file_name=path.name, mime=mime, key=key,
        use_container_width=True,
    )


def render_experiment_tab() -> None:
    """تبويب 1: ملخص الأوضاع + كشف + اتفاق + مصفوفة + تنزيلات."""
    summary = _load_json(RESULTS_DIR / "summary.json")
    if not summary:
        st.info(t("evaluation_no_results"))
        st.markdown(f"**{t('evaluation_how_to_run')}**")
        st.code(RUN_COMMANDS, language="bash")
        return

    modes: dict[str, Any] = summary.get("modes") or {}
    if not summary.get("ground_truth_ready"):
        st.warning(t("gt_pending_banner"))

    st.subheader(t("mode_label"))
    for mode_name, state in sorted(modes.items()):
        agreement = state.get("agreement") or {}
        row = st.columns(5)
        row[0].markdown(f"**{mode_name}**")
        row[1].write(f"{state.get('apps_ground_truth_filled', 0)} / {state.get('apps_total', 0)}")
        row[2].write("—" if state.get("macro_f1") is None else state["macro_f1"])
        row[3].write(agreement.get("weighted_kappa", "—"))
        row[4].write(agreement.get("gwet_ac1", "—"))
    st.caption(f"{t('apps_gt_filled')} · {t('macro_f1')} · {t('weighted_kappa')} · {t('gwet_ac1')}")

    primary = modes.get("full") or (next(iter(modes.values())) if modes else None)
    if not primary:
        return

    detection = primary.get("detection_per_app") or []
    st.subheader(t("detection_per_app"))
    if detection:
        st.dataframe(detection, use_container_width=True, hide_index=True)
        st.bar_chart({row["app_id"]: row["f1"] for row in detection}, y_label="F1")
    else:
        st.info(t("no_data"))

    agreement = primary.get("agreement") or {}
    if agreement:
        st.subheader(t("agreement_table"))
        ci = primary.get("ci") or {}
        st.dataframe(
            [
                {
                    "metric": "Weighted κ",
                    "value": agreement.get("weighted_kappa"),
                    t("interpretation"): _interpret(agreement.get("weighted_kappa")),
                    "CI95": ci.get("weighted_kappa_ci95"),
                },
                {
                    "metric": "Gwet's AC1",
                    "value": agreement.get("gwet_ac1"),
                    t("interpretation"): _interpret(agreement.get("gwet_ac1")),
                    "CI95": ci.get("gwet_ac1_ci95"),
                },
                {
                    "metric": t("percent_agreement"),
                    "value": agreement.get("percent_agreement"),
                    t("interpretation"): "—",
                    "CI95": ci.get("percent_agreement_ci95"),
                },
            ],
            use_container_width=True,
            hide_index=True,
        )

    matrix = summary.get("confusion_matrix_pooled")
    if matrix:
        st.subheader(f"{t('confusion_matrix')} (full)")
        categories = ["Low", "Medium", "High", "Critical"]
        st.dataframe(
            [[categories[i]] + [int(v) for v in row] for i, row in enumerate(matrix)],
            use_container_width=True,
            hide_index=True,
        )

    st.subheader(t("figures_download"))
    figures = (
        sorted((RESULTS_DIR / "figures").glob("*.html"))
        if (RESULTS_DIR / "figures").exists()
        else []
    )
    if figures:
        columns = st.columns(2)
        for index, figure in enumerate(figures):
            with columns[index % 2]:
                _download_button(f"📊 {figure.name}", figure, "text/html", f"fig_{figure.name}")
    else:
        st.info(t("no_data"))
    _download_button(
        "📄 " + t("report_download"), RESULTS_DIR / "REPORT.md", "text/markdown", "report_md"
    )


def render_ab_tab() -> None:
    """تبويب 2: فوجا A/B + الاختبار المزدوج."""
    payload = _load_json(RESULTS_DIR / "feedback_ab_test.json")
    if not payload:
        st.info(t("evaluation_no_results"))
        st.markdown(f"**{t('evaluation_how_to_run')}**")
        st.code("python evaluation/analyze_feedback.py", language="bash")
        return

    cohort_a = payload.get("cohort_a") or {}
    cohort_b = payload.get("cohort_b") or {}
    metrics = st.columns(3)
    metrics[0].metric(t("total_corrections"), payload.get("total_corrections", 0))
    metrics[1].metric("A (بلا أمثلة)", cohort_a.get("n", 0))
    metrics[2].metric("B (مع أمثلة)", cohort_b.get("n", 0))

    st.subheader(t("feedback_ab_title"))
    st.dataframe(
        [
            {"cohort": "A — بلا few-shot", **cohort_a},
            {"cohort": "B — مع few-shot", **cohort_b},
        ],
        use_container_width=True,
        hide_index=True,
    )

    paired = payload.get("paired") or {}
    if (paired.get("paired_n") or 0) >= 3:
        st.subheader("Wilcoxon / t-test مزدوج")
        st.dataframe(
            [{t("paired_stat"): key, t("paired_value"): value} for key, value in paired.items()],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(t("feedback_ab_insufficient"))
    _download_button(
        "📄 feedback_ab_test.md",
        RESULTS_DIR / "feedback_ab_test.md",
        "text/markdown",
        key="ab_md",
    )


def render_live_tab() -> None:
    """تبويب 3: إحصاءات HITL الحية من الـ API."""
    try:
        review_stats = client.review_stats()
        assessment_stats = client.assessment_stats()
    except Exception as exc:  # noqa: BLE001
        show_error(exc)
        return

    cols = st.columns(4)
    cols[0].metric(t("corrections_total"), review_stats.get("corrections_total", 0))
    cols[1].metric(t("feedback_examples"), review_stats.get("feedback_examples_total", 0))
    cols[2].metric(t("pending_count"), review_stats.get("pending", 0))
    cols[3].metric("approved", review_stats.get("approved", 0))

    st.subheader(t("severity_chart_title"))
    distribution = assessment_stats.get("severity_distribution") or {}
    if distribution:
        st.bar_chart(
            {"severity": list(distribution.keys()), "count": list(distribution.values())},
            x="severity",
            y="count",
        )
    st.caption(
        f"{t('avg_score')}: {assessment_stats.get('avg_final_score')} · "
        f"max: {assessment_stats.get('max_final_score')} · "
        f"min: {assessment_stats.get('min_final_score')}"
    )
    st.caption(
        "منحنى التعلم (اتفاق تراكمي عبر التصحيحات) يُبنى في "
        "`results/figures/learning_curve.html` بعد توفر تصحيحات كافية."
    )


tab_experiment, tab_ab, tab_live = st.tabs(
    [t("tab_experiment"), t("tab_feedback_ab"), t("tab_live")]
)
with tab_experiment:
    render_experiment_tab()
with tab_ab:
    render_ab_tab()
with tab_live:
    render_live_tab()
