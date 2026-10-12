"""صفحة قائمة المراجعة — التصحيحات البشرية (HITL) + سجل التصحيحات."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from components.diff_view import render_correction_diff  # noqa: E402
from i18n import t  # noqa: E402
from ui_common import page_setup, show_error  # noqa: E402

client = page_setup("reviews")
st.title("🧑‍⚖️ " + t("review_queue_title"))

_SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"]

try:
    stats = client.review_stats()
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

stat_cols = st.columns(4)
stat_cols[0].metric(t("pending_count"), stats.get("pending", 0))
stat_cols[1].metric("approved", stats.get("approved", 0))
stat_cols[2].metric(t("corrections_total"), stats.get("corrections_total", 0))
stat_cols[3].metric(t("feedback_examples"), stats.get("feedback_examples_total", 0))

severity_filter = st.selectbox(
    f"{t('filter_severity')} ({t('pending_count')})",
    options=[""] + _SEVERITY_OPTIONS,
    format_func=lambda value: value or "الكل",
)
try:
    pending = client.pending_reviews(limit=50, severity=severity_filter or None)
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

if not pending:
    st.success(t("no_data"))
    st.stop()

st.dataframe(
    [
        {
            "#": row["id"],
            t("findings_title"): (row.get("title") or row.get("cwe_id") or "")[:60],
            "CWE": row.get("cwe_id"),
            "MASVS": row.get("masvs_category"),
            t("filter_severity"): row.get("severity"),
            t("final_score"): row.get("final_score"),
        }
        for row in pending
    ],
    use_container_width=True,
    hide_index=True,
)

options = {
    f"#{row['id']} — {row.get('title') or row.get('cwe_id') or ''} ({row.get('severity')} · {row.get('final_score')})": row[
        "id"
    ]
    for row in pending
}
label = st.selectbox(t("select_assessment"), options=list(options.keys()))
assessment_id = options[label]
selected = next(row for row in pending if row["id"] == assessment_id)

with st.container(border=True):
    st.markdown(f"**{selected.get('title') or ''}**")
    st.caption(
        f"CWE: {selected.get('cwe_id') or '—'} · system: {selected.get('severity')}"
        f" · {t('final_score')}: {selected.get('final_score')}"
    )
    if selected.get("rationale"):
        st.caption(selected["rationale"][:600])

with st.form("correction_form"):
    col1, col2 = st.columns(2)
    corrected_severity = col1.selectbox(
        t("correction_severity"),
        options=_SEVERITY_OPTIONS,
        index=_SEVERITY_OPTIONS.index(selected.get("severity") or "Medium"),
    )
    corrected_score = col2.slider(
        t("correction_score"),
        min_value=0.0,
        max_value=10.0,
        value=float(selected.get("final_score") or 5.0),
        step=0.1,
    )
    reason = st.text_area(t("correction_reason"), height=100)
    if st.form_submit_button(t("submit_correction"), type="primary"):
        if len(reason.strip()) < 3:
            st.error(t("correction_reason"))
        else:
            try:
                client.submit_correction(assessment_id, corrected_severity, corrected_score, reason.strip())
                st.success(t("correction_saved"))
                st.rerun()
            except Exception as exc:  # noqa: BLE001
                show_error(exc)

st.subheader(t("previous_corrections"))
try:
    details = client.get_assessment(assessment_id)
    render_correction_diff(details.get("corrections") or [])
except Exception as exc:  # noqa: BLE001
    show_error(exc)
