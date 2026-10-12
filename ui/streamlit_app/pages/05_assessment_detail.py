"""صفحة تفاصيل التقييم — تفكيك المعادلة + الثقة + الأدلة + Reasoning."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from components.diff_view import render_correction_diff  # noqa: E402
from components.score_breakdown import render_score_metrics, render_score_waterfall  # noqa: E402
from i18n import t  # noqa: E402
from ui_common import page_setup, show_error  # noqa: E402

client = page_setup("assessment")
st.title("🧮 " + t("page_assessment"))

# ── اختيار الثغرة: من صفحة الثغرات أو من قائمة كل التقييمات ─────────
vuln_id = st.session_state.get("selected_vuln_id")
assessments: list[dict] = []
if vuln_id is None:
    try:
        assessments = client.list_assessments(limit=100)
    except Exception as exc:  # noqa: BLE001
        show_error(exc)
        st.stop()
    if not assessments:
        st.info(t("no_data"))
        st.stop()
    options = {
        f"#{row['vulnerability_id']} — {row.get('vuln_title') or ''} ({row.get('severity')})": row[
            "vulnerability_id"
        ]
        for row in assessments
    }
    label = st.selectbox(t("page_assessment"), options=list(options.keys()))
    vuln_id = options[label]

try:
    vulnerability = client.get_vulnerability(vuln_id)
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

assessment = vulnerability.get("assessment") or {}
if not assessment:
    st.warning(t("no_data"))
    st.stop()

# ── الترويسة ────────────────────────────────────────────────────────
st.subheader(vulnerability["title"])
st.caption(
    f"CWE: {vulnerability.get('cwe_id') or '—'} · MASVS: {vulnerability.get('masvs_category') or '—'}"
    f" · {t('review_status')}: {assessment.get('review_status') or '—'}"
)
st.write(vulnerability.get("description") or "—")

st.subheader(t("equation_title"))
render_score_metrics(assessment)
render_score_waterfall(assessment)

# ── الثقة والأدلة ───────────────────────────────────────────────────
left, right = st.columns(2)
with left:
    st.subheader(t("confidence_title"))
    try:
        evidence_rows = client.get_vulnerability_evidence(vuln_id)
    except Exception as exc:  # noqa: BLE001
        evidence_rows = []
        show_error(exc)
    st.markdown(f"**Confidence factor:** {assessment.get('confidence_factor')}")
    if evidence_rows:
        st.dataframe(
            [
                {
                    "tool": row.get("tool_name"),
                    "category": row.get("tool_category"),
                    "reliability": row.get("tool_reliability"),
                    "evidence_type": row.get("evidence_type"),
                }
                for row in evidence_rows
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(t("no_data"))
with right:
    st.subheader(t("evidence_title"))
    if evidence_rows:
        for row in evidence_rows:
            with st.container(border=True):
                st.markdown(f"**{row.get('tool_name')}** ({row.get('evidence_type')})")
                st.caption(row.get("location") or "")
                if row.get("artifact_ref"):
                    st.code(str(row.get("artifact_ref"))[:400], language=None)
    else:
        st.info(t("no_data"))

st.subheader(t("rationale_title"))
st.markdown(assessment.get("rationale") or "—")

# ── التصحيحات البشرية السابقة (إن وُجدت) ────────────────────────────
if assessment.get("id"):
    try:
        full = client.get_assessment(assessment["id"])
        st.subheader(t("previous_corrections"))
        render_correction_diff(full.get("corrections") or [])
    except Exception as exc:  # noqa: BLE001
        show_error(exc)
