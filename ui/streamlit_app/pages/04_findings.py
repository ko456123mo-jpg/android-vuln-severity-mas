"""صفحة الثغرات — جدول قابل للفلترة + توزيع MASVS + الانتقال لتفاصيل التقييم."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from i18n import t  # noqa: E402
from ui_common import page_setup, show_error  # noqa: E402

client = page_setup("findings")
st.title("🐞 " + t("page_findings"))

try:
    scans = client.list_scans()
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

if not scans:
    st.info(t("no_data"))
    st.stop()

scan_options = {
    f"#{row['id']} — {row['status']} — {row.get('tools_used') or '—'}": row["id"] for row in scans
}
scan_label = st.selectbox(t("select_scan"), options=list(scan_options.keys()))
scan_id = scan_options[scan_label]

try:
    vulnerabilities = client.get_scan_vulnerabilities(scan_id)
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

if not vulnerabilities:
    st.info(t("no_data"))
    st.stop()

# ── الفلاتر ─────────────────────────────────────────────────────────
fcol1, fcol2, fcol3 = st.columns(3)
severity_filter = fcol1.multiselect(
    t("filter_severity"), options=["Critical", "High", "Medium", "Low"]
)
masvs_options = sorted({v.get("masvs_category") or "—" for v in vulnerabilities})
masvs_filter = fcol2.multiselect(t("filter_masvs"), options=masvs_options)
search = fcol3.text_input(t("search_text"))
confirmed_only = st.checkbox(t("confirmed_dynamic"))

filtered = []
for vuln in vulnerabilities:
    assessment = vuln.get("assessment") or {}
    if severity_filter and assessment.get("severity") not in severity_filter:
        continue
    if masvs_filter and (vuln.get("masvs_category") or "—") not in masvs_filter:
        continue
    if search and search.lower() not in (vuln.get("title") or "").lower() + (vuln.get("cwe_id") or "").lower():
        continue
    evidence = vuln.get("evidence") or {}
    is_dynamic_confirmed = "frida" in (evidence.get("tools") or []) or "objection" in (
        evidence.get("tools") or []
    )
    if confirmed_only and not is_dynamic_confirmed:
        continue
    filtered.append((vuln, assessment, evidence, is_dynamic_confirmed))

st.caption(f"{len(filtered)} / {len(vulnerabilities)}")

st.dataframe(
    [
        {
            "#": vuln["id"],
            t("findings_title"): vuln["title"][:70],
            "CWE": vuln.get("cwe_id"),
            "MASVS": vuln.get("masvs_category"),
            t("filter_severity"): (assessment.get("severity") or "—"),
            t("final_score"): assessment.get("final_score"),
            t("confirmed_dynamic"): "✅" if confirmed else "—",
            t("review_status"): assessment.get("review_status") or "—",
        }
        for vuln, assessment, _evidence, confirmed in filtered
    ],
    use_container_width=True,
    hide_index=True,
)

# ── توزيع MASVS ─────────────────────────────────────────────────────
st.subheader(t("masvs_chart_title"))
masvs_counts: dict[str, int] = {}
for vuln, _assessment, _evidence, _confirmed in filtered:
    key = vuln.get("masvs_category") or "—"
    masvs_counts[key] = masvs_counts.get(key, 0) + 1
if masvs_counts:
    fig = go.Figure(
        go.Bar(
            x=list(masvs_counts.values()),
            y=list(masvs_counts.keys()),
            orientation="h",
            marker_color="#1976d2",
        )
    )
    fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info(t("no_data"))

# ── تفاصيل ثغرة + الانتقال ──────────────────────────────────────────
st.subheader(t("view_details"))
detail_options = {f"#{v['id']} — {v['title'][:60]}": v["id"] for v, *_ in filtered}
if detail_options:
    detail_label = st.selectbox(t("findings_title"), options=list(detail_options.keys()))
    selected_vuln_id = detail_options[detail_label]
    try:
        detail = client.get_vulnerability(selected_vuln_id)
    except Exception as exc:  # noqa: BLE001
        show_error(exc)
        st.stop()
    with st.container(border=True):
        st.markdown(f"**{detail['title']}**")
        st.caption(
            f"CWE: {detail.get('cwe_id') or '—'} · MASVS: {detail.get('masvs_category') or '—'}"
        )
        st.write(detail.get("description") or "—")
    if st.button("🧮 " + t("page_assessment"), type="primary"):
        st.session_state["selected_vuln_id"] = selected_vuln_id
        st.switch_page("pages/05_assessment_detail.py")
else:
    st.info(t("no_data"))
