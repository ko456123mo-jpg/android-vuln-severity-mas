"""صفحة لوحة المعلومات — KPIs + توزيع الخطورة + آخر الفحوصات + أعلى الثغرات."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from i18n import t  # noqa: E402
from ui_common import page_setup, render_brand_header, show_error  # noqa: E402

client = page_setup("dashboard")
render_brand_header(t("app_subtitle"))
st.divider()
st.subheader("📊 " + t("page_dashboard"))

try:
    summary = client.summary()
    severity = client.severity_chart()
    recent = client.recent_scans(10)
    top = client.top_vulns(10)
    trends = client.trends(7)
except Exception as exc:  # noqa: BLE001 — عرض موحّد للخطأ
    show_error(exc)
    st.stop()

cols = st.columns(5)
cols[0].metric(t("kpi_projects"), summary["total_projects"])
cols[1].metric(t("kpi_apps"), summary["total_applications"])
cols[2].metric(t("kpi_scans"), summary["total_scans"])
cols[3].metric(t("kpi_vulns"), summary["total_vulnerabilities"])
cols[4].metric(t("kpi_pending"), summary["pending_reviews"])
st.caption(f"{t('avg_score')}: {summary.get('avg_final_score') or '—'}")

left, right = st.columns(2)
with left:
    st.subheader(t("severity_chart_title"))
    if severity:
        fig = go.Figure(
            go.Pie(
                labels=[row["severity"] for row in severity],
                values=[row["count"] for row in severity],
                hole=0.55,
                marker={
                    "colors": ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c"][: len(severity)]
                },
            )
        )
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info(t("no_data"))
with right:
    st.subheader(t("top_vulns_title"))
    if top:
        st.dataframe(
            [
                {
                    "#": row["vulnerability_id"],
                    t("findings_title"): row["title"][:60],
                    "CWE": row["cwe_id"],
                    t("filter_severity"): row["severity"],
                    t("final_score"): row["final_score"],
                }
                for row in top
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(t("no_data"))

st.subheader(t("recent_scans_title"))
if recent:
    st.dataframe(
        [
            {
                "#": row["scan_id"],
                t("applications_title"): row["application_name"],
                t("scan_status"): row["status"],
                "started": row["started_at"],
                "ms": row["total_duration_ms"],
            }
            for row in recent
        ],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info(t("no_data"))

st.subheader(t("corrections_timeline"))
scan_trend = trends.get("scans") or []
if scan_trend:
    st.bar_chart({"date": [r["date"] for r in scan_trend], "count": [r["count"] for r in scan_trend]}, x="date", y="count")
else:
    st.info(t("no_data"))
