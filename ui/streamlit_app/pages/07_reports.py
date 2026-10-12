"""صفحة التقارير — توليد + معاينة Technical/Executive + تنزيل md/html/pdf."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from i18n import t  # noqa: E402
from ui_common import human_size, page_setup, show_error  # noqa: E402

client = page_setup("reports")
st.title("📄 " + t("page_reports"))

try:
    scans = client.list_scans()
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

if not scans:
    st.info(t("no_data"))
    st.stop()

scan_options = {f"#{row['id']} — {row['status']}": row["id"] for row in scans}
scan_label = st.selectbox(t("select_scan"), options=list(scan_options.keys()))
scan_id = scan_options[scan_label]

if st.button("⚙️ " + t("generate_reports"), type="primary"):
    try:
        result = client.generate_reports(scan_id)
        st.success(t("reports_generated"))
        st.session_state["report_files"] = result.get("files") or {}
    except Exception as exc:  # noqa: BLE001
        show_error(exc)

files = st.session_state.get("report_files") or {}
if files:
    st.caption(f"{len(files)} × " + t("download"))

    tab_tech, tab_exec = st.tabs([t("technical_report"), t("executive_report")])

    with tab_tech:
        try:
            technical = client.get_technical_report(scan_id)
            stats = technical.get("stats") or {}
            st.caption(
                f"Critical: {stats.get('critical', '—')} · High: {stats.get('high', '—')} · "
                f"Medium: {stats.get('medium', '—')} · Low: {stats.get('low', '—')}"
            )
            st.markdown(technical.get("markdown") or t("no_data"))
        except Exception as exc:  # noqa: BLE001
            show_error(exc)
        for fmt, label in (("technical_md", "MD"), ("technical_html", "HTML"), ("technical_pdf", "PDF")):
            try:
                payload = client.download_report(scan_id, fmt)
                st.download_button(
                    f"⬇️ {label} ({human_size(len(payload))})",
                    data=payload,
                    file_name=f"technical_report_{scan_id}.{fmt.split('_')[1]}",
                    key=f"dl_{fmt}",
                )
            except Exception as exc:  # noqa: BLE001
                show_error(exc)

    with tab_exec:
        try:
            executive = client.get_executive_report(scan_id)
            st.markdown(executive.get("markdown") or t("no_data"))
        except Exception as exc:  # noqa: BLE001
            show_error(exc)
        for fmt, label in (("executive_md", "MD"), ("executive_html", "HTML"), ("executive_pdf", "PDF")):
            try:
                payload = client.download_report(scan_id, fmt)
                st.download_button(
                    f"⬇️ {label} ({human_size(len(payload))})",
                    data=payload,
                    file_name=f"executive_report_{scan_id}.{fmt.split('_')[1]}",
                    key=f"dl_{fmt}",
                )
            except Exception as exc:  # noqa: BLE001
                show_error(exc)
else:
    st.info(t("no_data") + " — " + t("generate_reports"))
