"""صفحة رفع APK وبدء فحص — Upload + SHA-256 + polling حي للتقدم."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from i18n import t  # noqa: E402
from ui_common import human_size, page_setup, show_error  # noqa: E402

POLL_INTERVAL_SECONDS = 1.0
POLL_MAX_ITERATIONS = 90  # سقف أمان للواجهة — الفحص الحقيقي أطول عبر CLI

client = page_setup("upload")
st.title("📤 " + t("page_upload"))

try:
    projects = client.list_projects()
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

if not projects:
    st.warning(t("no_data") + " — " + t("page_projects"))
    st.stop()

project_options = {f"#{p['id']} — {p['name']}": p["id"] for p in projects}

# ── 1) الرفع ────────────────────────────────────────────────────────
st.subheader(t("upload_title"))
with st.form("upload_form"):
    project_label = st.selectbox(t("projects_title"), options=list(project_options.keys()))
    uploaded = st.file_uploader(t("upload_file"), type=["apk"])
    col1, col2, col3 = st.columns(3)
    name = col1.text_input(t("applications_title"))
    package_name = col2.text_input("package_name", placeholder="com.example.app")
    version = col3.text_input("version", placeholder="1.0.0")
    app_category = st.text_input("app_category", placeholder="banking")
    if st.form_submit_button(t("upload_submit"), type="primary"):
        if uploaded is None:
            st.error(t("upload_file"))
        else:
            try:
                result = client.upload_apk(
                    project_id=project_options[project_label],
                    filename=uploaded.name,
                    content=uploaded.getvalue(),
                    name=name.strip() or None,
                    package_name=package_name.strip() or None,
                    version=version.strip() or None,
                    app_category=app_category.strip() or None,
                )
                st.session_state["last_application"] = result["application"]
                if result.get("deduplicated"):
                    st.info(t("upload_duplicate"))
                else:
                    st.success(t("upload_done"))
            except Exception as exc:  # noqa: BLE001
                show_error(exc)

application = st.session_state.get("last_application")
if application:
    with st.container(border=True):
        st.markdown(f"**#{application['id']} — {application['name']}**")
        cols = st.columns(3)
        cols[0].markdown(f"{t('sha256')}: `{application['sha256'][:24]}…`")
        cols[1].markdown(f"{t('file_size')}: **{human_size(application.get('file_size'))}**")
        cols[2].markdown(f"category: **{application.get('app_category') or '—'}**")

    # ── 2) بدء الفحص ────────────────────────────────────────────────
    st.subheader(t("start_scan"))
    scan_type_labels = {
        "comprehensive": t("scan_type_comprehensive"),
        "static": t("scan_type_static"),
        "dynamic": t("scan_type_dynamic"),
    }
    scan_type_key = st.radio(
        t("scan_type"),
        options=list(scan_type_labels.keys()),
        format_func=lambda key: scan_type_labels[key],
        horizontal=True,
    )
    if st.button(t("start_scan"), type="primary"):
        try:
            started = client.start_scan(application["id"], scan_type=scan_type_key)
            st.session_state["poll_scan_id"] = started["scan_id"]
            st.success(t("scan_started") + f" — scan #{started['scan_id']}")
        except Exception as exc:  # noqa: BLE001
            show_error(exc)

# ── 3) polling الحالة ───────────────────────────────────────────────
scan_id = st.session_state.get("poll_scan_id")
if scan_id:
    st.subheader(f"{t('scan_status')} — #{scan_id}")
    bar = st.progress(0, text=t("loading"))
    status_line = st.empty()
    for _ in range(POLL_MAX_ITERATIONS):
        try:
            status = client.get_scan_status(scan_id)
        except Exception as exc:  # noqa: BLE001
            show_error(exc)
            break
        bar.progress(
            max(0, min(100, status.get("progress_percent") or 0)),
            text=f"{status.get('progress_percent')}% — {status.get('current_agent') or ''}",
        )
        status_line.markdown(
            f"{t('scan_status')}: **{status['status']}** · {t('current_stage')}: "
            f"{status.get('current_agent') or '—'} · ms: {status.get('total_duration_ms')}"
        )
        if status["status"] not in ("pending", "running"):
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    else:
        st.caption("⏳ " + t("scan_progress"))

    if st.button(t("refresh"), key="refresh_status"):
        st.rerun()

    if status and status["status"] in ("success", "partial"):
        st.success(t("scan_finished"))
        try:
            vulns = client.get_scan_vulnerabilities(scan_id)
            st.metric(t("kpi_vulns"), len(vulns))
        except Exception as exc:  # noqa: BLE001
            show_error(exc)
    elif status and status["status"] == "failed":
        st.error(status.get("error_message") or t("error"))
