"""صفحة المشاريع والتطبيقات — إنشاء/عرض المشاريع + تطبيقاتها + سياق التطبيق."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

from i18n import t  # noqa: E402
from ui_common import human_size, page_setup, show_error  # noqa: E402

client = page_setup("projects")
st.title("📁 " + t("page_projects"))

try:
    projects = client.list_projects()
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

with st.expander(t("new_project"), expanded=not projects):
    with st.form("create_project"):
        name = st.text_input(t("project_name"))
        description = st.text_area(t("description"), height=80)
        if st.form_submit_button(t("create"), type="primary"):
            if not name.strip():
                st.error(f"{t('project_name')} مطلوب")
            else:
                try:
                    client.create_project(name.strip(), description.strip() or None)
                    st.success(t("project_created"))
                    st.rerun()
                except Exception as exc:  # noqa: BLE001
                    show_error(exc)

if not projects:
    st.info(t("no_data"))
    st.stop()

st.subheader(t("projects_title"))
cards = st.columns(min(3, len(projects)))
for index, project in enumerate(projects):
    with cards[index % len(cards)]:
        with st.container(border=True):
            st.markdown(f"**{project['name']}**")
            st.caption(project.get("description") or "—")
            metrics = st.columns(3)
            metrics[0].metric(t("kpi_apps"), project["stats"]["applications"])
            metrics[1].metric(t("kpi_scans"), project["stats"]["scans"])
            metrics[2].metric(t("kpi_vulns"), project["stats"]["vulnerabilities"])
            if st.button(t("archive_project"), key=f"archive_{project['id']}"):
                try:
                    client.delete_project(project["id"])
                    st.rerun()
                except Exception as exc:  # noqa: BLE001
                    show_error(exc)

project_options = {f"#{p['id']} — {p['name']}": p["id"] for p in projects}
selected_label = st.selectbox(t("projects_title"), options=list(project_options.keys()))
selected_project_id = project_options[selected_label]

try:
    applications = client.list_applications(project_id=selected_project_id)
except Exception as exc:  # noqa: BLE001
    show_error(exc)
    st.stop()

st.subheader(t("applications_title"))
if applications:
    st.dataframe(
        [
            {
                "#": app["id"],
                t("applications_title"): app["name"],
                "package": app.get("package_name") or "—",
                "sha256": app["sha256"][:16] + "…",
                t("file_size"): human_size(app.get("file_size")),
            }
            for app in applications
        ],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info(t("no_data"))
    st.stop()

app_options = {f"#{app['id']} — {app['name']}": app["id"] for app in applications}
app_label = st.selectbox(t("applications_title"), options=list(app_options.keys()))
application = client.get_application(app_options[app_label])
context = application.get("app_context") or {}

st.subheader(t("app_context_title"))
st.caption(f"{t('context_score')}: **{context.get('context_score') if context else '—'}**")

_PLACEHOLDER = "غير محدد"
with st.form("context_form"):
    col1, col2, col3 = st.columns(3)
    with col1:
        sensitivity_opts = [_PLACEHOLDER, "LOW", "MEDIUM", "HIGH"]
        sensitivity = st.selectbox(
            "data_sensitivity",
            sensitivity_opts,
            index=sensitivity_opts.index(context.get("data_sensitivity") or _PLACEHOLDER),
        )
        industry_opts = [_PLACEHOLDER, "banking", "health", "commerce", "game", "utility"]
        industry = st.selectbox(
            "industry",
            industry_opts,
            index=industry_opts.index(context.get("industry") or _PLACEHOLDER),
        )
    with col2:
        userbase_opts = [_PLACEHOLDER, "small", "medium", "large"]
        user_base = st.selectbox(
            "user_base_size",
            userbase_opts,
            index=userbase_opts.index(context.get("user_base_size") or _PLACEHOLDER),
        )
        facing_opts = [_PLACEHOLDER, "yes", "no"]
        facing_value = context.get("internet_facing")
        facing_default = _PLACEHOLDER if facing_value is None else ("yes" if facing_value else "no")
        internet_facing = st.selectbox(
            "internet_facing", facing_opts, index=facing_opts.index(facing_default)
        )
    with col3:
        criticality_opts = [_PLACEHOLDER, "LOW", "MEDIUM", "HIGH"]
        criticality = st.selectbox(
            "business_criticality",
            criticality_opts,
            index=criticality_opts.index(context.get("business_criticality") or _PLACEHOLDER),
        )
        compliance = st.text_input(
            "compliance_requirements", value=context.get("compliance_requirements") or ""
        )
    if st.form_submit_button(t("save"), type="primary"):
        payload = {
            "data_sensitivity": None if sensitivity == _PLACEHOLDER else sensitivity,
            "industry": None if industry == _PLACEHOLDER else industry,
            "user_base_size": None if user_base == _PLACEHOLDER else user_base,
            "internet_facing": None if internet_facing == _PLACEHOLDER else internet_facing == "yes",
            "business_criticality": None if criticality == _PLACEHOLDER else criticality,
            "compliance_requirements": compliance.strip() or None,
        }
        try:
            client.update_app_context(application["id"], payload)
            st.success(t("context_updated"))
            st.rerun()
        except Exception as exc:  # noqa: BLE001
            show_error(exc)
