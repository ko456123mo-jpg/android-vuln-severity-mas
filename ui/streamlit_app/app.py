"""نقطة دخول واجهة Streamlit — تسجيل الدخول + التنقل حسب الدور (المرحلة 6).

التشغيل: python scripts/run_ui.py --port 8501
- بلا جلسة: نموذج دخول فقط (POST /auth/login) ويُحفظ التوكن في session_state.
- بجلسة: شريط جانبي مشترك (لغة/مستخدم/خروج) + صفحات st.navigation حسب الدور.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st  # noqa: E402

from api_client import APIClient, APIError  # noqa: E402
from i18n import inject_direction_css, t  # noqa: E402
from ui_common import (  # noqa: E402
    CLIENT_KEY,
    ROLE_PAGES,
    SIDEBAR_FLAG,
    TOKEN_KEY,
    USER_KEY,
    render_brand_header,
    render_sidebar,
    set_page_config_once,
)

set_page_config_once()
inject_direction_css()

_I18N_KEYS = set()


def _safe_subtitle() -> str | None:
    """شعاري الواجهة من ملف الترجمة إن وُجد المفتاح (بلا كسر إن غاب)."""
    for key in ("app_subtitle", "tagline"):
        value = t(key)
        if value and value != key:
            return value
    return None


_PAGE_DEFS = {
    "dashboard": ("pages/01_dashboard.py", "📊", "page_dashboard"),
    "projects": ("pages/02_projects_apps.py", "📁", "page_projects"),
    "upload": ("pages/03_upload_scan.py", "📤", "page_upload"),
    "findings": ("pages/04_findings.py", "🐞", "page_findings"),
    "assessment": ("pages/05_assessment_detail.py", "🧮", "page_assessment"),
    "reviews": ("pages/06_review_queue.py", "🧑‍⚖️", "page_reviews"),
    "reports": ("pages/07_reports.py", "📄", "page_reports"),
    "evaluation": ("pages/08_evaluation.py", "📈", "page_evaluation"),
}


def _login_screen() -> None:
    """نموذج تسجيل الدخول (بلا شبكة حتى الإرسال)."""
    render_brand_header(_safe_subtitle())
    st.caption(f"{t('username')}: admin · {t('password')}: admin123 (بيانات البذر الافتراضية)")
    with st.form("login_form"):
        username = st.text_input(t("username"), value="")
        password = st.text_input(t("password"), type="password", value="")
        submitted = st.form_submit_button(t("login"), type="primary")
    if not submitted:
        return
    try:
        result = APIClient().login(username.strip(), password)
    except APIError as exc:
        st.error(f"{t('login_failed')} — HTTP {exc.status_code}: {exc.detail}")
        return
    st.session_state[TOKEN_KEY] = result["access_token"]
    st.session_state[USER_KEY] = result["user"]
    st.session_state[CLIENT_KEY] = APIClient(token=result["access_token"])
    st.rerun()


def _navigation() -> None:
    """صفحات حسب الدور + عرضها عبر st.navigation."""
    user = st.session_state.get(USER_KEY) or {}
    allowed = ROLE_PAGES.get(user.get("role"), set())
    pages = [
        st.Page(path, title=t(label_key), icon=icon, default=(key == "dashboard"))
        for key, (path, icon, label_key) in _PAGE_DEFS.items()
        if key in allowed
    ]
    if not pages:  # دور غير معروف — لا صفحات
        st.error(t("no_data"))
        st.stop()
    st.session_state[SIDEBAR_FLAG] = False  # إعادة الضبط لكل تشغيل
    render_sidebar()
    st.session_state[SIDEBAR_FLAG] = True
    st.navigation(pages).run()


def main() -> None:
    """توجيه: دخول أو تنقل."""
    if not st.session_state.get(TOKEN_KEY):
        _login_screen()
        return
    _navigation()


main()
