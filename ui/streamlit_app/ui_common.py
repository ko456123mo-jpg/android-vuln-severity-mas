"""طبقة مشتركة لكل الصفحات — بوابة الجلسة + الشريط الجانبي + العميل.

نمطان مدعومان (مهم للاختبار بـ AppTest وللاستخدام الحقيقي):
    1) تشغيل عبر app.py (st.navigation): app.py يعرض الشريط الجانبي ويضبط
       st.session_state["_ui_sidebar_ready"]=True، فالصفحات لا تكرره.
    2) تشغيل الصفحة مستقلة (AppTest / streamlit run pages/XX.py): العلم غائب
       فتضيف الصفحة بنفسها بوابة اللغة/المستخدم — لا تكرار في الحالتين.

كل صفحة تبدأ بـ:
    import sys; from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from ui_common import page_setup
    client = page_setup("page_dashboard")
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import streamlit as st

from api_client import APIClient, APIError
from i18n import LANGUAGES, current_lang, inject_direction_css, set_lang, t

SIDEBAR_FLAG = "_ui_sidebar_ready"
CLIENT_KEY = "_api_client"
USER_KEY = "user"
TOKEN_KEY = "token"
ROLE_PAGES = {
    "admin": {
        "dashboard",
        "projects",
        "upload",
        "findings",
        "assessment",
        "reviews",
        "reports",
        "evaluation",
    },
    "analyst": {"dashboard", "projects", "upload", "findings", "assessment", "reports"},
    "reviewer": {"dashboard", "findings", "assessment", "reviews", "reports", "evaluation"},
}


#: مسار أيقونة الهوية (favicon.ico المهيّأ بأربعة أحجام) نسبةً إلى جذر المشروع
BRAND_FAVICON = Path(__file__).resolve().parents[2] / "assets" / "logo" / "favicon.ico"
BRAND_LOGO = Path(__file__).resolve().parents[2] / "assets" / "logo" / "logo.svg"

#: عنوان الصفحة واسم اللوحة من هوية المشروع (مصدر واحد)
APP_PAGE_TITLE = "Android Vuln Severity MAS"


def page_icon() -> str:
    """أيقونة الصفحة من ملفات الهوية إن وُجدت، وإلا رمز احتياطي (لا كسر للواجهة)."""
    return str(BRAND_FAVICON) if BRAND_FAVICON.exists() else "🛡️"


def render_brand_header(subtitle: str | None = None) -> None:
    """ترويسة الهوية داخل الصفحة: الشعار النصي الأصلي (SVG) + العنوان + الشعاري.

    تُستخدم في صفحة الدخول واللوحة الرئيسية؛ تتدهور بأمان إلى عنوان نصي إن غاب
    ملف الشعار (مثل تشغيل مقصوص الشجرة).
    """
    if BRAND_LOGO.exists():
        st.image(str(BRAND_LOGO), width=132)
    st.markdown(f"### {APP_PAGE_TITLE}")
    if subtitle:
        st.caption(subtitle)


def set_page_config_once() -> None:
    """set_page_config مرة واحدة لكل تشغيل (app.py أو الصفحة أيهما أسبق)."""
    try:
        st.set_page_config(
            page_title=APP_PAGE_TITLE,
            page_icon=page_icon(),
            layout="wide",
            initial_sidebar_state="expanded",
        )
    except Exception:  # noqa: BLE001 — app.py سبق الصفحة في هذا التشغيل
        pass


def _sidebar_language_widget() -> None:
    """مُبدِّل اللغة (عربي/إنجليزي) في الشريط الجانبي."""
    options = list(LANGUAGES.keys())
    index = options.index(current_lang()) if current_lang() in options else 0
    choice = st.sidebar.radio(
        t("language"),
        options=options,
        index=index,
        format_func=lambda code: LANGUAGES[code],
        key="_lang_choice",
    )
    if choice != current_lang():
        set_lang(choice)
        st.rerun()


def render_sidebar() -> None:
    """الشريط الجانبي المشترك: العنوان + اللغة + المستخدم + خروج."""
    st.sidebar.title("🛡️ " + t("app_title"))
    _sidebar_language_widget()
    user = st.session_state.get(USER_KEY)
    if user:
        st.sidebar.caption(f"{t('logged_in_as')}: **{user.get('username')}** ({t('role')}: {user.get('role')})")
        if st.sidebar.button(t("logout"), key="_logout_btn"):
            client = st.session_state.get(CLIENT_KEY)
            if client is not None:
                try:
                    client.logout()
                except APIError:  # خروج محلي رغم فشل الشبكة
                    pass
            for key in (TOKEN_KEY, USER_KEY, CLIENT_KEY):
                st.session_state.pop(key, None)
            st.session_state.pop(SIDEBAR_FLAG, None)
            st.rerun()
    st.sidebar.divider()


def get_client() -> APIClient:
    """عميل API للجلسة الحالية (يحمل التوكن)."""
    token = st.session_state.get(TOKEN_KEY)
    client = st.session_state.get(CLIENT_KEY)
    if client is None or client.token != token:
        client = APIClient(token=token)
        st.session_state[CLIENT_KEY] = client
    return client


def require_login() -> dict[str, Any]:
    """بوابة الجلسة — تُنهي الصفحة برسالة لطيفة إن لم يوجد توكن."""
    user = st.session_state.get(USER_KEY)
    if not st.session_state.get(TOKEN_KEY) or not user:
        st.warning(t("login_required"))
        st.stop()
    return user


def page_setup(page_key: str) -> APIClient:
    """تهيئة موحّدة للصفحة: إعداد + RTL + شريط جانبي + بوابة جلسة.

    تُعيد عميل API جاهزاً (مع التوكن).
    """
    set_page_config_once()
    inject_direction_css()
    if not st.session_state.get(SIDEBAR_FLAG):
        render_sidebar()
    require_login()
    _enforce_role(page_key)
    return get_client()


def _enforce_role(page_key: str) -> None:
    """تحقق دور مبدئي في الواجهة (الحماية الفعلية على الـ API نفسه)."""
    user = st.session_state.get(USER_KEY) or {}
    allowed = ROLE_PAGES.get(user.get("role"), set())
    if page_key not in allowed:
        st.error(f"{t('error')}: {t('role')} '{user.get('role')}' — {page_key}")
        st.stop()


def show_error(exc: Exception) -> None:
    """عرض موحّد لأخطاء API (بلا تسريب داخلي)."""
    if isinstance(exc, APIError):
        st.error(f"{t('error')} (HTTP {exc.status_code}): {exc.detail}")
    else:
        st.error(f"{t('error')}: {exc}")


def human_size(num_bytes: int | None) -> str:
    """حجم مقروء (KB/MB)."""
    if not num_bytes:
        return "—"
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.1f} MB"
