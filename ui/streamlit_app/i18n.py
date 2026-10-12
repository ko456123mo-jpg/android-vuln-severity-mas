"""دعم اللغتين (عربي/إنجليزي) + RTL — واجهة Streamlit (المرحلة 6).

الاستخدام:
    from i18n import t, inject_direction_css, LANGUAGES
    st.write(t("dashboard_title"))

اللغة الحالية في st.session_state["lang"] (الافتراضي "ar" لأن الجمهور عربي).
inject_direction_css تُحقن مرة في كل تشغيل من ui_common.page_setup.
"""
from __future__ import annotations

from typing import Any

import streamlit as st

DEFAULT_LANG = "ar"
LANGUAGES = {"ar": "العربية", "en": "English"}

TRANSLATIONS: dict[str, dict[str, str]] = {
    # عام
    "app_title": {"ar": "نظام تقييم خطورة ثغرات أندرويد", "en": "Android Vuln Severity MAS"},
    "app_subtitle": {
        "ar": "نظام متعدد الوكلاء لتقييم خطورة ثغرات تطبيقات أندرويد — متوافق مع OWASP MASVS",
        "en": "Multi-Agent Vulnerability Severity Assessment for Android Applications — OWASP MASVS aligned",
    },
    "login": {"ar": "تسجيل الدخول", "en": "Log in"},
    "logout": {"ar": "تسجيل الخروج", "en": "Log out"},
    "username": {"ar": "اسم المستخدم", "en": "Username"},
    "password": {"ar": "كلمة المرور", "en": "Password"},
    "login_failed": {"ar": "فشل تسجيل الدخول — تحقق من البيانات", "en": "Login failed — check credentials"},
    "login_required": {"ar": "الرجاء تسجيل الدخول أولاً من الصفحة الرئيسية", "en": "Please log in from the main page first"},
    "logged_in_as": {"ar": "مسجل الدخول باسم", "en": "Logged in as"},
    "language": {"ar": "اللغة", "en": "Language"},
    "refresh": {"ar": "تحديث", "en": "Refresh"},
    "loading": {"ar": "جارٍ التحميل…", "en": "Loading…"},
    "no_data": {"ar": "لا توجد بيانات لعرضها", "en": "No data to display"},
    "error": {"ar": "خطأ", "en": "Error"},
    "success": {"ar": "تم بنجاح", "en": "Success"},
    "back": {"ar": "رجوع", "en": "Back"},
    "role": {"ar": "الدور", "en": "Role"},
    # التنقل والصفحات
    "nav_home": {"ar": "الرئيسية", "en": "Home"},
    "page_dashboard": {"ar": "لوحة المعلومات", "en": "Dashboard"},
    "page_projects": {"ar": "المشاريع والتطبيقات", "en": "Projects & Apps"},
    "page_upload": {"ar": "رفع APK وفحص جديد", "en": "Upload APK & Scan"},
    "page_findings": {"ar": "الثغرات", "en": "Findings"},
    "page_assessment": {"ar": "تفاصيل التقييم", "en": "Assessment Detail"},
    "page_reviews": {"ar": "قائمة المراجعة", "en": "Review Queue"},
    "page_reports": {"ar": "التقارير", "en": "Reports"},
    "page_evaluation": {"ar": "التقييم البحثي", "en": "Evaluation"},
    "home_welcome": {"ar": "مرحباً بك في نظام تقييم خطورة ثغرات تطبيقات أندرويد", "en": "Welcome to the Android Vulnerability Severity MAS"},
    "home_hint": {"ar": "اختر صفحة من القائمة الجانبية للبدء.", "en": "Pick a page from the sidebar to start."},
    # لوحة المعلومات
    "kpi_projects": {"ar": "المشاريع", "en": "Projects"},
    "kpi_apps": {"ar": "التطبيقات", "en": "Applications"},
    "kpi_scans": {"ar": "الفحوصات", "en": "Scans"},
    "kpi_vulns": {"ar": "الثغرات", "en": "Vulnerabilities"},
    "kpi_pending": {"ar": "مراجعات معلّقة", "en": "Pending reviews"},
    "severity_chart_title": {"ar": "توزيع الخطورة", "en": "Severity distribution"},
    "recent_scans_title": {"ar": "آخر 10 فحوصات", "en": "Last 10 scans"},
    "top_vulns_title": {"ar": "أعلى 10 ثغرات خطورة", "en": "Top 10 vulnerabilities"},
    "avg_score": {"ar": "متوسط الدرجة", "en": "Average score"},
    # المشاريع والتطبيقات
    "projects_title": {"ar": "المشاريع", "en": "Projects"},
    "new_project": {"ar": "مشروع جديد", "en": "New project"},
    "project_name": {"ar": "اسم المشروع", "en": "Project name"},
    "description": {"ar": "الوصف", "en": "Description"},
    "create": {"ar": "إنشاء", "en": "Create"},
    "project_created": {"ar": "أُنشئ المشروع", "en": "Project created"},
    "archive_project": {"ar": "أرشفة المشروع", "en": "Archive project"},
    "applications_title": {"ar": "التطبيقات", "en": "Applications"},
    "app_context_title": {"ar": "سياق التطبيق التشغيلي", "en": "Application context"},
    "context_updated": {"ar": "حُدِّث السياق وأُعيد حساب درجته", "en": "Context updated and score recomputed"},
    "context_score": {"ar": "درجة السياق", "en": "Context score"},
    "save": {"ar": "حفظ", "en": "Save"},
    # الرفع والفحص
    "upload_title": {"ar": "رفع APK", "en": "Upload APK"},
    "upload_file": {"ar": "ملف APK", "en": "APK file"},
    "upload_submit": {"ar": "رفع الملف", "en": "Upload"},
    "upload_done": {"ar": "تم رفع الملف", "en": "File uploaded"},
    "upload_duplicate": {"ar": "الملف مرفوع مسبقاً (نفس SHA-256) — أُعيد السجل القائم", "en": "Duplicate file (same SHA-256) — existing record returned"},
    "sha256": {"ar": "بصمة SHA-256", "en": "SHA-256"},
    "file_size": {"ar": "الحجم", "en": "Size"},
    "scan_type": {"ar": "نوع الفحص", "en": "Scan type"},
    "scan_type_static": {"ar": "ساكن (Static)", "en": "Static"},
    "scan_type_dynamic": {"ar": "ديناميكي (Dynamic)", "en": "Dynamic"},
    "scan_type_comprehensive": {"ar": "شامل (Comprehensive)", "en": "Comprehensive"},
    "start_scan": {"ar": "بدء الفحص", "en": "Start scan"},
    "scan_started": {"ar": "بدأ الفحص — تابع التقدم", "en": "Scan started — follow progress"},
    "scan_progress": {"ar": "تقدم الفحص", "en": "Scan progress"},
    "scan_status": {"ar": "حالة الفحص", "en": "Scan status"},
    "scan_finished": {"ar": "انتهى الفحص", "en": "Scan finished"},
    "current_stage": {"ar": "المرحلة الحالية", "en": "Current stage"},
    # الثغرات
    "findings_title": {"ar": "ثغرات الفحص", "en": "Scan findings"},
    "select_scan": {"ar": "اختر فحصاً", "en": "Select a scan"},
    "filter_severity": {"ar": "تصفية بالخطورة", "en": "Filter by severity"},
    "filter_masvs": {"ar": "تصفية بفئة MASVS", "en": "Filter by MASVS"},
    "search_text": {"ar": "بحث بعنوان/CWE", "en": "Search title/CWE"},
    "view_details": {"ar": "عرض التفاصيل", "en": "View details"},
    "confirmed_dynamic": {"ar": "مؤكد ديناميكياً", "en": "Dynamically confirmed"},
    "masvs_chart_title": {"ar": "توزيع فئات MASVS", "en": "MASVS categories"},
    # تفاصيل التقييم
    "assessment_title": {"ar": "تفاصيل التقييم", "en": "Assessment detail"},
    "equation_title": {"ar": "تفكيك المعادلة", "en": "Score equation breakdown"},
    "confidence_title": {"ar": "تفصيل عامل الثقة", "en": "Confidence breakdown"},
    "evidence_title": {"ar": "الأدلة", "en": "Evidence"},
    "rationale_title": {"ar": "تفسير الوكيل (Reasoning)", "en": "Agent reasoning"},
    "final_score": {"ar": "الدرجة النهائية", "en": "Final score"},
    "base_score": {"ar": "الدرجة الأساسية", "en": "Base score"},
    "evidence_score": {"ar": "درجة الأدلة", "en": "Evidence score"},
    "review_status": {"ar": "حالة المراجعة", "en": "Review status"},
    # المراجعة
    "review_queue_title": {"ar": "قائمة المراجعة البشرية", "en": "Human review queue"},
    "pending_count": {"ar": "عدد المعلّق", "en": "Pending"},
    "select_assessment": {"ar": "اختر تقييماً للمراجعة", "en": "Select an assessment"},
    "correction_severity": {"ar": "الخطورة المصحَّحة", "en": "Corrected severity"},
    "correction_score": {"ar": "الدرجة المصحَّحة", "en": "Corrected score"},
    "correction_reason": {"ar": "سبب التصحيح", "en": "Correction reason"},
    "submit_correction": {"ar": "حفظ التصحيح", "en": "Save correction"},
    "correction_saved": {"ar": "حُفظ التصحيح وأُنشئ مثال تعلّم تلقائياً", "en": "Correction saved; feedback example created"},
    "previous_corrections": {"ar": "التصحيحات السابقة", "en": "Previous corrections"},
    "system_vs_human": {"ar": "النظام مقابل المراجع البشري", "en": "System vs human reviewer"},
    # التقارير
    "reports_title": {"ar": "التقارير", "en": "Reports"},
    "generate_reports": {"ar": "توليد التقارير", "en": "Generate reports"},
    "reports_generated": {"ar": "وُلِّدت التقارير الستة", "en": "All six report files generated"},
    "technical_report": {"ar": "التقرير الفني (EN)", "en": "Technical report"},
    "executive_report": {"ar": "التقرير التنفيذي (AR)", "en": "Executive report"},
    "download": {"ar": "تنزيل", "en": "Download"},
    # التقييم البحثي
    "evaluation_title": {"ar": "التقييم البحثي", "en": "Research evaluation"},
    "evaluation_phase7": {"ar": "مقاييس الاتفاق (Cohen's Kappa / Gwet's AC1) ومنحنى التعلم ضمن المرحلة 7 — تُعرض هنا بيانات الحلقة الحالية إلى حينها.", "en": "Agreement metrics (Cohen's Kappa / Gwet's AC1) and learning curve arrive in Phase 7 — current feedback-loop data is shown meanwhile."},
    "corrections_total": {"ar": "إجمالي التصحيحات", "en": "Total corrections"},
    "feedback_examples": {"ar": "أمثلة التعلّم النشطة", "en": "Active feedback examples"},
    "corrections_timeline": {"ar": "خط زمني للتصحيحات", "en": "Corrections timeline"},
    # التقييم البحثي — نتائج التجربة (المرحلة 7)
    "evaluation_intro": {"ar": "طبقة القياس البحثي: مقاييس الاتفاق (Weighted Kappa / Gwet AC1) ودقة الكشف من نتائج التجربة الفعلية.", "en": "Research measurement layer: agreement metrics (Weighted Kappa / Gwet AC1) and detection quality from real experiment results."},
    "tab_experiment": {"ar": "نتائج التجربة", "en": "Experiment results"},
    "tab_feedback_ab": {"ar": "اختبار A/B للتغذية الراجعة", "en": "Feedback A/B test"},
    "tab_live": {"ar": "الحلقة الحالية", "en": "Live feedback loop"},
    "evaluation_no_results": {"ar": "لا نتائج تجربة بعد — شغّل سكربتات القياس ثم أعد فتح الصفحة", "en": "No experiment results yet — run the evaluation scripts, then reopen this page"},
    "evaluation_how_to_run": {"ar": "أوامر التشغيل:", "en": "How to run:"},
    "mode_label": {"ar": "الوضع", "en": "Mode"},
    "apps_gt_filled": {"ar": "تطبيقات بحقيقة مرجعية", "en": "Apps with ground truth"},
    "macro_f1": {"ar": "F1 ماكروي", "en": "Macro F1"},
    "weighted_kappa": {"ar": "Weighted κ", "en": "Weighted κ"},
    "gwet_ac1": {"ar": "Gwet's AC1", "en": "Gwet's AC1"},
    "percent_agreement": {"ar": "نسبة الاتفاق", "en": "Percent agreement"},
    "interpretation": {"ar": "التفسير (Landis & Koch)", "en": "Interpretation (Landis & Koch)"},
    "detection_per_app": {"ar": "دقة الكشف لكل تطبيق (RQ1)", "en": "Per-app detection quality (RQ1)"},
    "agreement_table": {"ar": "مقاييس الاتفاق مع فترات الثقة (RQ2)", "en": "Agreement metrics with CIs (RQ2)"},
    "confusion_matrix": {"ar": "مصفوفة الالتباس", "en": "Confusion matrix"},
    "figures_download": {"ar": "تنزيل رسوم التحليل (HTML تفاعلي)", "en": "Download analysis figures (interactive HTML)"},
    "report_download": {"ar": "تنزيل تقرير التجربة (REPORT.md)", "en": "Download experiment report (REPORT.md)"},
    "gt_pending_banner": {"ar": "الحقيقة المرجعية غير مُملأة بعد — أرقام الكشف والاتفاق ستكون فارغة حتى إملاء ملفات ground_truth يدوياً.", "en": "Ground truth is not filled yet — detection/agreement numbers stay empty until ground_truth files are filled manually."},
    "feedback_ab_title": {"ar": "اختبار A/B: بلا أمثلة (A) مقابل مع أمثلة (B)", "en": "A/B test: without examples (A) vs with examples (B)"},
    "feedback_ab_insufficient": {"ar": "بيانات غير كافية للاختبار المزدوج بعد (الحد الأدنى 3 أزواج بعد العتبة).", "en": "Not enough data for the paired test yet (minimum 3 pairs after the threshold)."},
    "paired_stat": {"ar": "المتغير", "en": "Statistic"},
    "paired_value": {"ar": "القيمة", "en": "Value"},
    "total_corrections": {"ar": "تصحيحات في القاعدة", "en": "Corrections in DB"},
}


def current_lang() -> str:
    """اللغة الحالية من حالة الجلسة."""
    return st.session_state.get("lang", DEFAULT_LANG)


def set_lang(lang: str) -> None:
    """تغيير اللغة (ar/en)."""
    if lang in LANGUAGES:
        st.session_state["lang"] = lang


def t(key: str, **fmt: Any) -> str:
    """ترجمة مفتاح حسب اللغة الحالية — يُعيد المفتاح نفسه إن غاب (بلا كسر)."""
    entry = TRANSLATIONS.get(key)
    if entry is None:
        return key
    text = entry.get(current_lang()) or entry.get(DEFAULT_LANG) or key
    return text.format(**fmt) if fmt else text


def is_rtl() -> bool:
    """هل الاتجاه من اليمين لليسار؟"""
    return current_lang() == "ar"


def direction() -> str:
    """اتجاه النص الحالي."""
    return "rtl" if is_rtl() else "ltr"


RTL_CSS = """
<style>
    .stApp, .stMarkdown, .stTabs, section[data-testid="stSidebar"] {
        direction: rtl; text-align: right;
    }
    div[data-testid="stMetricValue"], div[data-testid="stMetricLabel"] {
        direction: rtl; text-align: right;
    }
    code, pre, .stCode { direction: ltr; text-align: left; }
</style>
"""


def inject_direction_css() -> None:
    """حقن CSS الاتجاه حسب اللغة (RTL للعربية)."""
    if is_rtl():
        st.markdown(RTL_CSS, unsafe_allow_html=True)
