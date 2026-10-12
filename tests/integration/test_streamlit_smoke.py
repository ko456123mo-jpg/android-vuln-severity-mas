"""اختبار دخان — صفحات Streamlit عبر AppTest (بلا شبكة حقيقية).

يُحاكى requests.request بحمولات ثابتة مطابقة لعقود الـ API، فتُشغَّل الصفحات
في عملية الاختبار نفسها (streamlit.testing.v1.AppTest) ويُتحقق من غياب
الاستثناءات وظهور العناصر الأساسية + بوابة الجلسة.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

UI_DIR = Path(__file__).resolve().parents[2] / "ui" / "streamlit_app"

FAKE_ROUTES: dict[str, object] = {
    "/dashboard/summary": {
        "total_projects": 2,
        "total_applications": 3,
        "total_scans": 4,
        "running_scans": 0,
        "total_vulnerabilities": 9,
        "total_assessments": 9,
        "pending_reviews": 6,
        "total_corrections": 1,
        "active_feedback_examples": 1,
        "avg_final_score": 7.92,
    },
    "/dashboard/severity_chart": [
        {"severity": "Critical", "count": 2},
        {"severity": "High", "count": 5},
        {"severity": "Medium", "count": 2},
        {"severity": "Low", "count": 0},
    ],
    "/dashboard/recent_scans": [
        {
            "scan_id": 4,
            "application_id": 1,
            "application_name": "InsecureBank",
            "package_name": "com.insecurebank.app",
            "project_name": "بنك",
            "status": "success",
            "started_at": "2026-10-11T22:00:00",
            "finished_at": "2026-10-11T22:05:00",
            "total_duration_ms": 4200,
            "error_message": None,
        }
    ],
    "/dashboard/top_vulns": [
        {
            "vulnerability_id": 2,
            "title": "Weak Crypto PBEWithMD5AndDES",
            "cwe_id": "CWE-327",
            "masvs_category": "MASVS-CRYPTO",
            "severity": "Critical",
            "final_score": 9.3626,
            "application_name": "InsecureBank",
        }
    ],
    "/dashboard/trends": {
        "days": 7,
        "scans": [{"date": "2026-10-11", "count": 2}],
        "vulnerabilities": [{"date": "2026-10-11", "count": 9}],
    },
    "/scans": [
        {"id": 4, "application_id": 1, "status": "success", "tools_used": ["jadx", "mobsf"]}
    ],
    "/scans/4/vulnerabilities": [
        {
            "id": 2,
            "application_id": 1,
            "title": "Weak Crypto PBEWithMD5AndDES",
            "description": "تشفير ضعيف",
            "masvs_category": "MASVS-CRYPTO",
            "cwe_id": "CWE-327",
            "status": "open",
            "discovered_at": "2026-10-11T22:01:00",
            "assessment": {
                "id": 2,
                "vulnerability_id": 2,
                "severity": "Critical",
                "final_score": 9.3626,
                "review_status": "pending",
                "assessed_by": "agent",
            },
            "evidence": {"findings_count": 2, "tools": ["jadx", "frida"]},
        }
    ],
    "/findings/2": {
        "id": 2,
        "application_id": 1,
        "title": "Weak Crypto PBEWithMD5AndDES",
        "description": "تشفير ضعيف",
        "masvs_category": "MASVS-CRYPTO",
        "cwe_id": "CWE-327",
        "status": "open",
        "discovered_at": "2026-10-11T22:01:00",
        "application_name": "InsecureBank",
        "package_name": "com.insecurebank.app",
        "evidence": {"findings_count": 2, "tools": ["jadx", "frida"]},
        "assessment": {
            "id": 2,
            "vulnerability_id": 2,
            "severity": "Critical",
            "final_score": 9.3626,
            "review_status": "pending",
            "assessed_by": "agent",
            "base_score": 9.8,
            "context_score": 7.2,
            "evidence_score": 9.1,
            "confidence_factor": 0.91,
            "rationale": "خطوات المعادلة…",
            "rule_version": "v1.1",
        },
    },
    "/findings/2/evidence": [
        {
            "id": 1,
            "vulnerability_id": 2,
            "scan_id": 4,
            "tool_id": 1,
            "tool_name": "jadx",
            "tool_category": "static",
            "tool_reliability": 0.9,
            "location": "MainActivity.java:42",
            "evidence_type": "static",
            "artifact_ref": None,
            "created_at": "2026-10-11T22:01:00",
        }
    ],
    "/findings/2/assessment": {
        "id": 2,
        "vulnerability_id": 2,
        "severity": "Critical",
        "final_score": 9.3626,
        "review_status": "pending",
        "assessed_by": "agent",
    },
    "/reviews/stats": {
        "pending": 6,
        "approved": 4,
        "rejected": 0,
        "pending_by_severity": {"Critical": 2},
        "corrections_total": 1,
        "feedback_examples_total": 1,
    },
    "/reviews/pending": [
        {
            "id": 2,
            "vulnerability_id": 2,
            "title": "Weak Crypto PBEWithMD5AndDES",
            "cwe_id": "CWE-327",
            "masvs_category": "MASVS-CRYPTO",
            "severity": "Critical",
            "final_score": 9.3626,
            "rationale": "معادلة…",
        }
    ],
    "/assessments/2": {
        "id": 2,
        "vulnerability_id": 2,
        "severity": "Critical",
        "final_score": 9.3626,
        "review_status": "approved",
        "assessed_by": "agent",
        "vuln_title": "Weak Crypto PBEWithMD5AndDES",
        "corrections": [
            {
                "id": 1,
                "reviewer_id": 1,
                "reviewer_username": "admin",
                "original_severity": "High",
                "corrected_severity": "Critical",
                "original_score": 8.2,
                "corrected_score": 9.7,
                "reason": "دليل ديناميكي مؤكد",
                "corrected_at": "2026-10-11T23:00:00",
            }
        ],
    },
    "/assessments/stats": {
        "total": 9,
        "severity_distribution": {"Critical": 2, "High": 5, "Medium": 2, "Low": 0},
        "review_status_counts": {"pending": 5, "approved": 4},
        "avg_final_score": 7.9228,
        "max_final_score": 9.3626,
        "min_final_score": 6.07,
    },
}


class _FakeResponse:
    """استجابة مزيّفة بعقد requests.Response المصغَّر."""

    status_code = 200
    content = b"{}"

    def __init__(self, payload: object) -> None:
        self._payload = payload

    def json(self) -> object:
        return self._payload


def _fake_request(method: str, url: str, **_kwargs: object) -> _FakeResponse:
    """موزّع مزيّف حسب المسار (يتجاهل الاستعلام والترويسات)."""
    path = url.split("8000", 1)[-1].split("?")[0]
    return _FakeResponse(FAKE_ROUTES.get(path, []))


def _logged_in(page_file: str) -> AppTest:
    """AppTest لصفحة مع جلسة admin وهمية."""
    app = AppTest.from_file(str(UI_DIR / page_file), default_timeout=60)
    app.session_state["token"] = "test-token"
    app.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
    app.session_state["lang"] = "ar"
    return app


@pytest.mark.parametrize("page", ["01_dashboard.py", "02_projects_apps.py", "03_upload_scan.py", "04_findings.py", "05_assessment_detail.py", "06_review_queue.py", "07_reports.py", "08_evaluation.py"])
def test_pages_render_without_exceptions(page: str) -> None:
    """كل الصفحات تُشغَّل بلا استثناءات مع API مزيّف."""
    page_path = f"pages/{page}"
    with patch("requests.request", side_effect=_fake_request):
        if page in ("02_projects_apps.py", "05_assessment_detail.py"):
            with patch.dict(
                FAKE_ROUTES,
                {
                    "/projects": [
                        {
                            "id": 1,
                            "name": "بنك",
                            "description": "تطبيق بنكي",
                            "status": "active",
                            "stats": {"applications": 1, "scans": 1, "vulnerabilities": 9},
                        }
                    ],
                    "/applications/1": {
                        "id": 1,
                        "project_id": 1,
                        "name": "InsecureBank",
                        "package_name": "com.insecurebank.app",
                        "sha256": "a" * 64,
                        "file_path": "/tmp/x.apk",
                        "file_size": 1024,
                        "app_category": "banking",
                        "app_context": {"context_score": 8.1, "industry": "banking"},
                    },
                    "/applications": [
                        {
                            "id": 1,
                            "project_id": 1,
                            "name": "InsecureBank",
                            "package_name": "com.insecurebank.app",
                            "sha256": "a" * 64,
                            "file_path": "/tmp/x.apk",
                            "file_size": 1024,
                            "app_category": "banking",
                        }
                    ],
                    "/assessments": [
                        {
                            "id": 2,
                            "vulnerability_id": 2,
                            "severity": "Critical",
                            "final_score": 9.3626,
                            "review_status": "pending",
                            "vuln_title": "Weak Crypto",
                        }
                    ],
                },
            ):
                app = _logged_in(page_path)
                app.run()
        else:
            app = _logged_in(page_path)
            app.run()
    assert not app.exception, f"{page}: {[str(e.value) for e in app.exception]}"


def test_login_screen_without_session() -> None:
    """app.py بلا جلسة: نموذج الدخول فقط."""
    app = AppTest.from_file(str(UI_DIR / "app.py"), default_timeout=60)
    app.run()
    assert not app.exception
    assert len(app.text_input) == 2
    assert any("تسجيل الدخول" in button.label for button in app.button)


def test_page_requires_login() -> None:
    """صفحة بلا جلسة: تحذير بوابة الجلسة ثم توقف (بلا استثناء)."""
    app = AppTest.from_file(str(UI_DIR / "pages" / "01_dashboard.py"), default_timeout=60)
    app.run()
    assert not app.exception
    assert any("تسجيل الدخول" in warning.value for warning in app.warning)


def test_dashboard_metrics_and_charts() -> None:
    """لوحة المعلومات: 5 شرائح KPI + رسوم بيانية."""
    with patch("requests.request", side_effect=_fake_request):
        app = _logged_in("pages/01_dashboard.py")
        app.run()
    assert not app.exception
    labels = [metric.label for metric in app.metric]
    assert len(labels) == 5
    assert any("الثغرات" in label for label in labels)
