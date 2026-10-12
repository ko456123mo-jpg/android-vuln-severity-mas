"""عميل REST لواجهة Streamlit — كل استدعاءات الـ API في مكان واحد (المرحلة 6).

- العنوان: متغير البيئة MAS_API_URL ثم الافتراضي http://127.0.0.1:8000
  (الطلبات تخرج من خادم Streamlit لا من المتصفح — localhost صحيح هنا).
- التوكن: يُمرَّر في البناء ويُلحق تلقائياً كـ Bearer.
- كل الدوال ترفع APIError(status, detail, path) عند فشل الطلب — الواجهة تعرضها.

يُستخدم requests.request مباشرة (لا Session مشتركة) ليتيح للاختبارات
محاكاة الشبكة عبر patch("requests.request").
"""
from __future__ import annotations

import os
from typing import Any, Optional

import requests

DEFAULT_BASE_URL = os.getenv("MAS_API_URL", "http://127.0.0.1:8000")
DEFAULT_TIMEOUT = 30


class APIError(Exception):
    """خطأ استدعاء API — يحمل حالة HTTP ورسالة الخادم."""

    def __init__(self, status_code: int, detail: Any, path: str) -> None:
        self.status_code = status_code
        self.detail = detail
        self.path = path
        super().__init__(f"{path} → HTTP {status_code}: {detail}")


class APIClient:
    """عميل API — يُبنى مرة لكل جلسة ومعه التوكن الحالي."""

    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.token = token

    # ── الأساس ────────────────────────────────────────────────────────
    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        raw: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Any:
        """يطلب نقطة نهاية ويرفع APIError عند الفشل؛ raw=True يعيد bytes."""
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            response = requests.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                json=json,
                params=params,
                data=data,
                files=files,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise APIError(0, f"تعذر الوصول إلى الخادم: {exc}", path) from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text[:300])
            except Exception:  # noqa: BLE001 — جسم غير JSON
                detail = response.text[:300]
            raise APIError(response.status_code, detail, path)
        if raw:
            return response.content
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def _get(self, path: str, **kw: Any) -> Any:
        return self._request("GET", path, **kw)

    def _post(self, path: str, **kw: Any) -> Any:
        return self._request("POST", path, **kw)

    def _put(self, path: str, **kw: Any) -> Any:
        return self._request("PUT", path, **kw)

    def _delete(self, path: str, **kw: Any) -> Any:
        return self._request("DELETE", path, **kw)

    # ── المصادقة ──────────────────────────────────────────────────────
    def login(self, username: str, password: str) -> dict[str, Any]:
        """تسجيل الدخول → {access_token, token_type, user}."""
        result = self._post("/auth/login", json={"username": username, "password": password})
        self.token = result.get("access_token")
        return result

    def me(self) -> dict[str, Any]:
        """بيانات المستخدم الحالي."""
        return self._get("/auth/me")

    def logout(self) -> dict[str, Any]:
        """خروج منطقي (JWT stateless)."""
        return self._post("/auth/logout")

    def register(self, username: str, password: str, role: str, email: str | None = None) -> dict[str, Any]:
        """إنشاء مستخدم (admin فقط)."""
        return self._post(
            "/auth/register",
            json={"username": username, "password": password, "role": role, "email": email},
        )

    # ── المشاريع ──────────────────────────────────────────────────────
    def list_projects(self, include_archived: bool = False) -> list[dict[str, Any]]:
        """سرد المشاريع."""
        return self._get("/projects", params={"include_archived": include_archived})

    def create_project(self, name: str, description: str | None = None) -> dict[str, Any]:
        """إنشاء مشروع."""
        return self._post("/projects", json={"name": name, "description": description})

    def get_project(self, project_id: int) -> dict[str, Any]:
        """تفاصيل مشروع."""
        return self._get(f"/projects/{project_id}")

    def update_project(self, project_id: int, **fields: Any) -> dict[str, Any]:
        """تعديل مشروع."""
        return self._put(f"/projects/{project_id}", json=fields)

    def delete_project(self, project_id: int) -> dict[str, Any]:
        """أرشفة مشروع (حذف ناعم)."""
        return self._delete(f"/projects/{project_id}")

    # ── التطبيقات ─────────────────────────────────────────────────────
    def list_applications(self, project_id: int | None = None) -> list[dict[str, Any]]:
        """سرد التطبيقات (فلترة اختيارية بالمشروع)."""
        params = {"project_id": project_id} if project_id is not None else None
        return self._get("/applications", params=params)

    def upload_apk(
        self,
        project_id: int,
        filename: str,
        content: bytes,
        name: str | None = None,
        package_name: str | None = None,
        version: str | None = None,
        app_category: str | None = None,
    ) -> dict[str, Any]:
        """رفع APK — يعيد {created, deduplicated, application}."""
        form = {"project_id": str(project_id)}
        for key, value in (
            ("name", name),
            ("package_name", package_name),
            ("version", version),
            ("app_category", app_category),
        ):
            if value:
                form[key] = value
        return self._post(
            "/applications/upload",
            files={"file": (filename, content, "application/vnd.android.package-archive")},
            data=form,
            timeout=120,
        )

    def get_application(self, application_id: int) -> dict[str, Any]:
        """تفاصيل تطبيق + سياقه."""
        return self._get(f"/applications/{application_id}")

    def update_app_context(self, application_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """تحديث سياق التطبيق (يعيد حساب context_score)."""
        return self._put(f"/applications/{application_id}/context", json=payload)

    def list_application_scans(self, application_id: int) -> list[dict[str, Any]]:
        """فحوص تطبيق."""
        return self._get(f"/applications/{application_id}/scans")

    def delete_application(self, application_id: int) -> dict[str, Any]:
        """حذف تطبيق (409 إن وُجدت فحوص)."""
        return self._delete(f"/applications/{application_id}")

    # ── الفحوصات ──────────────────────────────────────────────────────
    def list_scans(self, application_id: int | None = None, status: str | None = None) -> list[dict[str, Any]]:
        """سرد الفحوصات."""
        params: dict[str, Any] = {}
        if application_id is not None:
            params["application_id"] = application_id
        if status:
            params["status"] = status
        return self._get("/scans", params=params or None)

    def start_scan(
        self, application_id: int, scan_type: str = "comprehensive", user_request: str | None = None
    ) -> dict[str, Any]:
        """بدء فحص في الخلفية → {scan_id, status, ...}."""
        return self._post(
            "/scans/start",
            json={
                "application_id": application_id,
                "scan_type": scan_type,
                "user_request": user_request,
            },
        )

    def get_scan(self, scan_id: int) -> dict[str, Any]:
        """تفاصيل فحص."""
        return self._get(f"/scans/{scan_id}")

    def get_scan_status(self, scan_id: int) -> dict[str, Any]:
        """حالة الفحص الحيّة (polling)."""
        return self._get(f"/scans/{scan_id}/status")

    def get_scan_vulnerabilities(self, scan_id: int) -> list[dict[str, Any]]:
        """ثغرات فحص."""
        return self._get(f"/scans/{scan_id}/vulnerabilities")

    def get_scan_assessments(self, scan_id: int) -> list[dict[str, Any]]:
        """تقييمات فحص."""
        return self._get(f"/scans/{scan_id}/assessments")

    def cancel_scan(self, scan_id: int) -> dict[str, Any]:
        """إلغاء فحص معلّق/جارٍ."""
        return self._delete(f"/scans/{scan_id}")

    # ── الثغرات ───────────────────────────────────────────────────────
    def get_vulnerability(self, vuln_id: int) -> dict[str, Any]:
        """تفاصيل ثغرة."""
        return self._get(f"/findings/{vuln_id}")

    def get_vulnerability_evidence(self, vuln_id: int) -> list[dict[str, Any]]:
        """أدلة الثغرة."""
        return self._get(f"/findings/{vuln_id}/evidence")

    def get_vulnerability_assessment(self, vuln_id: int) -> dict[str, Any]:
        """تقييم الثغرة."""
        return self._get(f"/findings/{vuln_id}/assessment")

    # ── التقييمات ─────────────────────────────────────────────────────
    def list_assessments(
        self, severity: str | None = None, review_status: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        """سرد التقييمات مع فلترة."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        if review_status:
            params["review_status"] = review_status
        return self._get("/assessments", params=params)

    def assessment_stats(self) -> dict[str, Any]:
        """إحصاءات التقييمات."""
        return self._get("/assessments/stats")

    def get_assessment(self, assessment_id: int) -> dict[str, Any]:
        """تفاصيل تقييم + تصحيحاته."""
        return self._get(f"/assessments/{assessment_id}")

    # ── المراجعة البشرية ──────────────────────────────────────────────
    def pending_reviews(self, limit: int = 50, severity: str | None = None) -> list[dict[str, Any]]:
        """قائمة المراجعات المعلّقة."""
        params: dict[str, Any] = {"limit": limit}
        if severity:
            params["severity"] = severity
        return self._get("/reviews/pending", params=params)

    def submit_correction(
        self, assessment_id: int, corrected_severity: str, corrected_score: float, reason: str
    ) -> dict[str, Any]:
        """إرسال تصحيح بشري (ينشئ feedback_example تلقائياً)."""
        return self._post(
            f"/reviews/{assessment_id}/correct",
            json={
                "corrected_severity": corrected_severity,
                "corrected_score": corrected_score,
                "reason": reason,
            },
        )

    def review_stats(self) -> dict[str, Any]:
        """إحصاءات قائمة المراجعة."""
        return self._get("/reviews/stats")

    # ── التقارير ──────────────────────────────────────────────────────
    def generate_reports(self, scan_id: int) -> dict[str, Any]:
        """توليد الملفات الستة."""
        return self._post(f"/reports/{scan_id}/generate")

    def get_technical_report(self, scan_id: int) -> dict[str, Any]:
        """التقرير الفني (JSON)."""
        return self._get(f"/reports/{scan_id}/technical")

    def get_executive_report(self, scan_id: int) -> dict[str, Any]:
        """التقرير التنفيذي (JSON)."""
        return self._get(f"/reports/{scan_id}/executive")

    def download_report(self, scan_id: int, fmt: str) -> bytes:
        """تنزيل ملف تقرير (md/html/pdf) كبايتات."""
        return self._get(f"/reports/{scan_id}/download/{fmt}", raw=True)

    # ── لوحة المعلومات ────────────────────────────────────────────────
    def summary(self) -> dict[str, Any]:
        """KPIs عامة."""
        return self._get("/dashboard/summary")

    def severity_chart(self) -> list[dict[str, Any]]:
        """توزيع الخطورة."""
        return self._get("/dashboard/severity_chart")

    def recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        """آخر الفحوصات."""
        return self._get("/dashboard/recent_scans", params={"limit": limit})

    def top_vulns(self, limit: int = 10) -> list[dict[str, Any]]:
        """أعلى الثغرات خطورة."""
        return self._get("/dashboard/top_vulns", params={"limit": limit})

    def trends(self, days: int = 7) -> dict[str, Any]:
        """اتجاهات زمنية."""
        return self._get("/dashboard/trends", params={"days": days})

    # ── الصحة ─────────────────────────────────────────────────────────
    def health(self) -> dict[str, Any]:
        """فحص صحة الخادم (بلا توكن)."""
        return self._request("GET", "/health")
