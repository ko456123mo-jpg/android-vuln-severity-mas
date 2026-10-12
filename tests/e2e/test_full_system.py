"""اختبار شامل من الصفر / Full-system E2E (المرحلة 8).

سيناريو كامل عبر الـ API الحقيقي (TestClient على قاعدة اختبار معزولة):
    1) فحص الصحة          2) تسجيل دخول        3) مشروع جديد
    4) رفع APK            5) فحص كامل (مهمة خلفية + polling)
    6) مراجعة بشرية       7) تقرير (MD/HTML/PDF)  8) قياس إحصائي (مقاييس من وحدة
       التقييم على بيانات **اصطناعية داخل الاختبار** — ليست نتائج تجربة)

يُقاس الزمن الكلي للسيناريو ويُطبع في السجل (لا يُدَّعى رقم أداء ثابت).
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TERMINAL_STATUSES = {"success", "partial", "failed", "cancelled"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """عميل API مع عزل مجلد رفع APKs في مجلد مؤقت."""
    monkeypatch.setattr("api.routers.applications.APKS_DIR", tmp_path / "apks")
    from api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


def _login(client: TestClient) -> dict[str, str]:
    """تسجيل دخول admin وإرجاع ترويسة Bearer."""
    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _fake_apk() -> bytes:
    """بايتات APK وهمية فريدة (Mock لا يحلل الملف فعلياً)."""
    return b"PK\x03\x04" + uuid.uuid4().hex.encode() * 8


def _wait_for_scan(client: TestClient, headers: dict[str, str], scan_id: int, timeout_s: int = 90) -> dict:
    """استقصاء حالة الفحص حتى الوصول إلى حالة نهائية."""
    deadline = time.time() + timeout_s
    status: dict = {}
    while time.time() < deadline:
        status = client.get(f"/scans/{scan_id}/status", headers=headers).json()
        if status.get("status") in TERMINAL_STATUSES:
            return status
        time.sleep(0.5)
    pytest.fail(f"لم يصل الفحص لحالة نهائية خلال {timeout_s}s — آخر حالة: {status}")


def test_full_system_scenario(client: TestClient) -> None:
    """السيناريو الشامل من الصحة إلى القياس — بترتيب تنفيذ صريح."""
    scenario_started = time.perf_counter()

    # ── 1) فحص الصحة ────────────────────────────────────────────────
    health = client.get("/health")
    assert health.status_code == 200
    payload = health.json()
    assert payload["status"] == "ok" and payload["database"] == "ok"
    assert payload["version"] == "1.0.0"

    # ── 2) تسجيل الدخول ─────────────────────────────────────────────
    headers = _login(client)
    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200 and me.json()["username"] == "admin"

    # ── 3) مشروع جديد ───────────────────────────────────────────────
    project = client.post(
        "/projects",
        json={"name": f"E2E-{uuid.uuid4().hex[:6]}", "description": "اختبار شامل"},
        headers=headers,
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    # ── 4) رفع APK (مع التحقق من كشف التكرار) ──────────────────────
    apk_bytes = _fake_apk()
    upload = client.post(
        "/applications/upload",
        data={"project_id": str(project_id), "name": "E2E App", "package_name": "e2e.app"},
        files={"file": ("e2e.apk", apk_bytes, "application/vnd.android.package-archive")},
        headers=headers,
    )
    assert upload.status_code == 201, upload.text
    application = upload.json()["application"]
    application_id = application["id"]
    assert len(application["sha256"]) == 64

    duplicate = client.post(
        "/applications/upload",
        data={"project_id": str(project_id)},
        files={"file": ("e2e-copy.apk", apk_bytes, "application/vnd.android.package-archive")},
        headers=headers,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["deduplicated"] is True
    assert duplicate.json()["application"]["id"] == application_id

    # ── 5) فحص كامل ─────────────────────────────────────────────────
    started = client.post(
        "/scans/start",
        json={"application_id": application_id, "scan_type": "comprehensive"},
        headers=headers,
    )
    assert started.status_code == 202, started.text
    scan_id = started.json()["scan_id"]
    status = _wait_for_scan(client, headers, scan_id)
    assert status["status"] in {"success", "partial"}, status
    assert status["progress_percent"] == 100

    vulns = client.get(f"/scans/{scan_id}/vulnerabilities", headers=headers).json()
    assert len(vulns) > 0, "لا ثغرات — السيناريو لا يكتمل"
    assessments = client.get(f"/scans/{scan_id}/assessments", headers=headers).json()
    assert len(assessments) == len(vulns)
    detail = client.get(f"/scans/{scan_id}", headers=headers).json()
    assert detail["stats"]["vulnerabilities"] == len(vulns)

    # ── 6) مراجعة بشرية (تصحيح مع ثبات final_score) ──────────────────
    pending = client.get("/reviews/pending", headers=headers)
    assert pending.status_code == 200
    queue = pending.json()
    if not queue:
        # لا عناصر معلّقة في هذا التشغيل ⇒ نصحّح أول تقييم مباشرة
        queue = [{"id": row["id"], "severity": row["severity"]} for row in assessments]
    assessment_id = queue[0]["id"]
    before = client.get(f"/assessments/{assessment_id}", headers=headers).json()
    corrected = client.post(
        f"/reviews/{assessment_id}/correct",
        json={
            "corrected_severity": "Critical",
            "corrected_score": 9.4,
            "reason": "مراجعة خبير — اختبار شامل: رفع التصنيف بعد تحقق يدوي من الأثر",
        },
        headers=headers,
    )
    assert corrected.status_code == 200, corrected.text
    after = client.get(f"/assessments/{assessment_id}", headers=headers).json()
    assert after["final_score"] == before["final_score"], "final_score يجب ألا يُمَس"
    assert after["severity"] == "Critical"
    assert after["review_status"] == "approved", "التصحيح يعتمد التقييم (review_status=approved)"
    assert len(after.get("corrections") or []) >= 1
    review_stats = client.get("/reviews/stats", headers=headers).json()
    assert review_stats["corrections_total"] >= 1

    # ── 7) تقرير: توليد + تنزيل MD/HTML/PDF ─────────────────────────
    generated = client.post(f"/reports/{scan_id}/generate", headers=headers)
    assert generated.status_code == 200, generated.text
    files = generated.json().get("files") or {}
    assert len(files) >= 6
    for fmt in ("technical_md", "executive_md", "technical_html", "executive_html",
                "technical_pdf", "executive_pdf"):
        download = client.get(f"/reports/{scan_id}/download/{fmt}", headers=headers)
        assert download.status_code == 200, f"{fmt}: {download.status_code} {download.text[:200]}"
        assert len(download.content) > 200
    pdf = client.get(f"/reports/{scan_id}/download/technical_pdf", headers=headers)
    assert pdf.content[:4] == b"%PDF"
    arabic = client.get(f"/reports/{scan_id}/download/executive_md", headers=headers)
    assert any("ا" <= ch <= "ي" for ch in arabic.text), "التقرير التنفيذي يجب أن يكون عربياً"

    # ── 8) قياس إحصائي (بيانات اصطناعية داخل الاختبار — ليست نتائج تجربة) ──
    from evaluation.metrics import (
        gwet_ac1,
        percent_agreement,
        precision_recall_f1,
        weighted_cohens_kappa,
    )

    detection = precision_recall_f1(tp=8, fp=2, fn=4)  # قيم يعرفها الاختبار مسبقاً
    assert detection["precision"] == pytest.approx(0.8)
    assert detection["recall"] == pytest.approx(0.6667, abs=1e-4)
    assert detection["f1"] == pytest.approx(0.7273, abs=1e-4)

    synthetic_system = ["Low", "Medium", "High", "Critical", "High", "Medium"]
    synthetic_expert = ["Low", "Medium", "High", "High", "Critical", "Medium"]
    assert percent_agreement(synthetic_system, synthetic_expert) == pytest.approx(0.6667, abs=1e-4)  # 4/6
    kappa = weighted_cohens_kappa(synthetic_system, synthetic_expert)
    ac1 = gwet_ac1(synthetic_system, synthetic_expert)
    assert -0.2 <= kappa <= 1.0 and -0.2 <= ac1 <= 1.0

    # ── لوحة المعلومات تعكس ما أُنشئ فعلاً ──────────────────────────
    summary = client.get("/dashboard/summary", headers=headers).json()
    assert summary["total_projects"] >= 1 and summary["total_applications"] >= 1
    assert summary["total_vulnerabilities"] >= len(vulns)
    assert summary["total_corrections"] >= 1
    assert summary["active_feedback_examples"] >= 1, "التصحيح يولّد مثال Few-Shot تلقائياً"

    elapsed = time.perf_counter() - scenario_started
    print(
        f"\n[E2E] السيناريو الكامل: {elapsed:.2f}s | ثغرات={len(vulns)} | "
        f"تقييمات={len(assessments)} | κ={kappa} | AC1={ac1} | تقارير={len(files)}"
    )


def test_e2e_authorization_boundaries(client: TestClient) -> None:
    """حدود الصلاحيات ضمن السيناريو: بلا توثيق ⇒ 401 على كل مسار حساس."""
    for path in ("/projects", "/applications", "/scans", "/reviews/pending", "/dashboard/summary"):
        response = client.get(path)
        assert response.status_code == 401, f"{path} يجب أن يرفض بلا توثيق"
    reports = client.post("/reports/1/generate")
    assert reports.status_code in (401, 403, 404)
