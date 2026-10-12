"""اختبار تكامل E2E — السيناريو الكامل عبر HTTP (المرحلة 6).

المسار: دخول → مشروع → رفع APK → بدء فحص (Background) → polling الحالة →
ثغرات → تقييمات → تفاصيل ثغرة/أدلة → تصحيح بشري (ثبات final_score) →
تقارير (6 ملفات + PDF) → لوحة معلومات.

يعمل بالكامل في Mock Mode (قاعدة مؤقتة + LLM/MCP مزيّفان — conftest).
"""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

POLL_MAX_ITERATIONS = 120
POLL_INTERVAL_SECONDS = 0.5


def _fake_apk() -> tuple[str, bytes]:
    """اسم + محتوى APK وهمي فريد (يتفادى منع التكرار عبر التشغيلات)."""
    token = uuid.uuid4().hex
    return f"e2e_{token}.apk", b"PK\x03\x04" + token.encode() + b"\x00" * 32


@pytest.fixture()
def client(tmp_path, monkeypatch) -> TestClient:
    """TestClient مع توجيه مخزن APK إلى مجلد مؤقت."""
    monkeypatch.setattr("api.routers.applications.APKS_DIR", tmp_path / "apks")
    from api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def headers(client: TestClient) -> dict[str, str]:
    """جلسة admin."""
    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _poll_until_final(client: TestClient, headers: dict[str, str], scan_id: int) -> dict:
    """polling حتى خروج الفحص من pending/running."""
    status: dict = {}
    for _ in range(POLL_MAX_ITERATIONS):
        status = client.get(f"/scans/{scan_id}/status", headers=headers).json()
        if status["status"] not in ("pending", "running"):
            return status
        time.sleep(POLL_INTERVAL_SECONDS)
    return status


def test_full_api_e2e(client: TestClient, headers: dict[str, str]) -> None:
    """السيناريو الكامل من الدخول حتى التقارير."""
    # ── 1) المشروع ──────────────────────────────────────────────────
    project = client.post(
        "/projects", headers=headers, json={"name": f"مشروع E2E {uuid.uuid4().hex[:6]}"}
    ).json()
    assert project["id"] > 0

    # ── 2) رفع APK ──────────────────────────────────────────────────
    filename, content = _fake_apk()
    upload = client.post(
        "/applications/upload",
        headers=headers,
        data={"project_id": str(project["id"]), "name": "E2E App", "package_name": "com.e2e.app"},
        files={"file": (filename, content, "application/vnd.android.package-archive")},
    )
    assert upload.status_code == 201, upload.text
    application = upload.json()["application"]
    assert len(application["sha256"]) == 64
    assert application["file_size"] == len(content)

    # رفع مكرر → deduplicated بلا سجل جديد
    duplicate = client.post(
        "/applications/upload",
        headers=headers,
        data={"project_id": str(project["id"])},
        files={"file": (filename, content, "application/vnd.android.package-archive")},
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["created"] is False
    assert duplicate.json()["deduplicated"] is True
    assert duplicate.json()["application"]["id"] == application["id"]

    detail = client.get(f"/applications/{application['id']}", headers=headers).json()
    assert detail["stats"]["scans"] == 0
    assert detail["app_context"] is None

    # سياق التطبيق + إعادة حساب الدرجة
    context = client.put(
        f"/applications/{application['id']}/context",
        headers=headers,
        json={
            "data_sensitivity": "HIGH",
            "industry": "banking",
            "user_base_size": "large",
            "internet_facing": True,
            "business_criticality": "HIGH",
        },
    )
    assert context.status_code == 200
    assert context.json()["context_score"] is not None

    # ── 3) بدء الفحص + polling ──────────────────────────────────────
    started = client.post(
        "/scans/start",
        headers=headers,
        json={"application_id": application["id"], "scan_type": "comprehensive"},
    )
    assert started.status_code == 202, started.text
    scan_id = started.json()["scan_id"]

    final_status = _poll_until_final(client, headers, scan_id)
    assert final_status["status"] in ("success", "partial"), final_status
    assert final_status["progress_percent"] == 100

    scans = client.get("/scans", headers=headers, params={"application_id": application["id"]}).json()
    assert any(row["id"] == scan_id for row in scans)

    # ── 4) الثغرات والتقييمات ───────────────────────────────────────
    vulns = client.get(f"/scans/{scan_id}/vulnerabilities", headers=headers).json()
    assert len(vulns) > 0, "الفحص في Mock Mode يجب أن ينتج ثغرات"
    scored = [v for v in vulns if v.get("assessment")]
    assert scored, "كل ثغرة يجب أن تحمل تقييماً بعد الفحص"

    assessments = client.get(f"/scans/{scan_id}/assessments", headers=headers).json()
    assert len(assessments) >= len(scored)

    top_vuln = max(scored, key=lambda v: v["assessment"].get("final_score") or 0)
    vuln_id = top_vuln["id"]

    full_vuln = client.get(f"/findings/{vuln_id}", headers=headers).json()
    assert full_vuln["assessment"]["final_score"] is not None
    evidence = client.get(f"/findings/{vuln_id}/evidence", headers=headers).json()
    assert len(evidence) > 0
    assert {row["evidence_type"] for row in evidence} <= {"static", "dynamic"}
    assert client.get(f"/findings/{vuln_id}/assessment", headers=headers).status_code == 200

    # ── 5) التصحيح البشري: final_score ثابت، severity يتغير ─────────
    assessment_id = top_vuln["assessment"]["id"]
    before = client.get(f"/assessments/{assessment_id}", headers=headers).json()
    before_score = before["final_score"]
    before_severity = before["severity"]

    corrected_severity = "Critical" if before_severity != "Critical" else "High"
    correction = client.post(
        f"/reviews/{assessment_id}/correct",
        headers=headers,
        json={
            "corrected_severity": corrected_severity,
            "corrected_score": 9.7,
            "reason": "تصحيح E2E: دليل ديناميكي مؤكد يرفع خطورة الثغرة.",
        },
    )
    assert correction.status_code == 200, correction.text

    after = client.get(f"/assessments/{assessment_id}", headers=headers).json()
    assert after["final_score"] == before_score, "final_score لا يُمَس بالتصحيح البشري"
    assert after["severity"] == corrected_severity
    assert after["review_status"] == "approved"
    assert after["corrections"][0]["corrected_score"] == 9.7

    review_stats = client.get("/reviews/stats", headers=headers).json()
    assert review_stats["corrections_total"] >= 1
    assert review_stats["feedback_examples_total"] >= 1

    # ── 6) التقارير ─────────────────────────────────────────────────
    generated = client.post(f"/reports/{scan_id}/generate", headers=headers)
    assert generated.status_code == 200, generated.text
    assert generated.json()["format_count"] == 6

    technical_md = client.get(f"/reports/{scan_id}/download/technical_md", headers=headers)
    assert technical_md.status_code == 200 and len(technical_md.content) > 200

    technical_pdf = client.get(f"/reports/{scan_id}/download/technical_pdf", headers=headers)
    assert technical_pdf.content[:5] == b"%PDF-"

    executive = client.get(f"/reports/{scan_id}/executive", headers=headers).json()
    assert "الملخص التنفيذي" in executive["markdown"]

    # ── 7) لوحة المعلومات ───────────────────────────────────────────
    summary = client.get("/dashboard/summary", headers=headers).json()
    assert summary["total_projects"] >= 1
    assert summary["total_scans"] >= 1
    assert summary["total_vulnerabilities"] >= len(vulns)

    chart = client.get("/dashboard/severity_chart", headers=headers).json()
    assert [bucket["severity"] for bucket in chart] == ["Critical", "High", "Medium", "Low"]

    health = client.get("/health").json()
    assert health["status"] == "ok" and health["database"] == "ok"


def test_cancel_and_delete_rules(client: TestClient, headers: dict[str, str]) -> None:
    """قواعد الإلغاء/الحذف: إلغاء فحص منتهٍ 409، حذف تطبيق له فحوص 409."""
    project = client.post(
        "/projects", headers=headers, json={"name": f"مشروع قواعد {uuid.uuid4().hex[:6]}"}
    ).json()
    filename, content = _fake_apk()
    application = client.post(
        "/applications/upload",
        headers=headers,
        data={"project_id": str(project["id"])},
        files={"file": (filename, content, "application/vnd.android.package-archive")},
    ).json()["application"]

    scan_id = client.post(
        "/scans/start", headers=headers, json={"application_id": application["id"]}
    ).json()["scan_id"]
    _poll_until_final(client, headers, scan_id)

    cancelled = client.delete(f"/scans/{scan_id}", headers=headers)
    assert cancelled.status_code == 409, "لا يُلغى فحص منتهٍ"

    blocked = client.delete(f"/applications/{application['id']}", headers=headers)
    assert blocked.status_code == 409, "لا يُحذف تطبيق له فحوص"

    missing = client.get("/scans/999999/status", headers=headers)
    assert missing.status_code == 404
