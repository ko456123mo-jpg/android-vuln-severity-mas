"""اختبارات وحدة — CRUD المشاريع عبر API (المرحلة 6)."""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client() -> TestClient:
    """عميل TestClient على قاعدة الاختبار المعزولة."""
    from api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def headers(client: TestClient) -> dict[str, str]:
    """ترويسات admin المزروع."""
    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _project_payload() -> dict[str, str]:
    """حمولة مشروع فريدة لكل اختبار."""
    suffix = uuid.uuid4().hex[:8]
    return {"name": f"مشروع اختبار {suffix}", "description": "وصف اختباري"}


class TestProjectsCrud:
    def test_create_returns_full_record(self, client: TestClient, headers: dict[str, str]) -> None:
        response = client.post("/projects", headers=headers, json=_project_payload())
        body = response.json()
        assert response.status_code == 201
        assert body["id"] > 0
        assert body["status"] == "active"
        assert body["owner_username"] == "admin"
        assert body["stats"] == {"applications": 0, "scans": 0, "vulnerabilities": 0}

    def test_list_and_get_details(self, client: TestClient, headers: dict[str, str]) -> None:
        created = client.post("/projects", headers=headers, json=_project_payload()).json()
        listing = client.get("/projects", headers=headers).json()
        assert any(row["id"] == created["id"] for row in listing)

        detail = client.get(f"/projects/{created['id']}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["name"] == created["name"]

    def test_get_missing_404(self, client: TestClient, headers: dict[str, str]) -> None:
        response = client.get("/projects/999999", headers=headers)
        assert response.status_code == 404
        assert response.json()["error"] == "http_error"

    def test_update_fields(self, client: TestClient, headers: dict[str, str]) -> None:
        created = client.post("/projects", headers=headers, json=_project_payload()).json()
        updated = client.put(
            f"/projects/{created['id']}",
            headers=headers,
            json={"name": "اسم محدَّث", "description": "وصف محدَّث"},
        )
        assert updated.status_code == 200
        assert updated.json()["name"] == "اسم محدَّث"

    def test_update_without_fields_422(self, client: TestClient, headers: dict[str, str]) -> None:
        created = client.post("/projects", headers=headers, json=_project_payload()).json()
        response = client.put(f"/projects/{created['id']}", headers=headers, json={})
        assert response.status_code == 422

    def test_soft_delete_hidden_by_default(self, client: TestClient, headers: dict[str, str]) -> None:
        created = client.post("/projects", headers=headers, json=_project_payload()).json()
        deleted = client.delete(f"/projects/{created['id']}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json()["mode"] == "soft"

        default_list = client.get("/projects", headers=headers).json()
        assert all(row["id"] != created["id"] for row in default_list)

        archived = client.get("/projects", headers=headers, params={"include_archived": True}).json()
        assert any(row["id"] == created["id"] and row["status"] == "archived" for row in archived)

    def test_owner_filter(self, client: TestClient, headers: dict[str, str]) -> None:
        created = client.post("/projects", headers=headers, json=_project_payload()).json()
        mine = client.get("/projects", headers=headers, params={"owner_id": 1}).json()
        assert any(row["id"] == created["id"] for row in mine)
        others = client.get("/projects", headers=headers, params={"owner_id": 424242}).json()
        assert all(row["id"] != created["id"] for row in others)

    def test_unauthenticated_401(self, client: TestClient) -> None:
        assert client.post("/projects", json=_project_payload()).status_code == 401
        assert client.get("/projects").status_code == 401

    def test_validation_error_shape(self, client: TestClient, headers: dict[str, str]) -> None:
        response = client.post("/projects", headers=headers, json={"name": ""})
        body = response.json()
        assert response.status_code == 422
        assert body["error"] == "validation_error"
        assert isinstance(body["detail"], list)
