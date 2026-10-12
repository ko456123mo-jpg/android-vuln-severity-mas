"""اختبارات وحدة — مصادقة API الكاملة (JWT) — المرحلة 6.

تغطي: تجزئة كلمات المرور، إنشاء/تحقق التوكن (توقيع/انتهاء/sub)، /auth/login،
/auth/me، /auth/register (admin فقط)، ورفض الوصول غير المُصرَّح.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from api import auth as auth_module


@pytest.fixture()
def client() -> TestClient:
    """عميل TestClient على قاعدة الاختبار المعزولة (conftest)."""
    from api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def admin_headers(client: TestClient) -> dict[str, str]:
    """ترويسات admin المزروع."""
    response = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _unique(prefix: str) -> str:
    """اسم فريد لكل تشغيل (قاعدة الاختبار تُبذر مرة واحدة للجلسة)."""
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------
# كلمات المرور
# ---------------------------------------------------------------------
class TestPasswordHashing:
    def test_round_trip(self) -> None:
        digest = auth_module.hash_password("StrongPass123")
        assert digest != "StrongPass123"
        assert auth_module.verify_password("StrongPass123", digest) is True

    def test_wrong_password_rejected(self) -> None:
        digest = auth_module.hash_password("StrongPass123")
        assert auth_module.verify_password("WrongPass123", digest) is False

    def test_garbage_hash_returns_false(self) -> None:
        assert auth_module.verify_password("anything", "not-a-bcrypt-hash") is False


# ---------------------------------------------------------------------
# التوكن
# ---------------------------------------------------------------------
class TestToken:
    def test_round_trip(self) -> None:
        token = auth_module.create_access_token(
            {"sub": "42", "username": "tester", "role": "reviewer"}
        )
        payload = auth_module.verify_token(token)
        assert payload["sub"] == "42"
        assert payload["username"] == "tester"
        assert payload["role"] == "reviewer"
        assert "exp" in payload

    def test_tampered_token_rejected(self) -> None:
        token = auth_module.create_access_token({"sub": "1", "username": "admin"})
        with pytest.raises(ValueError):
            auth_module.verify_token(token[:-3] + "abc")

    def test_expired_token_rejected(self) -> None:
        token = auth_module.create_access_token(
            {"sub": "1", "username": "admin"}, expires_delta=timedelta(minutes=-5)
        )
        with pytest.raises(ValueError):
            auth_module.verify_token(token)

    def test_missing_sub_rejected(self) -> None:
        token = auth_module.create_access_token({"username": "ghost"})
        with pytest.raises(ValueError):
            auth_module.verify_token(token)


# ---------------------------------------------------------------------
# /auth/login
# ---------------------------------------------------------------------
class TestLogin:
    def test_success_returns_token_and_user(self, client: TestClient) -> None:
        response = client.post(
            "/auth/login", json={"username": "admin", "password": "admin123"}
        )
        body = response.json()
        assert response.status_code == 200
        assert body["token_type"] == "bearer"
        assert body["user"]["username"] == "admin"
        assert body["user"]["role"] == "admin"
        assert "password" not in body["user"]

    def test_wrong_password_401(self, client: TestClient) -> None:
        response = client.post(
            "/auth/login", json={"username": "admin", "password": "wrongpass123"}
        )
        assert response.status_code == 401

    def test_unknown_user_401(self, client: TestClient) -> None:
        response = client.post(
            "/auth/login", json={"username": "nobody_here", "password": "whatever123"}
        )
        assert response.status_code == 401

    def test_short_password_422_shape(self, client: TestClient) -> None:
        response = client.post("/auth/login", json={"username": "admin", "password": "short"})
        body = response.json()
        assert response.status_code == 422
        assert body["error"] == "validation_error"
        assert body["detail"]


# ---------------------------------------------------------------------
# /auth/me + رفض غير المُصرَّح
# ---------------------------------------------------------------------
class TestMe:
    def test_me_ok(self, client: TestClient, admin_headers: dict[str, str]) -> None:
        response = client.get("/auth/me", headers=admin_headers)
        assert response.status_code == 200
        assert response.json()["username"] == "admin"

    def test_missing_header_401(self, client: TestClient) -> None:
        assert client.get("/auth/me").status_code == 401

    def test_malformed_token_401(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer not.a.jwt"}
        assert client.get("/auth/me", headers=headers).status_code == 401

    def test_token_of_unknown_user_401(self, client: TestClient) -> None:
        token = auth_module.create_access_token({"sub": "999999", "username": "ghost"})
        response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_protected_routes_require_auth(self, client: TestClient) -> None:
        for path in ("/projects", "/applications", "/scans", "/dashboard/summary", "/reviews/pending"):
            assert client.get(path).status_code == 401, path


# ---------------------------------------------------------------------
# /auth/register (admin فقط)
# ---------------------------------------------------------------------
class TestRegister:
    def test_admin_creates_user_and_user_can_login(
        self, client: TestClient, admin_headers: dict[str, str]
    ) -> None:
        username = _unique("analyst")
        response = client.post(
            "/auth/register",
            headers=admin_headers,
            json={"username": username, "password": "AnalystPass1", "role": "analyst"},
        )
        assert response.status_code == 201
        assert response.json()["role"] == "analyst"

        login = client.post(
            "/auth/login", json={"username": username, "password": "AnalystPass1"}
        )
        assert login.status_code == 200

    def test_duplicate_username_409(
        self, client: TestClient, admin_headers: dict[str, str]
    ) -> None:
        username = _unique("dup")
        payload = {"username": username, "password": "DuplicatePass1", "role": "analyst"}
        assert client.post("/auth/register", headers=admin_headers, json=payload).status_code == 201
        assert client.post("/auth/register", headers=admin_headers, json=payload).status_code == 409

    def test_non_admin_forbidden_403(self, client: TestClient, admin_headers: dict[str, str]) -> None:
        username = _unique("reviewer")
        client.post(
            "/auth/register",
            headers=admin_headers,
            json={"username": username, "password": "ReviewerPass1", "role": "reviewer"},
        )
        token = client.post(
            "/auth/login", json={"username": username, "password": "ReviewerPass1"}
        ).json()["access_token"]
        response = client.post(
            "/auth/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": _unique("nope"), "password": "NoPass12345", "role": "analyst"},
        )
        assert response.status_code == 403

    def test_invalid_role_422(self, client: TestClient, admin_headers: dict[str, str]) -> None:
        response = client.post(
            "/auth/register",
            headers=admin_headers,
            json={"username": _unique("bad"), "password": "BadRolePass1", "role": "superuser"},
        )
        assert response.status_code == 422
