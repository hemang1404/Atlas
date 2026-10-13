from datetime import timedelta
import pytest
from httpx import Client

from core.security import create_access_token


@pytest.fixture
def test_user_payload():
    return {
        "name": "Auth Tester",
        "username": "authtester",
        "email": "auth@example.com",
        "password": "supersecretpassword123",
        "age": 28,
    }


@pytest.fixture
def registered_user(client: Client, test_user_payload: dict):
    response = client.post("/users/", json=test_user_payload)
    assert response.status_code == 201
    return response.json()


def test_login_success_with_username(client: Client, registered_user: dict, test_user_payload: dict):
    response = client.post(
        "/auth/login",
        data={
            "username": test_user_payload["username"],
            "password": test_user_payload["password"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 20


def test_login_success_with_email(client: Client, registered_user: dict, test_user_payload: dict):
    response = client.post(
        "/auth/login",
        data={
            "username": test_user_payload["email"],
            "password": test_user_payload["password"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_incorrect_password(client: Client, registered_user: dict, test_user_payload: dict):
    response = client.post(
        "/auth/login",
        data={
            "username": test_user_payload["username"],
            "password": "wrongpassword999",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"
    assert "Bearer" in response.headers.get("www-authenticate", "")


def test_login_nonexistent_user(client: Client):
    response = client.post(
        "/auth/login",
        data={
            "username": "ghost_user",
            "password": "anypassword",
        },
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_get_current_user_me_success(client: Client, registered_user: dict, test_user_payload: dict):
    # Log in to get token
    login_res = client.post(
        "/auth/login",
        data={
            "username": test_user_payload["username"],
            "password": test_user_payload["password"],
        },
    )
    token = login_res.json()["access_token"]

    # Access protected /users/me endpoint
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["id"] == registered_user["id"]
    assert user_data["username"] == registered_user["username"]
    assert user_data["email"] == registered_user["email"]
    assert "password" not in user_data
    assert "hashed_password" not in user_data


def test_get_current_user_me_missing_token(client: Client):
    response = client.get("/users/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_get_current_user_me_invalid_token(client: Client):
    response = client.get(
        "/users/me",
        headers={"Authorization": "Bearer malformed.token.signature"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_get_current_user_me_expired_token(client: Client, registered_user: dict):
    expired_token = create_access_token(
        subject=registered_user["id"],
        expires_delta=timedelta(minutes=-10),
    )
    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
