import uuid
from fastapi.testclient import TestClient


def test_create_user_success(client: TestClient):
    payload = {
        "name": "Alice Smith",
        "username": "alice_smith",
        "email": "alice@example.com",
        "password": "SecurePassword987!",
        "age": 28,
    }
    response = client.post("/users/", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["name"] == "Alice Smith"
    assert data["username"] == "alice_smith"
    assert data["email"] == "alice@example.com"
    assert data["age"] == 28
    assert "id" in data
    assert "created_at" in data

    # Crucial security invariants: passwords must NEVER leak in API responses
    assert "password" not in data
    assert "hashed_password" not in data


def test_create_user_duplicate_username_fails(client: TestClient):
    payload = {
        "name": "Bob Jones",
        "username": "bobjones",
        "email": "bob1@example.com",
        "password": "SecurePassword123!",
    }
    # First registration succeeds
    res1 = client.post("/users/", json=payload)
    assert res1.status_code == 201

    # Second registration with same username fails
    payload_dup = {
        "name": "Bob Other",
        "username": "bobjones",
        "email": "bob2@example.com",
        "password": "AnotherPassword456!",
    }
    res2 = client.post("/users/", json=payload_dup)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


def test_create_user_duplicate_email_fails(client: TestClient):
    payload1 = {
        "name": "Charlie One",
        "username": "charlie1",
        "email": "charlie@example.com",
        "password": "SecurePassword123!",
    }
    res1 = client.post("/users/", json=payload1)
    assert res1.status_code == 201

    payload2 = {
        "name": "Charlie Two",
        "username": "charlie2",
        "email": "charlie@example.com",
        "password": "SecurePassword456!",
    }
    res2 = client.post("/users/", json=payload2)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"]


def test_password_contains_username_fails_validation(client: TestClient):
    payload = {
        "name": "Dave Wilson",
        "username": "dave123",
        "email": "dave@example.com",
        "password": "password_dave123_secure",  # Contains username
    }
    response = client.post("/users/", json=payload)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any("Password cannot contain your username" in str(err) for err in errors)


def test_password_contains_email_prefix_fails_validation(client: TestClient):
    payload = {
        "name": "Eve Davis",
        "username": "evedavis",
        "email": "eve_super@example.com",
        "password": "mypass_eve_super_123",  # Contains email prefix
    }
    response = client.post("/users/", json=payload)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any("Password cannot contain your email prefix" in str(err) for err in errors)


def test_password_too_short_fails(client: TestClient):
    payload = {
        "name": "Frank White",
        "username": "frankwhite",
        "email": "frank@example.com",
        "password": "short",  # Less than 8 chars
    }
    response = client.post("/users/", json=payload)
    assert response.status_code == 422


def test_password_too_long_fails_dos_protection(client: TestClient):
    payload = {
        "name": "Grace Hopper",
        "username": "gracehopper",
        "email": "grace@example.com",
        "password": "A" * 129,  # Greater than 128 chars (DoS protection)
    }
    response = client.post("/users/", json=payload)
    assert response.status_code == 422


def test_username_invalid_chars_fails_regex(client: TestClient):
    # Slashes, spaces, or path traversal sequences must be rejected
    invalid_usernames = ["user/admin", "../../admin", "alice smith", "user@handle"]
    for bad_username in invalid_usernames:
        payload = {
            "name": "Test User",
            "username": bad_username,
            "email": f"{abs(hash(bad_username))}@example.com",
            "password": "ValidPassword999!",
        }
        response = client.post("/users/", json=payload)
        assert response.status_code == 422, f"Expected 422 for username '{bad_username}'"


def test_get_users_list(client: TestClient):
    # Register two users
    client.post("/users/", json={
        "name": "User One", "username": "user1", "email": "u1@example.com", "password": "Password123!"
    })
    client.post("/users/", json={
        "name": "User Two", "username": "user2", "email": "u2@example.com", "password": "Password123!"
    })

    response = client.get("/users/")
    assert response.status_code == 200
    users = response.json()
    assert len(users) == 2
    usernames = [u["username"] for u in users]
    assert "user1" in usernames
    assert "user2" in usernames


def test_get_user_by_id(client: TestClient):
    res_create = client.post("/users/", json={
        "name": "Target User", "username": "target_user", "email": "target@example.com", "password": "Password123!"
    })
    user_id = res_create.json()["id"]

    res_get = client.get(f"/users/{user_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == user_id
    assert res_get.json()["username"] == "target_user"


def test_get_user_not_found(client: TestClient):
    random_uuid = str(uuid.uuid4())
    response = client.get(f"/users/{random_uuid}")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_delete_user(client: TestClient):
    res_create = client.post("/users/", json={
        "name": "Delete Me", "username": "delete_me", "email": "delete@example.com", "password": "Password123!"
    })
    user_id = res_create.json()["id"]

    # Delete returns 204 No Content
    res_del = client.delete(f"/users/{user_id}")
    assert res_del.status_code == 204

    # Subsequent GET returns 404
    res_get = client.get(f"/users/{user_id}")
    assert res_get.status_code == 404
