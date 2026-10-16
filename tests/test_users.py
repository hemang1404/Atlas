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
    assert data["is_active"] is True
    assert data["is_superuser"] is False
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


def test_get_users_list_admin_only(
    client: TestClient,
    superuser_headers: dict[str, str],
    normal_user: tuple,
):
    user, normal_headers = normal_user

    # 1. Unauthenticated request fails with 401
    res_unauth = client.get("/users/")
    assert res_unauth.status_code == 401

    # 2. Regular user fails with 403 Forbidden (RBAC)
    res_forbidden = client.get("/users/", headers=normal_headers)
    assert res_forbidden.status_code == 403
    assert res_forbidden.json()["detail"] == "The user does not have enough privileges"

    # 3. Superuser succeeds with 200 OK
    res_admin = client.get("/users/", headers=superuser_headers)
    assert res_admin.status_code == 200
    users = res_admin.json()
    assert len(users) >= 2
    usernames = [u["username"] for u in users]
    assert "admin_user" in usernames
    assert "regular_user" in usernames


def test_get_user_by_id_ownership_and_admin(
    client: TestClient,
    superuser_headers: dict[str, str],
    normal_user: tuple,
):
    user1, headers1 = normal_user

    # Register user2
    res2 = client.post("/users/", json={
        "name": "User Two", "username": "user2", "email": "u2@example.com", "password": "Password123!"
    })
    user2_id = res2.json()["id"]

    # 1. Normal user accessing their OWN profile succeeds (200)
    res_self = client.get(f"/users/{user1.id}", headers=headers1)
    assert res_self.status_code == 200
    assert res_self.json()["id"] == str(user1.id)

    # 2. Normal user accessing user2's profile FAILS with 403 Forbidden (BOLA/IDOR protection)
    res_other = client.get(f"/users/{user2_id}", headers=headers1)
    assert res_other.status_code == 403
    assert res_other.json()["detail"] == "Not authorized to access this user profile"

    # 3. Superuser accessing user2's profile SUCCEEDS (200)
    res_admin = client.get(f"/users/{user2_id}", headers=superuser_headers)
    assert res_admin.status_code == 200
    assert res_admin.json()["id"] == user2_id


def test_get_user_not_found_as_superuser(
    client: TestClient,
    superuser_headers: dict[str, str],
):
    random_uuid = str(uuid.uuid4())
    response = client.get(f"/users/{random_uuid}", headers=superuser_headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


def test_delete_user_ownership_and_admin(
    client: TestClient,
    superuser_headers: dict[str, str],
    normal_user: tuple,
):
    user1, headers1 = normal_user

    # Register user2
    res2 = client.post("/users/", json={
        "name": "Target User", "username": "target_user", "email": "target@example.com", "password": "Password123!"
    })
    user2_id = res2.json()["id"]

    # 1. Normal user attempting to delete another user FAILS with 403 Forbidden
    res_forbidden = client.delete(f"/users/{user2_id}", headers=headers1)
    assert res_forbidden.status_code == 403
    assert res_forbidden.json()["detail"] == "Not authorized to delete this user"

    # 2. Normal user deleting their OWN account succeeds with 204 No Content
    res_self_delete = client.delete(f"/users/{user1.id}", headers=headers1)
    assert res_self_delete.status_code == 204

    # 3. Superuser deleting user2 succeeds with 204 No Content
    res_admin_delete = client.delete(f"/users/{user2_id}", headers=superuser_headers)
    assert res_admin_delete.status_code == 204

    # Subsequent GET returns 404
    res_check = client.get(f"/users/{user2_id}", headers=superuser_headers)
    assert res_check.status_code == 404


def test_inactive_user_rejected_by_active_dependency(
    client: TestClient,
    db_session,
):
    from core.security import create_access_token, hash_password
    from models.user import User

    inactive_user = User(
        name="Deactivated User",
        username="inactive_user",
        email="inactive@example.com",
        hashed_password=hash_password("Password123!"),
        is_active=False,
        is_superuser=False,
    )
    db_session.add(inactive_user)
    db_session.commit()
    db_session.refresh(inactive_user)

    token = create_access_token(subject=str(inactive_user.id))
    headers = {"Authorization": f"Bearer {token}"}

    # Calling /users/me fails because account is deactivated
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "Inactive user"


def test_update_user_self_success(
    client: TestClient,
    normal_user: tuple,
):
    user, headers = normal_user
    res_patch = client.patch(
        f"/users/{user.id}",
        json={"name": "Brand New Name", "age": 42},
        headers=headers,
    )
    assert res_patch.status_code == 200
    data = res_patch.json()
    assert data["name"] == "Brand New Name"
    assert data["age"] == 42
    assert data["username"] == user.username
    assert data["email"] == user.email


def test_update_user_password_success(
    client: TestClient,
    normal_user: tuple,
):
    user, headers = normal_user
    new_password = "NewlyUpdatedPassword123!"

    # 1. Update password
    res_patch = client.patch(
        f"/users/{user.id}",
        json={"password": new_password},
        headers=headers,
    )
    assert res_patch.status_code == 200

    # 2. Login with new password succeeds
    login_new = client.post(
        "/auth/login",
        data={"username": user.username, "password": new_password},
    )
    assert login_new.status_code == 200

    # 3. Login with old password fails
    login_old = client.post(
        "/auth/login",
        data={"username": user.username, "password": "RegularPassword123!"},
    )
    assert login_old.status_code == 401


def test_update_user_unauthorized_cross_account_fails(
    client: TestClient,
    normal_user: tuple,
):
    user1, headers1 = normal_user

    # Register user2
    res2 = client.post("/users/", json={
        "name": "User Two", "username": "user2_update", "email": "u2_up@example.com", "password": "Password123!"
    })
    user2_id = res2.json()["id"]

    # User 1 attempts to update User 2 -> 403 Forbidden
    response = client.patch(
        f"/users/{user2_id}",
        json={"name": "Hacked Name"},
        headers=headers1,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Not authorized to update this user"


def test_update_user_by_admin_success(
    client: TestClient,
    superuser_headers: dict[str, str],
    normal_user: tuple,
):
    user, _ = normal_user

    # Superuser updates normal user's profile
    res_admin = client.patch(
        f"/users/{user.id}",
        json={"name": "Admin Adjusted Name"},
        headers=superuser_headers,
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["name"] == "Admin Adjusted Name"


def test_update_user_non_admin_cannot_elevate_privileges(
    client: TestClient,
    normal_user: tuple,
):
    user, headers = normal_user

    # Regular user attempts to elevate self to superuser
    response = client.patch(
        f"/users/{user.id}",
        json={"is_superuser": True},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Cannot modify administrative privileges"


def test_update_user_admin_can_toggle_is_active(
    client: TestClient,
    superuser_headers: dict[str, str],
    normal_user: tuple,
):
    user, user_headers = normal_user

    # Superuser suspends user
    res_deactivate = client.patch(
        f"/users/{user.id}",
        json={"is_active": False},
        headers=superuser_headers,
    )
    assert res_deactivate.status_code == 200
    assert res_deactivate.json()["is_active"] is False

    # Suspended user now blocked from calling /users/me
    res_blocked = client.get("/users/me", headers=user_headers)
    assert res_blocked.status_code == 400
    assert res_blocked.json()["detail"] == "Inactive user"


def test_update_user_duplicate_username_fails(
    client: TestClient,
    normal_user: tuple,
):
    user1, headers1 = normal_user

    # Register user2 with username 'existing_user'
    client.post("/users/", json={
        "name": "Existing", "username": "existing_user", "email": "existing@example.com", "password": "Password123!"
    })

    # User 1 tries to change their username to 'existing_user'
    res_conflict = client.patch(
        f"/users/{user1.id}",
        json={"username": "existing_user"},
        headers=headers1,
    )
    assert res_conflict.status_code == 409
    assert "already exists" in res_conflict.json()["detail"]



