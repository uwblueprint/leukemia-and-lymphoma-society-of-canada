import pytest
from fastapi.testclient import TestClient

from app.schemas.user import SignUpMethod, UserRole


def test_register_success(client: TestClient):
    """Test successful user registration."""
    response = client.post(
        "/auth/register",
        json={
            "email": "new@example.com",
            "password": "NewPass123!",
            "first_name": "New",
            "last_name": "User",
            "role": UserRole.PARTICIPANT.value,
            "signup_method": SignUpMethod.PASSWORD.value,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "new@example.com"
    assert data["first_name"] == "New"
    assert data["last_name"] == "User"
    assert data["role_id"] == UserRole.to_role_id(UserRole.PARTICIPANT)


def test_register_duplicate_email(client: TestClient, test_user: dict):
    """Test registration with duplicate email."""
    response = client.post(
        "/auth/register",
        json={
            "email": test_user["email"],
            "password": "NewPass123!",
            "first_name": "New",
            "last_name": "User",
            "role": UserRole.PARTICIPANT.value,
            "signup_method": SignUpMethod.PASSWORD.value,
        },
    )
    assert response.status_code == 409


def test_login_success(client: TestClient, test_user: dict):
    """Test successful login."""
    response = client.post(
        "/auth/login",
        params={
            "email": test_user["email"],
            "password": "TestPass123!",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == test_user["id"]
    assert data["auth_id"] == test_user["auth_id"]
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_invalid_credentials(client: TestClient):
    """Test login with invalid credentials."""
    response = client.post(
        "/auth/login",
        params={
            "email": "wrong@example.com",
            "password": "WrongPass123!",
        },
    )
    assert response.status_code == 401


def test_refresh_token_success(client: TestClient, refresh_token: str):
    """Test successful token refresh."""
    response = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_refresh_token_expired(client: TestClient, expired_token: str):
    """Test token refresh with expired token."""
    response = client.post(
        "/auth/refresh",
        json={"refresh_token": expired_token}
    )
    assert response.status_code == 401


def test_logout_success(client: TestClient, test_user: dict, access_token: str):
    """Test successful logout."""
    response = client.post(
        f"/auth/logout/{test_user['id']}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Successfully logged out"}


def test_logout_wrong_user(client: TestClient, access_token: str):
    """Test logout with wrong user."""
    response = client.post(
        "/auth/logout/wrong-user-id",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 403


def test_reset_password_success(client: TestClient, test_user: dict, access_token: str):
    """Test successful password reset request."""
    response = client.post(
        "/auth/reset-password",
        params={"email": test_user["email"]},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Password reset email sent"}


def test_reset_password_invalid_email(client: TestClient, access_token: str):
    """Test password reset request with invalid email."""
    response = client.post(
        "/auth/reset-password",
        params={"email": "wrong@example.com"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 400


def test_verify_email_success(client: TestClient, test_user: dict, access_token: str):
    """Test successful email verification request."""
    response = client.post(
        "/auth/verify-email",
        params={"email": test_user["email"]},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Email verification link sent"}


def test_verify_email_invalid_email(client: TestClient, access_token: str):
    """Test email verification request with invalid email."""
    response = client.post(
        "/auth/verify-email",
        params={"email": "wrong@example.com"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 400 