import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.schemas.user import SignUpMethod, UserCreateRequest, UserRole
from app.services.implementations.auth_service import AuthService


@pytest.mark.asyncio
async def test_register_user_success(auth_service: AuthService):
    """Test successful user registration."""
    user_data = UserCreateRequest(
        email="new@example.com",
        password="NewPass123!",
        first_name="New",
        last_name="User",
        role=UserRole.PARTICIPANT,
        signup_method=SignUpMethod.PASSWORD,
    )

    result = await auth_service.register_user(user_data)
    assert result.email == user_data.email
    assert result.first_name == user_data.first_name
    assert result.last_name == user_data.last_name
    assert result.role_id == UserRole.to_role_id(user_data.role)


@pytest.mark.asyncio
async def test_register_user_duplicate_email(auth_service: AuthService, test_user: dict):
    """Test registration with duplicate email."""
    user_data = UserCreateRequest(
        email=test_user["email"],
        password="NewPass123!",
        first_name="New",
        last_name="User",
        role=UserRole.PARTICIPANT,
        signup_method=SignUpMethod.PASSWORD,
    )

    with pytest.raises(HTTPException) as exc_info:
        await auth_service.register_user(user_data)
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_generate_token_success(auth_service: AuthService, test_user: dict):
    """Test successful token generation."""
    result = await auth_service.generate_token(test_user["email"], "TestPass123!")
    assert result.user_id == test_user["id"]
    assert result.auth_id == test_user["auth_id"]
    assert result.access_token
    assert result.refresh_token


@pytest.mark.asyncio
async def test_generate_token_invalid_credentials(auth_service: AuthService):
    """Test token generation with invalid credentials."""
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.generate_token("wrong@example.com", "WrongPass123!")
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_renew_token_success(auth_service: AuthService, refresh_token: str):
    """Test successful token renewal."""
    result = await auth_service.renew_token(refresh_token)
    assert result.access_token
    assert result.refresh_token


@pytest.mark.asyncio
async def test_renew_token_expired(auth_service: AuthService, expired_token: str):
    """Test token renewal with expired token."""
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.renew_token(expired_token)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_revoke_tokens_success(auth_service: AuthService, test_user: dict):
    """Test successful token revocation."""
    await auth_service.revoke_tokens(test_user["id"])
    # No exception means success


@pytest.mark.asyncio
async def test_revoke_tokens_invalid_user(auth_service: AuthService):
    """Test token revocation for invalid user."""
    with pytest.raises(HTTPException) as exc_info:
        await auth_service.revoke_tokens("invalid-user-id")
    assert exc_info.value.status_code == 500


def test_is_authorized_by_role_success(
    auth_service: AuthService, access_token: str, test_user: dict
):
    """Test successful role authorization."""
    assert auth_service.is_authorized_by_role(
        access_token, {test_user["role"].value}
    )


def test_is_authorized_by_role_wrong_role(
    auth_service: AuthService, access_token: str
):
    """Test role authorization with wrong role."""
    assert not auth_service.is_authorized_by_role(
        access_token, {UserRole.ADMIN.value}
    )


def test_is_authorized_by_role_expired_token(
    auth_service: AuthService, expired_token: str
):
    """Test role authorization with expired token."""
    assert not auth_service.is_authorized_by_role(
        expired_token, {UserRole.PARTICIPANT.value}
    )


def test_is_authorized_by_user_id_success(
    auth_service: AuthService, access_token: str, test_user: dict
):
    """Test successful user ID authorization."""
    assert auth_service.is_authorized_by_user_id(access_token, test_user["id"])


def test_is_authorized_by_user_id_wrong_user(
    auth_service: AuthService, access_token: str
):
    """Test user ID authorization with wrong user."""
    assert not auth_service.is_authorized_by_user_id(
        access_token, "wrong-user-id"
    )


def test_is_authorized_by_user_id_expired_token(
    auth_service: AuthService, expired_token: str, test_user: dict
):
    """Test user ID authorization with expired token."""
    assert not auth_service.is_authorized_by_user_id(
        expired_token, test_user["id"]
    )


def test_is_authorized_by_email_success(
    auth_service: AuthService, access_token: str, test_user: dict
):
    """Test successful email authorization."""
    assert auth_service.is_authorized_by_email(access_token, test_user["email"])


def test_is_authorized_by_email_wrong_email(
    auth_service: AuthService, access_token: str
):
    """Test email authorization with wrong email."""
    assert not auth_service.is_authorized_by_email(
        access_token, "wrong@example.com"
    )


def test_is_authorized_by_email_expired_token(
    auth_service: AuthService, expired_token: str, test_user: dict
):
    """Test email authorization with expired token."""
    assert not auth_service.is_authorized_by_email(
        expired_token, test_user["email"]
    ) 