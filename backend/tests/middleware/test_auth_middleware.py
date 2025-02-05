from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.middleware.auth_middleware import require_auth, require_roles, require_user_id
from app.schemas.user import UserRole


def test_require_auth_valid_token(app: FastAPI, access_token: str):
    """Test require_auth middleware with valid token."""

    @app.get("/test-auth")
    @require_auth
    async def test_endpoint():
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        "/test-auth", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "success"}


def test_require_auth_invalid_token(app: FastAPI):
    """Test require_auth middleware with invalid token."""

    @app.get("/test-auth")
    @require_auth
    async def test_endpoint():
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        "/test-auth", headers={"Authorization": "Bearer invalid-token"}
    )
    assert response.status_code == 401


def test_require_auth_missing_token(app: FastAPI):
    """Test require_auth middleware with missing token."""

    @app.get("/test-auth")
    @require_auth
    async def test_endpoint():
        return {"message": "success"}

    client = TestClient(app)
    response = client.get("/test-auth")
    assert response.status_code == 401


def test_require_roles_valid_role(app: FastAPI, access_token: str, test_user: dict):
    """Test require_roles middleware with valid role."""

    @app.get("/test-roles")
    @require_roles({test_user["role"]})
    async def test_endpoint():
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        "/test-roles", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "success"}


def test_require_roles_invalid_role(app: FastAPI, access_token: str):
    """Test require_roles middleware with invalid role."""

    @app.get("/test-roles")
    @require_roles({UserRole.ADMIN})
    async def test_endpoint():
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        "/test-roles", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 403


def test_require_roles_expired_token(app: FastAPI, expired_token: str):
    """Test require_roles middleware with expired token."""

    @app.get("/test-roles")
    @require_roles({UserRole.PARTICIPANT})
    async def test_endpoint():
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        "/test-roles", headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert response.status_code == 401


def test_require_user_id_valid_user(app: FastAPI, access_token: str, test_user: dict):
    """Test require_user_id middleware with valid user."""

    @app.get("/test-user/{user_id}")
    @require_user_id()
    async def test_endpoint(user_id: str):
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        f"/test-user/{test_user['id']}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "success"}


def test_require_user_id_invalid_user(app: FastAPI, access_token: str):
    """Test require_user_id middleware with invalid user."""

    @app.get("/test-user/{user_id}")
    @require_user_id()
    async def test_endpoint(user_id: str):
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        "/test-user/wrong-user-id",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 403


def test_require_user_id_expired_token(app: FastAPI, expired_token: str, test_user: dict):
    """Test require_user_id middleware with expired token."""

    @app.get("/test-user/{user_id}")
    @require_user_id()
    async def test_endpoint(user_id: str):
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        f"/test-user/{test_user['id']}",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401


def test_require_user_id_custom_param(app: FastAPI, access_token: str, test_user: dict):
    """Test require_user_id middleware with custom parameter name."""

    @app.get("/test-user/{custom_id}")
    @require_user_id(user_id_param="custom_id")
    async def test_endpoint(custom_id: str):
        return {"message": "success"}

    client = TestClient(app)
    response = client.get(
        f"/test-user/{test_user['id']}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "success"} 