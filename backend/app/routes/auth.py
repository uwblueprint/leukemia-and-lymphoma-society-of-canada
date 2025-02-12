from fastapi import APIRouter, Depends, HTTPException, Security, Body
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from ..schemas.auth import AuthResponse, LoginRequest, Token, RefreshRequest
from ..services.implementations.auth_service import AuthService
from ..services.implementations.user_service import UserService
from ..utilities.db_utils import get_db
from ..utilities.service_utils import get_auth_service
from ..middleware.auth import get_current_user, require_roles
import logging

from ..schemas.user import UserRole

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()

@router.post("/login", response_model=AuthResponse)
async def login(
    credentials: LoginRequest, 
    auth_service: AuthService = Depends(get_auth_service)
):
    return auth_service.generate_token(credentials.email, credentials.password)


@router.post("/logout")
async def logout(
    current_user = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        auth_service.revoke_tokens(current_user["user"])
        return {"message": "Successfully logged out"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/refresh", response_model=Token)
async def refresh(
    refresh_data: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        return auth_service.renew_token(refresh_data.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@router.get("/verify", response_model=dict)
async def verify_token(
    current_user = Depends(get_current_user)
):
    """Test endpoint to verify a bearer token is valid and return the user info"""
    try:
        return {
            "message": "Token is valid",
            "user": current_user["user"]
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
    