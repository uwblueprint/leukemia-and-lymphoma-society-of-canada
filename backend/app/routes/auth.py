from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..schemas.auth import AuthResponse, LoginRequest, Token
from ..services.implementations.auth_service import AuthService
from ..services.implementations.user_service import UserService
from ..utilities.db_utils import get_db
from ..utilities.service_utils import get_auth_service
from ..middleware.auth import get_current_user
import logging

router = APIRouter(prefix="/auth", tags=["auth"])

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
        auth_service.revoke_tokens(current_user)
        return {"message": "Successfully logged out"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/refresh", response_model=Token)
async def refresh(
    refresh_token: str,
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        return auth_service.renew_token(refresh_token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

