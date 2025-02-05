from pydantic import BaseModel, ConfigDict
from .user import UserCreateResponse

class LoginRequest(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    """
    For authentication tokens from Firebase
    Access tokens are short-lived and used to access resources
    Refresh tokens are long-lived and used to obtain new access tokens
    """
    access_token: str
    refresh_token: str
    
    model_config = ConfigDict(from_attributes=True)

class RefreshRequest(BaseModel):
    """Request body for token refresh"""
    refresh_token: str

class AuthResponse(Token):
    """Authentication response containing tokens and user info"""
    user: UserCreateResponse
    
    model_config = ConfigDict(from_attributes=True)