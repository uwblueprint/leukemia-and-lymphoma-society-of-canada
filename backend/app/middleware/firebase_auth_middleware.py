from fastapi import Request, HTTPException
from firebase_admin import auth
from typing import Optional, List
from functools import wraps

class FirebaseAuthMiddleware:
    def __init__(self, app, exclude_paths: List[str] = None):
        self.app = app
        self.exclude_paths = exclude_paths or []

    async def __call__(self, request: Request, call_next):
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Get the Authorization header
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid authorization header"
            )

        try:
            # Verify Firebase token
            token = authorization.split("Bearer ")[1]
            decoded_token = auth.verify_id_token(token)
            
            # Add user info to request state
            request.state.user_id = decoded_token.get("uid")
            request.state.user_claims = decoded_token.get("claims", {})
            
            response = await call_next(request)
            return response

        except Exception as e:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid authentication credentials: {str(e)}"
            )

def require_roles(roles: List[str]):
    """Dependency for role-based access control"""
    async def role_checker(request: Request):
        user_roles = request.state.user_claims.get("roles", [])
        if not any(role in user_roles for role in roles):
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions"
            )
        return True
    return role_checker