from fastapi import APIRouter, Depends, Request
from ..middleware.auth_middleware import require_auth, require_roles, require_user_id, get_token_from_header
from ..middleware.firebase_auth_middleware import require_roles as firebase_require_roles
from ..schemas.user import UserRole

router = APIRouter(prefix="/test", tags=["test"])

# # Basic auth test - any valid token
# @router.get("/auth")
# @require_auth
# async def test_auth():
#     """Test endpoint requiring just authentication"""
#     return {"message": "You are authenticated!"}

# Basic Firebase middleware test
@router.get("/auth-middleware")
async def test_firebase_middleware(request: Request):
    """Test endpoint to verify Firebase middleware is working"""
    return {
        "message": "Firebase auth successful",
        "user_id": request.state.user_id,
        "claims": request.state.user_claims
    }

# Test user context middleware
@router.get("/context")
async def test_context(request: Request):
    """Test endpoint to verify user context middleware"""
    try:
        return {
            "request_id": request.state.request_id,
            "timestamp": request.state.request_timestamp,
        }
    except Exception as e:
        return {
            "error": str(e)
        }
