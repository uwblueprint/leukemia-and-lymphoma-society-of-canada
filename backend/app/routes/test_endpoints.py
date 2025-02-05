from fastapi import APIRouter, Depends
from ..middleware.auth_middleware import require_auth, require_roles, require_user_id
from ..schemas.user import UserRole

router = APIRouter(prefix="/test", tags=["test"])

# # Basic auth test - any valid token
# @router.get("/auth")
# @require_auth
# async def test_auth():
#     """Test endpoint requiring just authentication"""
#     return {"message": "You are authenticated!"}

# Role-based tests
@router.get("/admin-only")
@require_roles({UserRole.ADMIN})
async def test_admin_only():
    """Test endpoint requiring admin role"""
    return {"message": "You are an admin!"}

@router.get("/volunteer-or-admin")
@require_roles({UserRole.VOLUNTEER, UserRole.ADMIN})
async def test_volunteer_or_admin():
    """Test endpoint requiring volunteer or admin role"""
    return {"message": "You are a volunteer or admin!"}

@router.get("/participant-only")
@require_roles({UserRole.PARTICIPANT})
async def test_participant_only():
    """Test endpoint requiring participant role"""
    return {"message": "You are a participant!"}

# User-specific tests
@router.get("/users/{user_id}/profile")
@require_user_id()
async def test_user_specific(user_id: str):
    """Test endpoint requiring specific user access"""
    return {"message": f"You can access user {user_id}'s profile!"}

# Combined tests
@router.get("/users/{user_id}/admin-action")
@require_roles({UserRole.ADMIN})
@require_user_id()
async def test_admin_user_specific(user_id: str):
    """Test endpoint requiring both admin role and specific user access"""
    return {"message": f"You are an admin accessing user {user_id}'s data!"} 