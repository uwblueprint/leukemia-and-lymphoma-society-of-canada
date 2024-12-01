import logging
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import firebase_admin.auth
from ..services.implementations.user_service import UserService
from ..utilities.db_utils import get_db
from ..schemas.user import UserRole
from functools import wraps
from typing import Set

security = HTTPBearer()
logger = logging.getLogger(__name__)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db = Depends(get_db)
):
    """
    Validates the authorization token and returns the current user and token
    """
    try:
        # Remove 'Bearer ' prefix
        token = credentials.credentials
        logger.info(f"Attempting to verify token: {token[:20]}...")
        
        # Verify the token with Firebase
        decoded_token = firebase_admin.auth.verify_id_token(token)
        logger.info(f"Decoded token UID: {decoded_token.get('uid')}")
        
        # Get user from database using Firebase UID
        user_service = UserService(db)
        user = user_service.get_user_id_by_auth_id(decoded_token['uid'])
        
        if not user:
            logger.error(f"No user found for auth_id: {decoded_token['uid']}")
            raise HTTPException(
                status_code=401,
                detail="User not found in database"
            )

        return {"user": user, "token": token}
        
    except firebase_admin.auth.InvalidIdTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=401, 
            detail=f"Invalid token: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail=str(e)
        )

def require_roles(allowed_roles: Set[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user=Depends(get_current_user), **kwargs):
            try:
                # Get user role using the token from current_user
                user_service = UserService(kwargs.get('db'))
                user_role = user_service.get_user_role_by_auth_id(
                    firebase_admin.auth.verify_id_token(current_user["token"])["uid"]
                )
                
                # Check if user's role is allowed
                if user_role not in allowed_roles:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access denied: role '{user_role}' not authorized"
                    )
                
                return await func(*args, current_user=current_user, **kwargs)
                
            except Exception as e:
                raise HTTPException(
                    status_code=403,
                    detail=str(e)
                )
        return wrapper
    return decorator
