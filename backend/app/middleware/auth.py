import logging
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import firebase_admin.auth
from ..services.implementations.user_service import UserService
from ..utilities.db_utils import get_db

security = HTTPBearer()
logger = logging.getLogger(__name__)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db = Depends(get_db)
):
    """
    Validates the authorization token and returns the current user
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
            
        return user
        
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