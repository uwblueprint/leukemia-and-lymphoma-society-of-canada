from functools import wraps
from typing import Set
from fastapi import Depends, HTTPException
from ..schemas.user import UserRole
from ..services.implementations.auth_service import AuthService
from ..utilities.db_utils import get_db
from .auth import get_current_user

def get_auth_service(db = Depends(get_db)):
    return AuthService(logger=logging.getLogger(__name__), user_service=UserService(db))

def require_role_authorization(roles: Set[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(
            *args,
            current_user_data = Depends(get_current_user),
            auth_service: AuthService = Depends(get_auth_service),
            **kwargs
        ):
            if not auth_service.is_authorized_by_role(current_user_data["token"], roles):
                raise HTTPException(
                    status_code=403,
                    detail=f"User does not have required role(s): {', '.join(roles)}"
                )
            kwargs["current_user"] = current_user_data["user"]
            return await func(*args, **kwargs)
        return wrapper
    return decorator