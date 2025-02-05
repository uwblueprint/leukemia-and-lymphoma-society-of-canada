from functools import wraps
from typing import Callable, List, Optional, Set
import logging

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.schemas.user import UserRole
from app.services.implementations.auth_service import AuthService
from app.services.implementations.user_service import UserService
from app.utilities.service_utils import get_auth_service, get_db

security = HTTPBearer()


def get_token_from_header(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """Extract token from Authorization header."""
    print("\n=== Token Extraction ===")
    print(f"Raw credentials type: {type(credentials)}")
    print(f"Raw credentials: {credentials}")
    print(f"Token from header: {credentials.credentials[:50]}...")  # Print first 50 chars
    print("=== End Token Extraction ===\n")
    return credentials.credentials


def require_auth(
    auth_service: AuthService = Depends(get_auth_service),
    token: str = Depends(get_token_from_header),
) -> None:
    """Verify that the request has a valid access token."""
    try:
        # The token validation is done in the role check, so we just need to check
        # if the token is valid for any role
        if not auth_service.is_authorized_by_role(token, {role.value for role in UserRole}):
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token",
            )
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        )


def require_roles(roles: Set[UserRole]):
    """Require specific roles to access the endpoint."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(
            *args,
            db: Session = Depends(get_db),
            token: str = Depends(get_token_from_header),
            **kwargs,
        ):
            try:
                print("\n=== Role Check ===")
                print(f"Checking roles: {roles}")
                role_values = {role.value for role in roles}
                print(f"Role values to check: {role_values}")
                
                # Create auth service directly
                logger = logging.getLogger(__name__)
                auth_service = AuthService(logger=logger, user_service=UserService(db))
                
                is_authorized = auth_service.is_authorized_by_role(token, role_values)
                print(f"Authorization result: {is_authorized}")
                
                if not is_authorized:
                    raise HTTPException(
                        status_code=403,
                        detail="Insufficient permissions",
                    )
                return await func(*args, **kwargs)
            except HTTPException as e:
                print(f"HTTP Exception: {str(e)}")
                raise e
            except Exception as e:
                print(f"Unexpected error: {str(e)}")
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired token",
                )

        return wrapper

    return decorator


def require_user_id(user_id_param: str = "user_id"):
    """Require that the token belongs to the requested user."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(
            *args,
            auth_service: AuthService = Depends(get_auth_service),
            token: str = Depends(get_token_from_header),
            **kwargs,
        ):
            try:
                user_id = kwargs.get(user_id_param)
                if not user_id:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Missing {user_id_param} parameter",
                    )

                if not auth_service.is_authorized_by_user_id(token, user_id):
                    raise HTTPException(
                        status_code=403,
                        detail="Not authorized to access this resource",
                    )
                return await func(*args, **kwargs)
            except HTTPException as e:
                raise e
            except Exception as e:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired token",
                )

        return wrapper

    return decorator 