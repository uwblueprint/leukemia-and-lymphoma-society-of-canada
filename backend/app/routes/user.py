from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.schemas.user import UserCreateRequest, UserCreateResponse
from app.services.implementations.user_service import UserService
from app.utilities.db_utils import get_db
from app.utilities.service_utils import get_user_service

router = APIRouter(
    prefix="/users",
    tags=["users"],
)

# TODO:
# send email verification via auth_service
# allow signup methods other than email (like sign up w Google)??


@router.post("/", response_model=UserCreateResponse)
async def create_user(
    user: UserCreateRequest, user_service: UserService = Depends(get_user_service)
):
    try:
        return await user_service.create_user(user)
    except HTTPException as http_ex:
        raise http_ex
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
