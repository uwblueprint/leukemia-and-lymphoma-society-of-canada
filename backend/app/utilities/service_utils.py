from fastapi import Depends
from sqlalchemy.orm import Session
from ..services.implementations.user_service import UserService
from ..services.implementations.auth_service import AuthService
from .db_utils import get_db
import logging

def get_user_service(db: Session = Depends(get_db)):
    return UserService(db)

def get_auth_service(db: Session = Depends(get_db)):
    logger = logging.getLogger(__name__)
    return AuthService(logger=logger, user_service=UserService(db))
