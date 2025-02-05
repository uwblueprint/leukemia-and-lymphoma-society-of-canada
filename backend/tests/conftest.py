import os
from datetime import datetime, timedelta
from typing import Dict, Generator
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models import Base, Role
from app.schemas.user import UserRole
from app.services.email.email_service import EmailService
from app.services.implementations.auth_service import AuthService
from app.services.implementations.user_service import UserService

# Test database URL - using in-memory SQLite for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

# Create test database engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def mock_firebase():
    """Mock Firebase authentication."""
    with pytest.MonkeyPatch.context() as mp:
        mock_auth = MagicMock()
        mock_auth.create_user.return_value = MagicMock(uid="test-firebase-uid")
        mock_auth.get_user_by_email.return_value = MagicMock(uid="test-firebase-uid")
        mock_auth.verify_id_token.return_value = {"uid": "test-firebase-uid"}
        mock_auth.revoke_refresh_tokens.return_value = None
        mock_auth.generate_password_reset_link.return_value = "https://reset-password"
        mock_auth.generate_email_verification_link.return_value = "https://verify-email"
        
        mp.setattr("firebase_admin.auth", mock_auth)
        yield mock_auth


@pytest.fixture(scope="session")
def jwt_secret() -> str:
    """Get JWT secret key for testing."""
    return "test-secret-key"


@pytest.fixture(scope="session")
def jwt_algorithm() -> str:
    """Get JWT algorithm for testing."""
    return "HS256"


@pytest.fixture
def db() -> Generator:
    """Create a fresh database for each test."""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create a new session
    session = TestingSessionLocal()
    
    # Create roles
    for role in UserRole:
        db_role = Role(id=UserRole.to_role_id(role), name=role.value)
        session.add(db_role)
    session.commit()
    
    try:
        yield session
    finally:
        session.close()
        # Drop all tables after test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def mock_email_service() -> EmailService:
    """Create a mock email service."""
    class MockEmailService:
        async def send_password_reset_email(self, email: str, reset_link: str) -> None:
            pass

        async def send_notification_email(self, email: str, message: str) -> None:
            pass

    return MockEmailService()


@pytest.fixture
def auth_service(db: Session, mock_email_service: EmailService, jwt_secret: str, jwt_algorithm: str) -> AuthService:
    """Create an auth service instance for testing."""
    return AuthService(
        db=db,
        email_service=mock_email_service,
        jwt_secret=jwt_secret,
        jwt_algorithm=jwt_algorithm,
    )


@pytest.fixture
def user_service(db: Session) -> UserService:
    """Create a user service instance for testing."""
    return UserService(db)


@pytest.fixture
def test_user(user_service: UserService) -> Dict:
    """Create a test user and return their details."""
    from app.schemas.user import UserCreateRequest, SignUpMethod

    user_data = UserCreateRequest(
        email="test@example.com",
        password="TestPass123!",
        first_name="Test",
        last_name="User",
        role=UserRole.PARTICIPANT,
        signup_method=SignUpMethod.PASSWORD,
    )
    user = user_service.create_user(user_data)
    return {
        "id": str(user.id),
        "email": user.email,
        "auth_id": user.auth_id,
        "role": UserRole.PARTICIPANT,
    }


@pytest.fixture
def access_token(test_user: Dict, jwt_secret: str, jwt_algorithm: str) -> str:
    """Create a valid access token for the test user."""
    expires = datetime.utcnow() + timedelta(minutes=30)
    to_encode = {
        "sub": test_user["id"],
        "auth_id": test_user["auth_id"],
        "exp": expires,
    }
    return jwt.encode(to_encode, jwt_secret, algorithm=jwt_algorithm)


@pytest.fixture
def refresh_token(test_user: Dict, jwt_secret: str, jwt_algorithm: str) -> str:
    """Create a valid refresh token for the test user."""
    expires = datetime.utcnow() + timedelta(days=7)
    to_encode = {
        "sub": test_user["id"],
        "auth_id": test_user["auth_id"],
        "token_type": "refresh",
        "exp": expires,
    }
    return jwt.encode(to_encode, jwt_secret, algorithm=jwt_algorithm)


@pytest.fixture
def expired_token(test_user: Dict, jwt_secret: str, jwt_algorithm: str) -> str:
    """Create an expired token for the test user."""
    expires = datetime.utcnow() - timedelta(minutes=1)
    to_encode = {
        "sub": test_user["id"],
        "auth_id": test_user["auth_id"],
        "exp": expires,
    }
    return jwt.encode(to_encode, jwt_secret, algorithm=jwt_algorithm)


@pytest.fixture
def app(db: Session) -> FastAPI:
    """Create a FastAPI test application."""
    from app.main import app
    from app.utilities.db_utils import get_db

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create a test client."""
    return TestClient(app) 