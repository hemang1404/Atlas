from collections.abc import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from db.session import get_db
from main import app
from models.base import Base
import models  # Ensures User model is registered on Base.metadata

# In-memory SQLite with StaticPool forces all connections to share the same RAM database
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """
    Creates a pristine database schema for each test, yields an active session,
    and drops all tables on teardown to guarantee 100% test isolation.
    """
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """
    Provides a FastAPI TestClient with the get_db dependency overridden
    to use the isolated in-memory test database session.
    """
    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def superuser_headers(db_session: Session) -> dict[str, str]:
    """
    Creates an active superuser in the test database and returns valid Bearer auth headers.
    """
    from core.security import create_access_token, hash_password
    from models.user import User

    admin = User(
        name="Admin User",
        username="admin_user",
        email="admin@example.com",
        hashed_password=hash_password("AdminPassword123!"),
        is_active=True,
        is_superuser=True,
    )
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)
    token = create_access_token(subject=str(admin.id))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def normal_user(db_session: Session) -> tuple["User", dict[str, str]]:
    """
    Creates an active regular user in the test database and returns (user, auth_headers).
    """
    from core.security import create_access_token, hash_password
    from models.user import User

    user = User(
        name="Regular User",
        username="regular_user",
        email="regular@example.com",
        hashed_password=hash_password("RegularPassword123!"),
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token(subject=str(user.id))
    return user, {"Authorization": f"Bearer {token}"}

