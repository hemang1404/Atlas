from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import settings

# SQLite requires check_same_thread=False for FastAPI's multi-threaded requests
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a database session per request,
    ensuring it automatically closes when the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()