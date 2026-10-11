from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application Settings managed via pydantic-settings.

    Loads configuration from environment variables and an optional .env file.
    Precedence:
      1. Explicit constructor arguments
      2. OS Environment variables
      3. Variables in .env file
      4. Default values defined on this model
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application Configuration
    PROJECT_NAME: str = "Atlas API"
    VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Database Configuration
    DATABASE_URL: str = "sqlite:///./atlas.db"

    # Security & Authentication (JWT)
    SECRET_KEY: str = "insecure-default-change-in-production-atlas-secret-key-12345"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days


@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached singleton instance of application settings.
    Using @lru_cache ensures the .env file is read and parsed exactly once at startup.
    """
    return Settings()


settings = get_settings()
