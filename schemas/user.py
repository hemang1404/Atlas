import uuid
from datetime import datetime
from typing_extensions import Self
from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100, description="User's full display name")
    username: str = Field(
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique URL-safe handle (alphanumeric, underscores, hyphens)",
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="Plaintext password (NIST standard: min 8 chars, max 128 to prevent hashing DoS)",
    )
    email: EmailStr = Field(description="Valid RFC 5322 email address")
    age: int | None = Field(default=None, ge=0, le=120, description="Optional age between 0 and 120")

    @model_validator(mode="after")
    def validate_password_context(self) -> Self:
        """
        NIST SP 800-63B Guidelines:
        Reject passwords containing the user's username or email local-part.
        Avoids trivial passwords like 'Username123!' or matching account names.
        """
        password_lower = self.password.lower()

        # Reject if username appears anywhere in password (case-insensitive)
        if self.username.lower() in password_lower:
            raise ValueError("Password cannot contain your username.")

        # Reject if the local-part of email appears in password
        email_local = self.email.split("@")[0].lower()
        if len(email_local) >= 3 and email_local in password_lower:
            raise ValueError("Password cannot contain your email prefix.")

        return self


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    username: str
    email: EmailStr
    age: int | None
    created_at: datetime