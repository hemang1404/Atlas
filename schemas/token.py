import uuid
from pydantic import BaseModel


class Token(BaseModel):
    """
    Response DTO returned upon successful authentication.
    """
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """
    Decoded JWT claims payload.
    """
    sub: str | None = None
    exp: int | None = None
