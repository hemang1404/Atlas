from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.security import create_access_token, verify_password
from db.session import get_db
from models.user import User
from schemas.token import Token

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=Token)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    """
    OAuth2 compatible token login endpoint.
    Accepts form-urlencoded credentials, verifies password against stored Argon2id hash,
    and returns a signed JWT access token.
    Supports providing either username or email in the form 'username' field.
    """
    user = db.scalar(
        select(User).where(
            (User.username == form_data.username) | (User.email == form_data.username)
        )
    )

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(subject=str(user.id))
    return Token(access_token=access_token, token_type="bearer")
