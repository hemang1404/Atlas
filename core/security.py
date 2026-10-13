from datetime import datetime, timedelta, timezone
import jwt
from pwdlib import PasswordHash

from core.config import settings

# Initialize PasswordHash with the recommended modern algorithm (Argon2id)
password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """
    Cryptographically hashes a plaintext password using Argon2id with memory-hard
    parameters (64MB RAM, 3 iterations) and an auto-generated random 16-byte salt.
    """
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash string in constant time,
    preventing timing attack vulnerabilities.
    """
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> str:
    """
    Generates a cryptographically signed HMAC-SHA256 JWT access token.
    The 'sub' (subject) claim holds the user's primary key UUID string.
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {
        "sub": str(subject),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Decodes and verifies a JWT token's signature and expiration using settings.SECRET_KEY.
    Raises jwt.PyJWTError on invalid signature, expired timestamp, or malformed claims.
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

