from pwdlib import PasswordHash

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
