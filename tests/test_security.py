from core.security import hash_password, verify_password


def test_hash_password_produces_argon2id_format():
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)

    # Argon2id Modular Crypt Format begins with $argon2id$
    assert hashed.startswith("$argon2id$")
    assert hashed != password


def test_verify_password_correct_and_incorrect():
    password = "CorrectHorseBatteryStaple!"
    hashed = hash_password(password)

    # Correct password succeeds
    assert verify_password(password, hashed) is True

    # Incorrect password fails
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_hash_password_generates_unique_salts():
    password = "IdenticalPassword999!"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Even with identical inputs, CSPRNG salts must produce completely distinct hashes
    assert hash1 != hash2
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True
