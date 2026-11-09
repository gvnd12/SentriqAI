from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash

from sentriqai.core.config import settings

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password=password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(password=plain_password, hash=hashed_password)


def create_access_token(subject: str, expires_delta: timedelta | None = None):

    now = datetime.now(UTC)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )

    payload = {"sub": subject, "iat": now, "exp": expire}

    return jwt.encode(
        payload=payload, key=settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        jwt=token, key=settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
    )
