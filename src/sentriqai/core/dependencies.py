from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.database import get_db
from sentriqai.core.security import decode_access_token
from sentriqai.models import User

bearer_scheme = HTTPBearer(auto_error=False)


def unauthorized_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if credentials is None:
        raise unauthorized_exception()
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.InvalidTokenError:
        raise unauthorized_exception() from None

    subject = payload.get("sub")

    if not isinstance(subject, str):
        raise unauthorized_exception()

    try:
        user_id = UUID(subject)
    except ValueError:
        raise unauthorized_exception() from None

    result = await session.execute(
        select(User).where(User.id) == user_id, User.is_active.is_(True)
    )

    user = result.scalar_one_or_none()

    if user is None:
        raise unauthorized_exception()

    return user
