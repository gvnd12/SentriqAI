from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.database import get_db
from sentriqai.core.security import decode_access_token
from sentriqai.models import Tenant, TenantUser, User

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentTenant:
    tenant: Tenant
    role: str


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
        select(User).where(User.id == user_id, User.is_active.is_(True))
    )

    user = result.scalar_one_or_none()

    if user is None:
        raise unauthorized_exception()

    return user


async def get_current_tenant(
    tenant_id: Annotated[UUID, Header(alias="X-Tenant-ID")],
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> CurrentTenant:
    result = await session.execute(
        select(Tenant, TenantUser.role)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .where(Tenant.id == tenant_id, TenantUser.user_id == current_user.id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found!"
        )

    tenant, role = row

    return CurrentTenant(tenant=tenant, role=role)


def require_tenant_role(
    *allowed_roles: str,
    detail: str = "Insufficient permissions to perform this action.",
) -> Callable[..., Awaitable[CurrentTenant]]:
    async def role_checker(
        current_tenant: Annotated[CurrentTenant, Depends(get_current_tenant)],
    ) -> CurrentTenant:
        if current_tenant.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
        return current_tenant

    return role_checker
