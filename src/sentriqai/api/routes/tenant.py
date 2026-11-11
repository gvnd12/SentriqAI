import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import (
    CurrentTenant,
    get_current_tenant,
    get_current_user,
    get_db,
)
from sentriqai.models import Tenant, TenantUser, User
from sentriqai.schemas.tenant import TenantCreateRequest, TenantResponse

tenant_router = APIRouter()


def generate_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "organization"


async def get_unique_slug(session: AsyncSession, name: str) -> str:
    base_slug = generate_slug(name)
    candidate = base_slug
    counter = 2

    while await session.scalar(select(Tenant.id).where(Tenant.slug == candidate)):
        candidate = f"{base_slug}-{counter}"
        counter += 1

    return candidate


@tenant_router.post(
    "", response_model=TenantResponse, status_code=status.HTTP_201_CREATED
)
async def create_tenant(
    data: TenantCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TenantResponse:
    tenant_name = data.name.strip()
    existing_tenant = await session.scalar(
        select(Tenant.id).where(func.lower(Tenant.name) == tenant_name.lower())
    )

    if existing_tenant is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An organization with this name already exists",
        )

    slug = await get_unique_slug(session, tenant_name)
    tenant = Tenant(name=tenant_name, slug=slug)
    try:
        session.add(tenant)
        await session.flush()

        membership = TenantUser(
            tenant_id=tenant.id, user_id=current_user.id, role="owner"
        )
        session.add(membership)
        await session.commit()
        await session.refresh(tenant)

    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not create organization. Please try again.",
        ) from None

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        role=membership.role,
    )


@tenant_router.get(
    "", response_model=list[TenantResponse], status_code=status.HTTP_200_OK
)
async def list_tenant(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[TenantResponse]:

    result = await session.execute(
        select(Tenant, TenantUser.role)
        .join(TenantUser, TenantUser.tenant_id == Tenant.id)
        .where(TenantUser.user_id == current_user.id)
        .order_by(Tenant.name.asc())
    )

    rows = result.all()

    return [
        TenantResponse(
            id=tenant.id,
            name=tenant.name,
            slug=tenant.slug,
            is_active=tenant.is_active,
            created_at=tenant.created_at,
            role=role,
        )
        for tenant, role in rows
    ]


@tenant_router.get(
    "/current", response_model=TenantResponse, status_code=status.HTTP_200_OK
)
async def get_current_tenant_details(
    current_tenant: Annotated[CurrentTenant, Depends(get_current_tenant)],
) -> TenantResponse:

    tenant = current_tenant.tenant

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
        role=current_tenant.role,
    )
