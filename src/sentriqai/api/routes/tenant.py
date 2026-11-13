import re
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import (
    CurrentTenant,
    get_current_tenant,
    get_current_user,
    get_db,
    require_tenant_role,
)
from sentriqai.models import Tenant, TenantUser, User
from sentriqai.schemas.tenant import (
    TenantCreateRequest,
    TenantMemberAddRequest,
    TenantMemberResponse,
    TenantMemberUpdateRequest,
    TenantResponse,
)

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


@tenant_router.get(
    "/members",
    response_model=list[TenantMemberResponse],
    status_code=status.HTTP_200_OK,
)
async def list_tenant_members(
    current_tenant: Annotated[CurrentTenant, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[TenantMemberResponse]:
    result = await session.execute(
        select(User, TenantUser.role, TenantUser.joined_at)
        .join(TenantUser, TenantUser.user_id == User.id)
        .where(TenantUser.tenant_id == current_tenant.tenant.id)
        .order_by(TenantUser.joined_at.asc(), User.email.asc())
    )
    rows = result.all()

    return [
        TenantMemberResponse(
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            role=role,
            joined_at=joined_at,
        )
        for user, role, joined_at in rows
    ]


@tenant_router.post(
    "/members", response_model=TenantMemberResponse, status_code=status.HTTP_201_CREATED
)
async def add_tenant_member(
    data: TenantMemberAddRequest,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TenantMemberResponse:
    if current_tenant.role == "admin" and data.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the tenant owner can add administrators.",
        )
    email = str(data.email).lower()

    user = await session.scalar(select(User).where(func.lower(User.email) == email))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User account not found."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Cannot add and inactive user."
        )

    existing_membership = await session.scalar(
        select(TenantUser).where(
            TenantUser.tenant_id == current_tenant.tenant.id,
            TenantUser.user_id == user.id,
        )
    )

    if existing_membership is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this organization.",
        )

    membership = TenantUser(
        tenant_id=current_tenant.tenant.id, user_id=user.id, role=data.role
    )

    try:
        session.add(membership)
        await session.commit()
        await session.refresh(membership)
    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not add member. The user may be already be a member.",
        ) from None

    return TenantMemberResponse(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        role=membership.role,
        joined_at=membership.joined_at,
    )


@tenant_router.patch(
    "/members/{user_id}",
    response_model=TenantMemberResponse,
    status_code=status.HTTP_200_OK,
)
async def update_tenant_member(
    user_id: UUID,
    data: TenantMemberUpdateRequest,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TenantMemberResponse:

    membership = await session.scalar(
        select(TenantUser).where(
            TenantUser.tenant_id == current_tenant.tenant.id,
            TenantUser.user_id == user_id,
        )
    )

    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Tenant member not found."
        )

    if membership.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The tenant owner's role cannot be changed.",
        )

    if current_tenant.role == "admin":
        if membership.user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admins cannot change their own role.",
            )
        if membership.role not in {"analyst", "viewer"} or data.role not in {
            "analyst",
            "viewer",
        }:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admins can only manage analyst and viewer roles.",
            )

    membership.role = data.role
    await session.commit()
    await session.refresh(membership)

    result = await session.execute(select(User).where(User.id == membership.user_id))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant member not found.",
        )
    return TenantMemberResponse(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        role=membership.role,
        joined_at=membership.joined_at,
    )


@tenant_router.delete(
    "/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_tenant_member(
    user_id: UUID,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    membership = await session.scalar(
        select(TenantUser).where(
            TenantUser.tenant_id == current_tenant.tenant.id,
            TenantUser.user_id == user_id,
        )
    )

    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant member not found.",
        )

    if membership.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The tenant owner cannot be removed.",
        )

    if current_tenant.role == "admin" and membership.user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins cannot remove themselves.",
        )

    if current_tenant.role == "admin" and membership.role not in {
        "analyst",
        "viewer",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins can only remove analysts and viewers.",
        )

    await session.delete(membership)
    await session.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
