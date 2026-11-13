from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import (
    CurrentTenant,
    get_current_tenant,
    get_db,
    require_tenant_role,
)
from sentriqai.models import LogSource
from sentriqai.schemas.log_source import (
    LogSourceCreateRequest,
    LogSourceResponse,
    LogSourceUpdateRequest,
)

log_source_router = APIRouter()


@log_source_router.post(
    "", response_model=LogSourceResponse, status_code=status.HTTP_201_CREATED
)
async def create_log_source(
    payload: LogSourceCreateRequest,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> LogSource:

    tenant_id = current_tenant.tenant.id

    existing_source = await session.scalar(
        select(LogSource).where(
            LogSource.tenant_id == tenant_id,
            func.lower(LogSource.name) == payload.name.lower(),
        )
    )

    if existing_source:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A log source with this name already exists!",
        )

    log_source = LogSource(
        tenant_id=tenant_id,
        name=payload.name,
        provider=payload.provider,
        status="pending",
    )

    session.add(log_source)
    try:
        await session.commit()
        await session.refresh(log_source)
    except IntegrityError as exc:
        await session.rollback()

        original_error = getattr(exc.orig, "diag", None)
        constraint_name = getattr(original_error, "constraint_name", None)

        if constraint_name == "uq_log_sources_tenant_name_lower":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A log source with this name already exists!",
            ) from exc
        raise
    return log_source


@log_source_router.get(
    "", response_model=list[LogSourceResponse], status_code=status.HTTP_200_OK
)
async def list_log_sources(
    current_tenant: Annotated[CurrentTenant, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[LogSource]:

    result = await session.scalars(
        select(LogSource)
        .where(LogSource.tenant_id == current_tenant.tenant.id)
        .order_by(LogSource.created_at.desc())
    )

    return list(result.all())


@log_source_router.get(
    "/{log_source_id}", response_model=LogSourceResponse, status_code=status.HTTP_200_OK
)
async def get_log_source(
    log_source_id: UUID,
    current_tenant: Annotated[CurrentTenant, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> LogSource:

    log_source = await session.scalar(
        select(LogSource).where(
            LogSource.id == log_source_id,
            LogSource.tenant_id == current_tenant.tenant.id,
        )
    )

    if log_source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found."
        )

    return log_source


@log_source_router.patch(
    "/{log_source_id}", response_model=LogSourceResponse, status_code=status.HTTP_200_OK
)
async def updated_log_source(
    log_source_id: UUID,
    payload: LogSourceUpdateRequest,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> LogSource:

    log_source = await session.scalar(
        select(LogSource).where(
            LogSource.id == log_source_id,
            LogSource.tenant_id == current_tenant.tenant.id,
        )
    )

    if log_source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found."
        )

    update_data = payload.model_dump(exclude_unset=True)

    if not update_data or update_data.get("name") is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="At least one valid field must be provided.",
        )

    new_name = update_data["name"]

    existing_source = await session.scalar(
        select(LogSource).where(
            LogSource.tenant_id == current_tenant.tenant.id,
            func.lower(LogSource.name) == new_name.lower(),
            LogSource.id != log_source_id,
        )
    )

    if existing_source:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A log source with this name already exists!",
        )

    log_source.name = new_name

    try:
        await session.commit()
        await session.refresh(log_source)
    except IntegrityError as exc:
        await session.rollback()

        original_error = getattr(exc.orig, "diag", None)
        constraint_name = getattr(original_error, "constraint_name", None)

        if constraint_name == "uq_log_source_tenant_name_lower":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A log source with this name already exists!",
            ) from exc
        raise
    return log_source


@log_source_router.delete("/{log_source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_log_source(
    log_source_id: UUID,
    current_tenant: Annotated[
        CurrentTenant,
        Depends(
            require_tenant_role(
                "owner",
                detail="Only the tenant owner can delete log sources.",
            )
        ),
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> Response:

    if current_tenant.role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the tenant owner can delete log sources.",
        )

    log_source = await session.scalar(
        select(LogSource).where(
            LogSource.id == log_source_id,
            LogSource.tenant_id == current_tenant.tenant.id,
        )
    )

    if log_source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Log source not found."
        )

    await session.delete(log_source)
    await session.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
