from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import CurrentTenant, get_current_tenant, get_db
from sentriqai.models import LogSource
from sentriqai.schemas.security_event import (
    SecurityEventCreateRequest,
    SecurityEventResponse,
)
from sentriqai.services.security_event import (
    EventIdentityConflict,
    ingest_security_event,
)

security_event_router = APIRouter()


@security_event_router.post(
    "/{log_source_id}/events",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_security_event(
    log_source_id: UUID,
    payload: SecurityEventCreateRequest,
    response: Response,
    current_tenant: Annotated[CurrentTenant, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> SecurityEventResponse:

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

    try:
        event, created = await ingest_security_event(
            session=session,
            tenant_id=current_tenant.tenant.id,
            log_source_id=log_source.id,
            payload=payload,
        )
        await session.commit()

    except EventIdentityConflict as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except Exception:
        await session.rollback()
        raise

    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK

    return event
