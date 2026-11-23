from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import get_db, get_webhook_credential
from sentriqai.models import WebhookCredential
from sentriqai.schemas.security_event import (
    SecurityEventCreateRequest,
    SecurityEventResponse,
)
from sentriqai.services.security_event import (
    EventIdentityConflict,
    ingest_security_event,
)

public_webhook_router = APIRouter()


@public_webhook_router.post(
    "/{credential_id}/events",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def receive_webhook_event(
    payload: SecurityEventCreateRequest,
    response: Response,
    credential: Annotated[WebhookCredential, Depends(get_webhook_credential)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> SecurityEventResponse:
    try:
        event, created = await ingest_security_event(
            session=session,
            tenant_id=credential.tenant_id,
            log_source_id=credential.log_source_id,
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
