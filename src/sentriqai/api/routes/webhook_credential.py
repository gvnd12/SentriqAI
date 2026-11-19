from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import (
    CurrentTenant,
    get_db,
    require_tenant_role,
)
from sentriqai.models import LogSource, WebhookCredential
from sentriqai.schemas.webhook_credential import (
    WebhookCredentialCreatedResponse,
    WebhookCredentialCreateRequest,
    WebhookCredentialResponse,
    WebhookCredentialRotatedResponse,
)
from sentriqai.services.webhook_secret import generate_webhook_secret

webhook_credential_router = APIRouter()


@webhook_credential_router.post(
    "/{log_source_id}/webhook-credentials",
    response_model=WebhookCredentialCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_webhook_credential(
    log_source_id: UUID,
    payload: WebhookCredentialCreateRequest,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> WebhookCredentialCreatedResponse:

    tenant_id = current_tenant.tenant.id

    log_source = await session.scalar(
        select(LogSource).where(
            LogSource.id == log_source_id,
            LogSource.tenant_id == tenant_id,
        )
    )

    if log_source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log source not found.",
        )

    secret, secret_hash = generate_webhook_secret()

    credential = WebhookCredential(
        tenant_id=tenant_id,
        log_source_id=log_source_id,
        name=payload.name,
        secret_hash=secret_hash,
    )

    session.add(credential)
    await session.commit()
    await session.refresh(credential)

    return WebhookCredentialCreatedResponse(
        **WebhookCredentialResponse.model_validate(credential).model_dump(),
        secret=secret,
    )


@webhook_credential_router.get(
    "/{log_source_id}/webhook-credentials",
    response_model=list[WebhookCredentialResponse],
    status_code=status.HTTP_200_OK,
)
async def list_webhook_credentials(
    log_source_id: UUID,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[WebhookCredential]:

    tenant_id = current_tenant.tenant.id

    log_source = await session.scalar(
        select(LogSource).where(
            LogSource.id == log_source_id,
            LogSource.tenant_id == tenant_id,
        )
    )

    if log_source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log source not found.",
        )

    result = await session.scalars(
        select(WebhookCredential)
        .where(
            WebhookCredential.tenant_id == tenant_id,
            WebhookCredential.log_source_id == log_source_id,
        )
        .order_by(WebhookCredential.created_at.desc())
    )

    return list(result.all())


@webhook_credential_router.post(
    "/{log_source_id}/webhook-credentials/{credential_id}/rotate",
    response_model=WebhookCredentialRotatedResponse,
    status_code=status.HTTP_200_OK,
)
async def rotate_webhook_credential(
    log_source_id: UUID,
    credential_id: UUID,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> WebhookCredentialRotatedResponse:

    tenant_id = current_tenant.tenant.id

    credential = await session.scalar(
        select(WebhookCredential).where(
            WebhookCredential.id == credential_id,
            WebhookCredential.tenant_id == tenant_id,
            WebhookCredential.log_source_id == log_source_id,
        )
    )

    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook credential not found.",
        )

    if credential.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A revoked webhook credential cannot be rotated.",
        )

    secret, secret_hash = generate_webhook_secret()

    credential.secret_hash = secret_hash

    await session.commit()
    await session.refresh(credential)

    return WebhookCredentialRotatedResponse(
        **WebhookCredentialResponse.model_validate(credential).model_dump(),
        secret=secret,
    )


@webhook_credential_router.delete(
    "/{log_source_id}/webhook-credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_webhook_credential(
    log_source_id: UUID,
    credential_id: UUID,
    current_tenant: Annotated[
        CurrentTenant, Depends(require_tenant_role("owner", "admin"))
    ],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> None:

    credential = await session.scalar(
        select(WebhookCredential).where(
            WebhookCredential.id == credential_id,
            WebhookCredential.tenant_id == current_tenant.tenant.id,
            WebhookCredential.log_source_id == log_source_id,
        )
    )

    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook credential not found.",
        )

    if credential.revoked_at is None:
        credential.revoked_at = datetime.now(UTC)
        await session.commit()
