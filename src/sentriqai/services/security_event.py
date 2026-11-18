import hashlib
import json
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.models import SecurityEvent
from sentriqai.schemas.security_event import SecurityEventCreateRequest


def generate_event_fingerprint(
    *, event_type: str, severity: str, occurred_at: Any, raw_event: dict
) -> str:
    fingerprint_data = {
        "event_type": event_type,
        "severity": severity,
        "occurred_at": occurred_at.isoformat() if occurred_at is not None else None,
        "raw_event": raw_event,
    }

    canonical_event = json.dumps(
        fingerprint_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )

    return hashlib.sha256(canonical_event.encode("utf-8")).hexdigest()


class EventIdentityConflict(Exception): ...


async def ingest_security_event(
    *,
    session: AsyncSession,
    tenant_id: UUID,
    log_source_id: UUID,
    payload: SecurityEventCreateRequest,
) -> tuple[SecurityEvent, bool]:

    fingerprint = generate_event_fingerprint(
        event_type=payload.event_type,
        severity=payload.severity,
        occurred_at=payload.occurred_at,
        raw_event=payload.raw_event,
    )

    statement = (
        insert(SecurityEvent)
        .values(
            tenant_id=tenant_id,
            log_source_id=log_source_id,
            external_event_id=payload.external_event_id,
            fingerprint=fingerprint,
            event_type=payload.event_type,
            severity=payload.severity,
            occurred_at=payload.occurred_at,
            raw_event=payload.raw_event,
        )
        .on_conflict_do_nothing()
        .returning(SecurityEvent.id)
    )

    inserted_id = await session.scalar(statement)

    if inserted_id is not None:
        event = await session.scalar(
            select(SecurityEvent).where(SecurityEvent.id == inserted_id)
        )

        if event is None:
            raise RuntimeError("Inserted security event could not be retrieved")

        return event, True

    existing_by_external_id = None
    existing_by_fingerprint = None

    if payload.external_event_id is not None:
        existing_by_external_id = await session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.log_source_id == log_source_id,
                SecurityEvent.external_event_id == payload.external_event_id,
            )
        )
    existing_by_fingerprint = await session.scalar(
        select(SecurityEvent).where(
            SecurityEvent.log_source_id == log_source_id,
            SecurityEvent.fingerprint == fingerprint,
        )
    )

    if (
        existing_by_external_id is not None
        and existing_by_fingerprint is not None
        and existing_by_external_id.id != existing_by_fingerprint.id
    ):
        raise EventIdentityConflict(
            "External event ID and fingerprint identity different events."
        )

    existing_event = existing_by_external_id or existing_by_fingerprint

    if existing_event is None:
        raise RuntimeError(
            "Event insertion conflicted, but no matching event was found."
        )

    return existing_event, False
