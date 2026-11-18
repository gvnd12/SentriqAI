from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

EventSeverity = Literal["critical", "high", "medium", "low", "informational", "unknown"]


class SecurityEventCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_event_id: str | None = Field(default=None, max_length=255)
    event_type: str = Field(min_length=1, max_length=100)
    severity: EventSeverity = "unknown"
    occurred_at: datetime | None = None
    raw_event: dict[str, Any]

    @field_validator("external_event_id")
    @classmethod
    def normalize_external_event_id(cls, value: str | None) -> str | None:
        if value is None:
            return None

        value = value.strip()
        if not value:
            raise ValueError("External eventID cannot be empty")
        return value

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        value = value.strip().lower()

        if not value:
            raise ValueError("Event type cannot be empty")
        return value

    @field_validator("occurred_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    log_source_id: UUID
    external_event_id: str | None
    fingerprint: str
    event_type: str
    severity: EventSeverity
    occurred_at: datetime | None
    received_at: datetime
