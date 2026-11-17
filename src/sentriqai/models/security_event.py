import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentriqai.core.database import Base

if TYPE_CHECKING:
    from sentriqai.models.log_source import LogSource


class SecurityEvent(Base):
    __tablename__ = "security_events"

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "log_source_id"],
            ["log_sources.tenant_id", "log_sources.id"],
            ondelete="RESTRICT",
            name="fk_security_events_log_source_tenant",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational', 'unknown')",
            name="valid_security_event_severity",
        ),
        Index(
            "uq_security_events_source_fingerprint",
            "log_source_id",
            "fingerprint",
            unique=True,
        ),
        Index(
            "uq_security_events_source_external_id",
            "log_source_id",
            "external_event_id",
            unique=True,
            postgresql_where="external_event_id IS NOT NULL",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)

    log_source_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)

    external_event_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False)

    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="unknown", server_default="unknown"
    )

    occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    raw_event: Mapped[dict] = mapped_column(JSONB, nullable=False)

    log_source: Mapped["LogSource"] = relationship(
        "LogSource",
        back_populates="security_events",
    )
