import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKeyConstraint, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentriqai.core.database import Base

if TYPE_CHECKING:
    from sentriqai.models.log_source import LogSource


class WebhookCredential(Base):
    __tablename__ = "webhook_credentials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)

    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    log_source_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    name: Mapped[str] = mapped_column(String(100), nullable=False)

    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "log_source_id"],
            ["log_sources.tenant_id", "log_sources.id"],
            ondelete="RESTRICT",
            name="fk_webhook_credentials_log_source_tenant",
        ),
        Index("ix_webhook_credentials_log_source_id", "log_source_id"),
    )

    log_source: Mapped["LogSource"] = relationship(back_populates="webhook_credentials")
