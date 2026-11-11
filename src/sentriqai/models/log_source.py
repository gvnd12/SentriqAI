import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentriqai.core.database import Base

if TYPE_CHECKING:
    from sentriqai.models.tenant import Tenant

class LogSource(Base):
    __tablename__ = "log_sources"

    __table_args__ = (CheckConstraint(
        "status IN ('pending', 'connected', 'disconnected', 'error')",
        name="valid_status",
    ),)

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )

    name: Mapped[str] = mapped_column(String(150), nullable=False)

    provider: Mapped[str] = mapped_column(String(100), nullable=False)

    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    tenant : Mapped["Tenant"] = relationship(back_populates="log_sources")


Index(
    "uq_log_sources_tenant_name_lower",
    LogSource.tenant_id,
    func.lower(LogSource.name),
    unique=True,
)
