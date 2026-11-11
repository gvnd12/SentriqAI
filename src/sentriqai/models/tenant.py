import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentriqai.core.database import Base

if TYPE_CHECKING:
    from sentriqai.models.log_source import LogSource
    from sentriqai.models.tenant_user import TenantUser


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    slug: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    memberships: Mapped[list["TenantUser"]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )

    log_sources: Mapped[list["LogSource"]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
    )


Index(
    "uq_tenants_name_lower",
    func.lower(Tenant.name),
    unique=True,
)
