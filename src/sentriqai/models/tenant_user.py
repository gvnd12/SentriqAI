import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentriqai.core.database import Base

if TYPE_CHECKING:
    from sentriqai.models.tenant import Tenant
    from sentriqai.models.user import User


class TenantUser(Base):
    __tablename__ = "tenant_users"

    __table_args__ = (
        CheckConstraint(
            "role IN ('owner','admin','analyst','viewer')", name="valid_role"
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )

    role: Mapped[str] = mapped_column(String(20), nullable=False, default="analyst")

    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="memberships")
    tenant: Mapped["Tenant"] = relationship(back_populates="memberships")
