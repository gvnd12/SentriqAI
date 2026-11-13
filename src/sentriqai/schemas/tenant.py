from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

MemberRole = Literal["admin", "analyst", "viewer"]


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=150)


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    is_active: bool
    created_at: datetime
    role: str


class TenantMemberAddRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    role: MemberRole = "analyst"


class TenantMemberUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: MemberRole


class TenantMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: UUID
    email: EmailStr
    full_name: str | None
    is_active: bool
    role: str
    joined_at: datetime
