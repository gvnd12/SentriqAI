from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from sentriqai.core.security import decode_access_token
from sentriqai.models import Tenant, TenantUser


async def get_auth_headers(client: AsyncClient) -> dict[str, str]:
    """Register a test user and return authenticated request headers."""
    register_response = await client.post(
        "/auth/register",
        json={
            "email": "tenant-owner@example.com",
            "password": "StrongPassword123!",
            "full_name": "Tenant Owner",
        },
    )
    assert register_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={
            "email": "tenant-owner@example.com",
            "password": "StrongPassword123!",
        },
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_create_tenant_and_assign_owner(
    client: AsyncClient,
    test_engine,
):
    headers = await get_auth_headers(client)

    response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "  Acme Security  "},
    )

    assert response.status_code == 201

    data = response.json()

    assert data["name"] == "Acme Security"
    assert data["slug"] == "acme-security"
    assert data["role"] == "owner"
    assert data["is_active"] is True

    tenant_id = UUID(data["id"])

    token = headers["Authorization"].removeprefix("Bearer ")
    user_id = UUID(decode_access_token(token)["sub"])

    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        tenant = await session.get(Tenant, tenant_id)
        membership = await session.scalar(
            select(TenantUser).where(
                TenantUser.tenant_id == tenant_id,
                TenantUser.user_id == user_id,
            )
        )

        assert tenant is not None
        assert tenant.name == "Acme Security"

        assert membership is not None
        assert membership.role == "owner"


@pytest.mark.asyncio
async def test_create_tenant_duplicate_name(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "Acme Security"},
    )

    second_response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "Acme Security"},
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409
    assert (
        second_response.json()["detail"]
        == "An organization with this name already exists"
    )


@pytest.mark.asyncio
async def test_create_tenant_case_insensitive_duplicate(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "Acme Security"},
    )

    second_response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "ACME SECURITY"},
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409


@pytest.mark.asyncio
async def test_create_tenant_generates_unique_slugs(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    names_and_expected_slugs = [
        ("ABC Technologies", "abc-technologies"),
        ("ABC-Technologies", "abc-technologies-2"),
        ("ABC Technologies!", "abc-technologies-3"),
    ]

    for name, expected_slug in names_and_expected_slugs:
        response = await client.post(
            "/tenants",
            headers=headers,
            json={"name": name},
        )

        assert response.status_code == 201
        assert response.json()["slug"] == expected_slug


@pytest.mark.asyncio
async def test_create_tenant_name_with_literal_wildcard_characters(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "AcmeXInc"},
    )

    second_response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "Acme_Inc"},
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201


@pytest.mark.asyncio
async def test_create_tenant_without_authentication(
    client: AsyncClient,
):
    response = await client.post(
        "/tenants",
        json={"name": "Acme Security"},
    )

    assert response.status_code == 401
