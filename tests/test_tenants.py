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


@pytest.mark.asyncio
async def test_list_tenants_with_membership_roles(client, test_engine):
    headers = await get_auth_headers(client)

    # Create the first tenant.
    first = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "Alpha Security"},
    )

    # Create the second tenant.
    second = await client.post(
        "/tenants",
        headers=headers,
        json={"name": "Beta Security"},
    )

    assert first.status_code == 201
    assert second.status_code == 201

    # Change the user's role in the second tenant to analyst.
    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        membership = await session.get(
            TenantUser,
            (
                UUID(second.json()["id"]),
                UUID(
                    decode_access_token(
                        headers["Authorization"].removeprefix("Bearer ")
                    )["sub"]
                ),
            ),
        )

        assert membership is not None
        membership.role = "analyst"
        await session.commit()

    # Retrieve the user's tenant memberships.
    response = await client.get("/tenants", headers=headers)

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert [item["name"] for item in data] == [
        "Alpha Security",
        "Beta Security",
    ]
    assert data[0]["role"] == "owner"
    assert data[1]["role"] == "analyst"


@pytest.mark.asyncio
async def test_list_tenants_when_user_has_no_memberships(client):
    headers = await get_auth_headers(client)

    response = await client.get("/tenants", headers=headers)

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_tenants_without_authentication(client):
    response = await client.get("/tenants")

    assert response.status_code == 401

@pytest.mark.asyncio
async def test_get_current_tenant(client: AsyncClient):
    headers = await get_auth_headers(client)

    create_response = await client.post(
        "/tenants",
        json={"name": "Current Tenant"},
        headers=headers,
    )
    assert create_response.status_code == 201

    tenant_id = create_response.json()["id"]

    response = await client.get(
        "/tenants/current",
        headers={
            **headers,
            "X-Tenant-ID": tenant_id,
        },
    )

    assert response.status_code == 200
    assert response.json()["id"] == tenant_id
    assert response.json()["name"] == "Current Tenant"
    assert response.json()["role"] == "owner"


@pytest.mark.asyncio
async def test_switch_between_tenants(client: AsyncClient):
    headers = await get_auth_headers(client)

    first_response = await client.post(
        "/tenants",
        json={"name": "First Organization"},
        headers=headers,
    )
    second_response = await client.post(
        "/tenants",
        json={"name": "Second Organization"},
        headers=headers,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    first_tenant_id = first_response.json()["id"]
    second_tenant_id = second_response.json()["id"]

    first_selection = await client.get(
        "/tenants/current",
        headers={
            **headers,
            "X-Tenant-ID": first_tenant_id,
        },
    )

    second_selection = await client.get(
        "/tenants/current",
        headers={
            **headers,
            "X-Tenant-ID": second_tenant_id,
        },
    )

    assert first_selection.status_code == 200
    assert first_selection.json()["name"] == "First Organization"

    assert second_selection.status_code == 200
    assert second_selection.json()["name"] == "Second Organization"

@pytest.mark.asyncio
async def test_get_current_tenant_without_membership(client: AsyncClient):
    owner_headers = await get_auth_headers(client)

    create_response = await client.post(
        "/tenants",
        json={"name": "Private Organization"},
        headers=owner_headers,
    )
    assert create_response.status_code == 201

    tenant_id = create_response.json()["id"]

    register_response = await client.post(
        "/auth/register",
        json={
            "email": "another-user@example.com",
            "password": "StrongPassword123!",
            "full_name": "Another User",
        },
    )
    assert register_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={
            "email": "another-user@example.com",
            "password": "StrongPassword123!",
        },
    )
    assert login_response.status_code == 200

    other_user_headers = {
        "Authorization": (
            f"Bearer {login_response.json()['access_token']}"
        ),
        "X-Tenant-ID": tenant_id,
    }

    response = await client.get(
        "/tenants/current",
        headers=other_user_headers,
    )

    assert response.status_code == 404

@pytest.mark.asyncio
async def test_get_current_tenant_without_tenant_header(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    response = await client.get(
        "/tenants/current",
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_current_tenant_with_invalid_tenant_id(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    response = await client.get(
        "/tenants/current",
        headers={
            **headers,
            "X-Tenant-ID": "not-a-valid-uuid",
        },
    )

    assert response.status_code == 422

@pytest.mark.asyncio
async def test_get_current_tenant_without_authentication(
    client: AsyncClient,
):
    response = await client.get(
        "/tenants/current",
        headers={
            "X-Tenant-ID": "00000000-0000-0000-0000-000000000001",
        },
    )

    assert response.status_code == 401
