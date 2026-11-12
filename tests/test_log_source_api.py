from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.models import TenantUser, User


async def get_auth_headers(
    client: AsyncClient,
    email: str = "log-source-owner@example.com",
) -> dict[str, str]:
    """Register a test user and return authenticated headers."""
    register_response = await client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Log Source Owner",
        },
    )
    assert register_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={
            "email": email,
            "password": "StrongPassword123!",
        },
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def create_tenant(
    client: AsyncClient,
    headers: dict[str, str],
    name: str,
) -> str:
    """Create a tenant and return its ID."""
    response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": name},
    )
    assert response.status_code == 201

    return response.json()["id"]


async def add_tenant_member(
    client: AsyncClient,
    test_engine,
    tenant_id: str,
    email: str,
    role: str,
) -> dict[str, str]:
    headers = await get_auth_headers(client, email=email)

    async with AsyncSession(test_engine, expire_on_commit=False) as session:
        user = await session.scalar(select(User).where(User.email == email))

        assert user is not None

        membership = TenantUser(
            tenant_id=UUID(tenant_id),
            user_id=user.id,
            role=role,
        )

        session.add(membership)
        await session.commit()

    return {
        **headers,
        "X-Tenant-ID": tenant_id,
    }


@pytest.mark.asyncio
async def test_create_log_source(client: AsyncClient):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Log Source Organization")

    response = await client.post(
        "/log-sources",
        headers={
            **headers,
            "X-Tenant-ID": tenant_id,
        },
        json={
            "name": "Microsoft Sentinel Production",
            "provider": "microsoft_sentinel",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["name"] == "Microsoft Sentinel Production"
    assert data["provider"] == "microsoft_sentinel"
    assert data["tenant_id"] == tenant_id
    assert data["status"] == "pending"
    assert data["id"] is not None


@pytest.mark.asyncio
async def test_create_duplicate_log_source_returns_conflict(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Duplicate Source Organization")

    request_headers = {
        **headers,
        "X-Tenant-ID": tenant_id,
    }

    first_response = await client.post(
        "/log-sources",
        headers=request_headers,
        json={
            "name": "Production Sentinel",
            "provider": "microsoft_sentinel",
        },
    )

    second_response = await client.post(
        "/log-sources",
        headers=request_headers,
        json={
            "name": "PRODUCTION SENTINEL",
            "provider": "microsoft_sentinel",
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409


@pytest.mark.asyncio
async def test_same_log_source_name_allowed_across_tenants(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_tenant_id = await create_tenant(client, headers, "First Source Organization")
    second_tenant_id = await create_tenant(
        client, headers, "Second Source Organization"
    )

    first_response = await client.post(
        "/log-sources",
        headers={
            **headers,
            "X-Tenant-ID": first_tenant_id,
        },
        json={
            "name": "Production Sentinel",
            "provider": "microsoft_sentinel",
        },
    )

    second_response = await client.post(
        "/log-sources",
        headers={
            **headers,
            "X-Tenant-ID": second_tenant_id,
        },
        json={
            "name": "Production Sentinel",
            "provider": "microsoft_sentinel",
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    assert first_response.json()["tenant_id"] == first_tenant_id
    assert second_response.json()["tenant_id"] == second_tenant_id


@pytest.mark.asyncio
async def test_user_cannot_create_log_source_for_another_tenant(
    client: AsyncClient,
):
    owner_headers = await get_auth_headers(client)

    tenant_id = await create_tenant(
        client, owner_headers, "Private Source Organization"
    )

    other_user_headers = await get_auth_headers(
        client,
        email="another-user@example.com",
    )

    response = await client.post(
        "/log-sources",
        headers={
            **other_user_headers,
            "X-Tenant-ID": tenant_id,
        },
        json={
            "name": "Unauthorized Source",
            "provider": "microsoft_sentinel",
        },
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_client_cannot_override_tenant_or_status(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Protected Source Organization")

    response = await client.post(
        "/log-sources",
        headers={
            **headers,
            "X-Tenant-ID": tenant_id,
        },
        json={
            "name": "Injected Source",
            "provider": "microsoft_sentinel",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "status": "connected",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_log_source_without_authentication(
    client: AsyncClient,
):
    response = await client.post(
        "/log-sources",
        headers={
            "X-Tenant-ID": "00000000-0000-0000-0000-000000000001",
        },
        json={
            "name": "Unauthenticated Source",
            "provider": "microsoft_sentinel",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_log_sources_for_selected_tenant(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_tenant_id = await create_tenant(client, headers, "First Listing Organization")
    second_tenant_id = await create_tenant(
        client, headers, "Second Listing Organization"
    )

    # Create a source in the first tenant.
    await client.post(
        "/log-sources",
        headers={**headers, "X-Tenant-ID": first_tenant_id},
        json={
            "name": "First Tenant Sentinel",
            "provider": "microsoft_sentinel",
        },
    )

    # Create a source in the second tenant.
    await client.post(
        "/log-sources",
        headers={**headers, "X-Tenant-ID": second_tenant_id},
        json={
            "name": "Second Tenant Splunk",
            "provider": "splunk",
        },
    )

    response = await client.get(
        "/log-sources",
        headers={**headers, "X-Tenant-ID": first_tenant_id},
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["name"] == "First Tenant Sentinel"
    assert data[0]["tenant_id"] == first_tenant_id


@pytest.mark.asyncio
async def test_list_log_sources_when_tenant_has_no_sources(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Empty Listing Organization")

    response = await client.get(
        "/log-sources",
        headers={**headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_list_log_sources_without_tenant_membership(
    client: AsyncClient,
):
    owner_headers = await get_auth_headers(client)

    tenant_id = await create_tenant(
        client, owner_headers, "Private Listing Organization"
    )

    other_user_headers = await get_auth_headers(
        client,
        email="listing-another-user@example.com",
    )

    response = await client.get(
        "/log-sources",
        headers={
            **other_user_headers,
            "X-Tenant-ID": tenant_id,
        },
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_log_sources_without_authentication(
    client: AsyncClient,
):
    response = await client.get(
        "/log-sources",
        headers={
            "X-Tenant-ID": "00000000-0000-0000-0000-000000000001",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_log_sources_without_tenant_header(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    response = await client.get(
        "/log-sources",
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_log_source(client: AsyncClient):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Get Source Organization")

    create_response = await client.post(
        "/log-sources",
        headers={**headers, "X-Tenant-ID": tenant_id},
        json={
            "name": "Production Sentinel",
            "provider": "microsoft_sentinel",
        },
    )

    assert create_response.status_code == 201

    log_source_id = create_response.json()["id"]

    response = await client.get(
        f"/log-sources/{log_source_id}",
        headers={**headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == log_source_id
    assert data["tenant_id"] == tenant_id
    assert data["name"] == "Production Sentinel"
    assert data["provider"] == "microsoft_sentinel"
    assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_get_log_source_from_another_tenant_returns_404(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_tenant_id = await create_tenant(client, headers, "First Get Organization")
    second_tenant_id = await create_tenant(client, headers, "Second Get Organization")

    create_response = await client.post(
        "/log-sources",
        headers={**headers, "X-Tenant-ID": first_tenant_id},
        json={
            "name": "Private Sentinel",
            "provider": "microsoft_sentinel",
        },
    )

    assert create_response.status_code == 201

    log_source_id = create_response.json()["id"]

    # The user belongs to both tenants, but selects the second tenant.
    response = await client.get(
        f"/log-sources/{log_source_id}",
        headers={**headers, "X-Tenant-ID": second_tenant_id},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log source not found."


@pytest.mark.asyncio
async def test_get_nonexistent_log_source_returns_404(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Missing Source Organization")

    response = await client.get(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        headers={**headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_log_source_without_authentication(
    client: AsyncClient,
):
    response = await client.get(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        headers={
            "X-Tenant-ID": "00000000-0000-0000-0000-000000000001",
        },
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_log_source_without_tenant_header(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    response = await client.get(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_log_source(client: AsyncClient):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Update Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    create_response = await client.post(
        "/log-sources",
        json={"name": "Original Source", "provider": "splunk"},
        headers=tenant_headers,
    )
    log_source_id = create_response.json()["id"]

    response = await client.patch(
        f"/log-sources/{log_source_id}",
        json={"name": "Updated Source"},
        headers=tenant_headers,
    )

    assert response.status_code == 200
    assert response.json()["name"] == "Updated Source"
    assert response.json()["provider"] == "splunk"


@pytest.mark.asyncio
async def test_update_log_source_from_another_tenant_returns_404(
    client: AsyncClient,
):
    owner_headers = await get_auth_headers(client, email="owner_update@example.com")
    owner_tenant_id = await create_tenant(client, owner_headers, "Owner Update Tenant")
    owner_tenant_headers = {
        **owner_headers,
        "X-Tenant-ID": owner_tenant_id,
    }

    create_response = await client.post(
        "/log-sources",
        json={"name": "Private Source", "provider": "splunk"},
        headers=owner_tenant_headers,
    )
    log_source_id = create_response.json()["id"]

    other_headers = await get_auth_headers(client, email="other_update@example.com")
    other_tenant_id = await create_tenant(client, other_headers, "Other Update Tenant")
    other_tenant_headers = {
        **other_headers,
        "X-Tenant-ID": other_tenant_id,
    }

    response = await client.patch(
        f"/log-sources/{log_source_id}",
        json={"name": "Unauthorized Rename"},
        headers=other_tenant_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log source not found."


@pytest.mark.asyncio
async def test_update_nonexistent_log_source_returns_404(client: AsyncClient):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Missing Source Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    response = await client.patch(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        json={"name": "Updated Source"},
        headers=tenant_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log source not found."


@pytest.mark.asyncio
async def test_update_log_source_with_duplicate_name_returns_conflict(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Duplicate Update Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    first_response = await client.post(
        "/log-sources",
        json={"name": "First Source", "provider": "splunk"},
        headers=tenant_headers,
    )
    await client.post(
        "/log-sources",
        json={"name": "Second Source", "provider": "splunk"},
        headers=tenant_headers,
    )

    first_id = first_response.json()["id"]

    response = await client.patch(
        f"/log-sources/{first_id}",
        json={"name": "second source"},
        headers=tenant_headers,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == ("A log source with this name already exists!")


@pytest.mark.asyncio
async def test_update_log_source_with_same_name_returns_success(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Same Name Update Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    create_response = await client.post(
        "/log-sources",
        json={"name": "Existing Source", "provider": "splunk"},
        headers=tenant_headers,
    )
    log_source_id = create_response.json()["id"]

    response = await client.patch(
        f"/log-sources/{log_source_id}",
        json={"name": "Existing Source"},
        headers=tenant_headers,
    )

    assert response.status_code == 200
    assert response.json()["name"] == "Existing Source"


@pytest.mark.asyncio
async def test_update_log_source_without_authentication(client: AsyncClient):
    response = await client.patch(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        json={"name": "Updated Source"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_update_log_source_without_tenant_header(client: AsyncClient):
    headers = await get_auth_headers(client)

    response = await client.patch(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        json={"name": "Updated Source"},
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_log_source_with_empty_payload_returns_422(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Empty Patch Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    create_response = await client.post(
        "/log-sources",
        json={"name": "Source To Update", "provider": "splunk"},
        headers=tenant_headers,
    )
    log_source_id = create_response.json()["id"]

    response = await client.patch(
        f"/log-sources/{log_source_id}",
        json={},
        headers=tenant_headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_log_source_with_null_name_returns_422(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Null Patch Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    create_response = await client.post(
        "/log-sources",
        json={"name": "Source To Update", "provider": "splunk"},
        headers=tenant_headers,
    )
    log_source_id = create_response.json()["id"]

    response = await client.patch(
        f"/log-sources/{log_source_id}",
        json={"name": None},
        headers=tenant_headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_log_source_cannot_change_provider_or_status(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Forbidden Fields Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    create_response = await client.post(
        "/log-sources",
        json={"name": "Protected Source", "provider": "splunk"},
        headers=tenant_headers,
    )
    log_source_id = create_response.json()["id"]

    response = await client.patch(
        f"/log-sources/{log_source_id}",
        json={
            "name": "Renamed Source",
            "provider": "crowdstrike",
            "status": "connected",
        },
        headers=tenant_headers,
    )

    assert response.status_code == 422

    # Verify that the rejected request did not modify the source.
    get_response = await client.get(
        f"/log-sources/{log_source_id}",
        headers=tenant_headers,
    )

    assert get_response.status_code == 200
    assert get_response.json()["name"] == "Protected Source"
    assert get_response.json()["provider"] == "splunk"
    assert get_response.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_delete_log_source(client: AsyncClient):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Delete Tenant")
    tenant_headers = {**headers, "X-Tenant-ID": tenant_id}

    create_response = await client.post(
        "/log-sources",
        json={"name": "Source To Delete", "provider": "splunk"},
        headers=tenant_headers,
    )

    assert create_response.status_code == 201
    log_source_id = create_response.json()["id"]

    response = await client.delete(
        f"/log-sources/{log_source_id}",
        headers=tenant_headers,
    )

    assert response.status_code == 204
    assert response.content == b""

    # Verify that the log source was actually deleted.
    get_response = await client.get(
        f"/log-sources/{log_source_id}",
        headers=tenant_headers,
    )

    assert get_response.status_code == 404
    assert get_response.json()["detail"] == "Log source not found."


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
async def test_non_owner_cannot_delete_log_source(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await get_auth_headers(
        client,
        email="delete_owner@example.com",
    )

    tenant_id = await create_tenant(
        client,
        owner_headers,
        "Owner Only Delete Tenant",
    )

    owner_tenant_headers = {
        **owner_headers,
        "X-Tenant-ID": tenant_id,
    }

    create_response = await client.post(
        "/log-sources",
        json={"name": "Protected Source", "provider": "splunk"},
        headers=owner_tenant_headers,
    )

    assert create_response.status_code == 201
    log_source_id = create_response.json()["id"]

    member_headers = await add_tenant_member(
        client=client,
        test_engine=test_engine,
        tenant_id=tenant_id,
        email=f"{role}_delete@example.com",
        role=role,
    )

    response = await client.delete(
        f"/log-sources/{log_source_id}",
        headers=member_headers,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Only the tenant owner can delete log sources."
    )

    # Verify that the source still exists.
    get_response = await client.get(
        f"/log-sources/{log_source_id}",
        headers=owner_tenant_headers,
    )

    assert get_response.status_code == 200
    assert get_response.json()["name"] == "Protected Source"


@pytest.mark.asyncio
async def test_delete_log_source_from_another_tenant_returns_404(
    client: AsyncClient,
):
    owner_headers = await get_auth_headers(
        client,
        email="first_delete_owner@example.com",
    )

    first_tenant_id = await create_tenant(
        client,
        owner_headers,
        "First Delete Tenant",
    )

    first_tenant_headers = {
        **owner_headers,
        "X-Tenant-ID": first_tenant_id,
    }

    create_response = await client.post(
        "/log-sources",
        json={"name": "Private Source", "provider": "splunk"},
        headers=first_tenant_headers,
    )

    assert create_response.status_code == 201
    log_source_id = create_response.json()["id"]

    other_owner_headers = await get_auth_headers(
        client,
        email="second_delete_owner@example.com",
    )

    second_tenant_id = await create_tenant(
        client,
        other_owner_headers,
        "Second Delete Tenant",
    )

    second_tenant_headers = {
        **other_owner_headers,
        "X-Tenant-ID": second_tenant_id,
    }

    response = await client.delete(
        f"/log-sources/{log_source_id}",
        headers=second_tenant_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log source not found."

    # Verify that the original source still exists.
    get_response = await client.get(
        f"/log-sources/{log_source_id}",
        headers=first_tenant_headers,
    )

    assert get_response.status_code == 200


@pytest.mark.asyncio
async def test_delete_nonexistent_log_source_returns_404(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(
        client,
        headers,
        "Nonexistent Delete Tenant",
    )

    tenant_headers = {
        **headers,
        "X-Tenant-ID": tenant_id,
    }

    response = await client.delete(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        headers=tenant_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log source not found."


@pytest.mark.asyncio
async def test_delete_log_source_without_authentication(
    client: AsyncClient,
):
    response = await client.delete(
        "/log-sources/00000000-0000-0000-0000-000000000001",
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_log_source_without_tenant_header(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    response = await client.delete(
        "/log-sources/00000000-0000-0000-0000-000000000001",
        headers=headers,
    )

    assert response.status_code == 422
