import hashlib
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.models import TenantUser, User, WebhookCredential


async def get_auth_headers(
    client: AsyncClient,
    email: str = "event-owner@example.com",
) -> dict[str, str]:
    register_response = await client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Event Test Owner",
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

    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


async def create_tenant(
    client: AsyncClient,
    headers: dict[str, str],
    name: str,
) -> str:
    response = await client.post(
        "/tenants",
        headers=headers,
        json={"name": name},
    )
    assert response.status_code == 201
    return response.json()["id"]


async def create_log_source(
    client: AsyncClient,
    headers: dict[str, str],
    tenant_id: str,
) -> str:
    response = await client.post(
        "/log-sources",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={
            "name": "Test Security Source",
            "provider": "splunk",
        },
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

    async with AsyncSession(test_engine) as session:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalar_one()

        membership = TenantUser(
            tenant_id=UUID(tenant_id),
            user_id=user.id,
            role=role,
        )
        session.add(membership)
        await session.commit()

    return headers | {"X-Tenant-ID": tenant_id}


@pytest.mark.asyncio
async def test_create_webhook_credential(client: AsyncClient) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Test Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "Production Sender"},
    )

    assert response.status_code == 201

    data = response.json()
    assert data["name"] == "Production Sender"
    assert data["tenant_id"] == tenant_id
    assert data["log_source_id"] == log_source_id
    assert data["secret"].startswith("whsec_")
    assert "secret_hash" not in data


@pytest.mark.asyncio
async def test_list_webhook_credentials_does_not_expose_secrets(
    client: AsyncClient,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook List Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    create_response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "List Test Sender"},
    )
    assert create_response.status_code == 201

    response = await client.get(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 200
    data = response.json()

    assert len(data) == 1
    assert data[0]["name"] == "List Test Sender"
    assert "secret" not in data[0]
    assert "secret_hash" not in data[0]


@pytest.mark.asyncio
async def test_rotate_webhook_credential(client: AsyncClient) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Rotate Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    create_response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "Rotation Test Sender"},
    )
    assert create_response.status_code == 201

    credential_id = create_response.json()["id"]
    old_secret = create_response.json()["secret"]

    rotate_response = await client.post(
        (f"/log-sources/{log_source_id}/webhook-credentials/{credential_id}/rotate"),
        headers=headers | {"X-Tenant-ID": tenant_id},
    )

    assert rotate_response.status_code == 200

    new_secret = rotate_response.json()["secret"]
    assert new_secret.startswith("whsec_")
    assert new_secret != old_secret
    assert rotate_response.json()["id"] == credential_id
    assert "secret_hash" not in rotate_response.json()


@pytest.mark.asyncio
async def test_revoke_webhook_credential(client: AsyncClient) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Revoke Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    create_response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "Revoke Test Sender"},
    )
    assert create_response.status_code == 201

    credential_id = create_response.json()["id"]

    revoke_response = await client.delete(
        (f"/log-sources/{log_source_id}/webhook-credentials/{credential_id}"),
        headers=headers | {"X-Tenant-ID": tenant_id},
    )

    assert revoke_response.status_code == 204


@pytest.mark.asyncio
async def test_revoke_webhook_credential_is_idempotent(
    client: AsyncClient,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Idempotent Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    create_response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "Idempotent Test Sender"},
    )
    assert create_response.status_code == 201

    credential_id = create_response.json()["id"]
    credential_url = f"/log-sources/{log_source_id}/webhook-credentials/{credential_id}"
    tenant_headers = headers | {"X-Tenant-ID": tenant_id}

    first_response = await client.delete(
        credential_url,
        headers=tenant_headers,
    )
    second_response = await client.delete(
        credential_url,
        headers=tenant_headers,
    )

    assert first_response.status_code == 204
    assert second_response.status_code == 204


@pytest.mark.asyncio
async def test_cannot_rotate_revoked_webhook_credential(
    client: AsyncClient,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Revoked Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    create_response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "Revoked Sender"},
    )
    assert create_response.status_code == 201

    credential_id = create_response.json()["id"]
    tenant_headers = headers | {"X-Tenant-ID": tenant_id}

    revoke_response = await client.delete(
        (f"/log-sources/{log_source_id}/webhook-credentials/{credential_id}"),
        headers=tenant_headers,
    )
    assert revoke_response.status_code == 204

    rotate_response = await client.post(
        (f"/log-sources/{log_source_id}/webhook-credentials/{credential_id}/rotate"),
        headers=tenant_headers,
    )

    assert rotate_response.status_code == 409


@pytest.mark.asyncio
async def test_webhook_credentials_are_isolated_between_tenants(
    client: AsyncClient,
) -> None:
    headers = await get_auth_headers(client)

    tenant_one_id = await create_tenant(client, headers, "Webhook Tenant One")
    tenant_two_id = await create_tenant(client, headers, "Webhook Tenant Two")

    log_source_one_id = await create_log_source(client, headers, tenant_one_id)

    response = await client.get(
        f"/log-sources/{log_source_one_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_two_id},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_create_webhook_credential_requires_authentication(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/log-sources/00000000-0000-0000-0000-000000000001/webhook-credentials",
        json={"name": "Unauthenticated Sender"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_webhook_secret_is_stored_as_hash(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Hash Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    response = await client.post(
        f"/log-sources/{log_source_id}/webhook-credentials",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json={"name": "Hash Test Sender"},
    )

    assert response.status_code == 201

    secret = response.json()["secret"]
    expected_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()

    async with AsyncSession(test_engine) as session:
        result = await session.execute(
            select(WebhookCredential).where(
                WebhookCredential.id == UUID(response.json()["id"])
            )
        )
        credential = result.scalar_one()

    assert credential.secret_hash == expected_hash
    assert credential.secret_hash != secret


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
@pytest.mark.parametrize(
    ("operation", "expected_admin_status"),
    [
        ("create", 201),
        ("list", 200),
        ("rotate", 200),
        ("revoke", 204),
    ],
)
async def test_webhook_credential_role_permissions(
    client: AsyncClient,
    test_engine,
    role: str,
    operation: str,
    expected_admin_status: int,
) -> None:
    owner_headers = await get_auth_headers(client)
    tenant_id = await create_tenant(
        client, owner_headers, f"Webhook RBAC {role} {operation}"
    )
    log_source_id = await create_log_source(client, owner_headers, tenant_id)

    # Create a credential as the owner for operations that need one.
    credential_id = None

    if operation != "create":
        create_response = await client.post(
            f"/log-sources/{log_source_id}/webhook-credentials",
            headers=owner_headers | {"X-Tenant-ID": tenant_id},
            json={"name": "RBAC Test Sender"},
        )
        assert create_response.status_code == 201
        credential_id = create_response.json()["id"]

    member_headers = await add_tenant_member(
        client=client,
        test_engine=test_engine,
        tenant_id=tenant_id,
        email=f"webhook-{role}-{operation}@example.com",
        role=role,
    )

    base_url = f"/log-sources/{log_source_id}/webhook-credentials"

    if operation == "create":
        response = await client.post(
            base_url,
            headers=member_headers,
            json={"name": "Member Created Sender"},
        )
    elif operation == "list":
        response = await client.get(
            base_url,
            headers=member_headers,
        )
    elif operation == "rotate":
        response = await client.post(
            f"{base_url}/{credential_id}/rotate",
            headers=member_headers,
        )
    else:
        response = await client.delete(
            f"{base_url}/{credential_id}",
            headers=member_headers,
        )

    if role == "admin":
        assert response.status_code == expected_admin_status
    else:
        assert response.status_code == 403
