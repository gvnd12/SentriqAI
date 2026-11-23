import hashlib
from datetime import UTC, datetime
from uuid import UUID

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.core.dependencies import get_webhook_credential
from sentriqai.models import SecurityEvent, TenantUser, User, WebhookCredential
from sentriqai.services.webhook_secret import hash_webhook_secret


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


async def create_webhook_credential(
    test_engine,
    tenant_id: str,
    log_source_id: str,
    secret: str,
    revoked: bool = False,
) -> WebhookCredential:
    credential = WebhookCredential(
        tenant_id=UUID(tenant_id),
        log_source_id=UUID(log_source_id),
        name="Authentication Test",
        secret_hash=hash_webhook_secret(secret),
        revoked_at=datetime.now(UTC) if revoked else None,
    )

    async with AsyncSession(test_engine, expire_on_commit=False) as session:
        session.add(credential)
        await session.commit()
        await session.refresh(credential)

    return credential


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


@pytest.mark.asyncio
async def test_webhook_authentication_rejects_missing_secret(
    test_engine,
) -> None:
    async with AsyncSession(test_engine) as session:
        with pytest.raises(HTTPException) as exc_info:
            await get_webhook_credential(
                UUID(int=0), session=session, webhook_secret=None
            )
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_webhook_authentication_rejects_unknown_secret(
    test_engine,
) -> None:
    async with AsyncSession(test_engine) as session:
        with pytest.raises(HTTPException) as exc_info:
            await get_webhook_credential(
                UUID(int=0),
                session,
                "whsec_invalid-secret",
            )

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_webhook_authentication_rejects_revoked_credential(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Revoked Auth Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        "whsec_revoked-secret",
        revoked=True,
    )

    async with AsyncSession(test_engine) as session:
        with pytest.raises(HTTPException) as exc_info:
            await get_webhook_credential(
                credential.id,
                session,
                "whsec_revoked-secret",
            )

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_webhook_authentication_accepts_valid_credential(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Valid Auth Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        "whsec_valid-secret",
    )

    async with AsyncSession(test_engine, expire_on_commit=False) as session:
        authenticated = await get_webhook_credential(
            credential.id,
            session,
            "whsec_valid-secret",
        )
        assert authenticated.id == credential.id
        assert str(authenticated.tenant_id) == tenant_id
        assert str(authenticated.log_source_id) == log_source_id
        assert authenticated.last_used_at is not None

        await session.commit()


@pytest.mark.asyncio
async def test_public_webhook_creates_security_event(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Public Webhook Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    secret = "whsec_public-webhook-test-secret"
    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        secret,
    )

    response = await client.post(
        f"/webhooks/{credential.id}/events",
        headers={"X-Webhook-Secret": secret},
        json={
            "external_event_id": "public-event-001",
            "event_type": "login_failure",
            "severity": "high",
            "occurred_at": "2026-11-17T10:30:00Z",
            "raw_event": {
                "user": "demo-user",
                "source_ip": "192.0.2.10",
            },
        },
    )

    assert response.status_code == 201

    data = response.json()
    assert data["tenant_id"] == tenant_id
    assert data["log_source_id"] == log_source_id
    assert data["external_event_id"] == "public-event-001"
    assert data["event_type"] == "login_failure"
    assert data["severity"] == "high"
    assert data["fingerprint"]
    assert data["received_at"]
    assert "raw_event" not in data

    async with AsyncSession(test_engine) as session:
        event = await session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.external_event_id == "public-event-001",
            )
        )

    assert event is not None
    assert str(event.tenant_id) == tenant_id
    assert str(event.log_source_id) == log_source_id


@pytest.mark.asyncio
async def test_public_webhook_duplicate_event_returns_existing_event(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Duplicate Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    secret = "whsec_duplicate-webhook-test-secret"
    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        secret,
    )

    endpoint = f"/webhooks/{credential.id}/events"
    webhook_headers = {"X-Webhook-Secret": secret}

    payload = {
        "external_event_id": "duplicate-public-event-001",
        "event_type": "login_failure",
        "severity": "high",
        "occurred_at": "2026-11-17T10:30:00Z",
        "raw_event": {"user": "demo-user"},
    }

    first_response = await client.post(
        endpoint,
        headers=webhook_headers,
        json=payload,
    )

    second_response = await client.post(
        endpoint,
        headers=webhook_headers,
        json=payload | {"severity": "critical"},
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 200

    first_data = first_response.json()
    second_data = second_response.json()

    assert second_data["id"] == first_data["id"]
    assert second_data["severity"] == "high"

    async with AsyncSession(test_engine) as session:
        count = await session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.external_event_id == "duplicate-public-event-001")
        )

    assert count == 1


@pytest.mark.asyncio
async def test_public_webhook_rejects_missing_secret(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Missing Secret Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        "whsec_missing-secret-test",
    )

    response = await client.post(
        f"/webhooks/{credential.id}/events",
        json={"event_type": "login_failure", "raw_event": {}},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook credentials."


@pytest.mark.asyncio
async def test_public_webhook_rejects_invalid_secret(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Invalid Secret Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        "whsec_correct-secret",
    )

    response = await client.post(
        f"/webhooks/{credential.id}/events",
        headers={"X-Webhook-Secret": "whsec_wrong-secret"},
        json={"event_type": "login_failure", "raw_event": {}},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook credentials."


@pytest.mark.asyncio
async def test_public_webhook_rejects_revoked_credential(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Revoked Credential Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    secret = "whsec_revoked-secret"
    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        secret,
        revoked=True,
    )

    response = await client.post(
        f"/webhooks/{credential.id}/events",
        headers={"X-Webhook-Secret": secret},
        json={"event_type": "login_failure", "raw_event": {}},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook credentials."


@pytest.mark.asyncio
async def test_public_webhook_rejects_mismatched_credential_id_and_secret(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Mismatched Credential Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    first_secret = "whsec_first-credential-secret"
    second_secret = "whsec_second-credential-secret"

    first_credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        first_secret,
    )
    await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        second_secret,
    )

    response = await client.post(
        f"/webhooks/{first_credential.id}/events",
        headers={"X-Webhook-Secret": second_secret},
        json={
            "event_type": "login_failure",
            "raw_event": {"user": "demo-user"},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid webhook credentials."


@pytest.mark.asyncio
async def test_public_webhook_rolls_back_last_used_at_on_identity_conflict(
    client: AsyncClient,
    test_engine,
) -> None:
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Webhook Rollback Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    secret = "whsec_rollback-test-secret"
    credential = await create_webhook_credential(
        test_engine,
        tenant_id,
        log_source_id,
        secret,
    )

    endpoint = f"/webhooks/{credential.id}/events"
    webhook_headers = {"X-Webhook-Secret": secret}

    first_response = await client.post(
        endpoint,
        headers=webhook_headers,
        json={
            "external_event_id": "event-A",
            "event_type": "login_failure",
            "severity": "high",
            "occurred_at": "2026-11-17T10:30:00Z",
            "raw_event": {"user": "alice"},
        },
    )

    second_response = await client.post(
        endpoint,
        headers=webhook_headers,
        json={
            "external_event_id": "event-B",
            "event_type": "login_failure",
            "severity": "high",
            "occurred_at": "2026-11-17T10:30:00Z",
            "raw_event": {"user": "bob"},
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    async with AsyncSession(test_engine) as session:
        last_used_before = await session.scalar(
            select(WebhookCredential.last_used_at).where(
                WebhookCredential.id == credential.id
            )
        )

    assert last_used_before is not None

    conflict_response = await client.post(
        endpoint,
        headers=webhook_headers,
        json={
            "external_event_id": "event-A",
            "event_type": "login_failure",
            "severity": "high",
            "occurred_at": "2026-11-17T10:30:00Z",
            "raw_event": {"user": "bob"},
        },
    )

    assert conflict_response.status_code == 409

    async with AsyncSession(test_engine) as session:
        last_used_after = await session.scalar(
            select(WebhookCredential.last_used_at).where(
                WebhookCredential.id == credential.id
            )
        )

    assert last_used_after == last_used_before
