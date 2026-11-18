
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentriqai.models import SecurityEvent


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

    return {
        "Authorization": f"Bearer {login_response.json()['access_token']}"
    }


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


def event_payload(
    external_event_id: str | None = "event-001",
    event_type: str = "login_failure",
    severity: str = "high",
    raw_event: dict | None = None,
) -> dict:
    return {
        "external_event_id": external_event_id,
        "event_type": event_type,
        "severity": severity,
        "occurred_at": "2026-11-17T10:30:00Z",
        "raw_event": raw_event or {
            "user": "demo-user",
            "source_ip": "192.0.2.10",
        },
    }


@pytest.mark.asyncio
async def test_create_security_event(client: AsyncClient):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Event Organization")
    log_source_id = await create_log_source(client, headers, tenant_id)

    response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json=event_payload(),
    )

    assert response.status_code == 201

    data = response.json()

    assert data["tenant_id"] == tenant_id
    assert data["log_source_id"] == log_source_id
    assert data["external_event_id"] == "event-001"
    assert data["event_type"] == "login_failure"
    assert data["severity"] == "high"
    assert len(data["fingerprint"]) == 64
    assert data["id"] is not None
    assert data["received_at"] is not None

    # Raw event data must not be exposed by the response.
    assert "raw_event" not in data


@pytest.mark.asyncio
async def test_duplicate_external_event_id_returns_existing_event(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Duplicate ID Organization")
    log_source_id = await create_log_source(client, headers, tenant_id)
    request_headers = headers | {"X-Tenant-ID": tenant_id}

    first_response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=request_headers,
        json=event_payload(),
    )

    second_response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=request_headers,
        json=event_payload(
            external_event_id="event-001",
            severity="critical",
        ),
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 200

    assert second_response.json()["id"] == first_response.json()["id"]
    assert second_response.json()["severity"] == "high"


@pytest.mark.asyncio
async def test_duplicate_fingerprint_returns_existing_event(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Duplicate Fingerprint Organization")
    log_source_id = await create_log_source(client, headers, tenant_id)
    request_headers = headers | {"X-Tenant-ID": tenant_id}

    payload = event_payload(external_event_id=None)

    first_response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=request_headers,
        json=payload,
    )

    second_response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=request_headers,
        json=payload,
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 200
    assert second_response.json()["id"] == first_response.json()["id"]


@pytest.mark.asyncio
async def test_duplicate_event_creates_only_one_database_record(
    client: AsyncClient,
    test_engine,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Event Count Organization")
    log_source_id = await create_log_source(client, headers, tenant_id)
    request_headers = headers | {"X-Tenant-ID": tenant_id}

    for _ in range(3):
        response = await client.post(
            f"/log-sources/{log_source_id}/events",
            headers=request_headers,
            json=event_payload(),
        )
        assert response.status_code in (200, 201)

    async with AsyncSession(test_engine) as session:
        count = await session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.log_source_id == UUID(log_source_id))
        )

    assert count == 1


@pytest.mark.asyncio
async def test_event_from_another_tenant_returns_404(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    first_tenant_id = await create_tenant(
        client, headers, "First Event Tenant"
    )
    second_tenant_id = await create_tenant(
        client, headers, "Second Event Tenant"
    )

    log_source_id = await create_log_source(
        client, headers, first_tenant_id
    )

    response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=headers | {"X-Tenant-ID": second_tenant_id},
        json=event_payload(),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Log source not found."


@pytest.mark.asyncio
async def test_nonexistent_log_source_returns_404(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Missing Source Tenant")

    response = await client.post(
        "/log-sources/00000000-0000-0000-0000-000000000001/events",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json=event_payload(),
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_invalid_severity_returns_422(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Invalid Severity Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    payload = event_payload(severity="emergency")

    response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json=payload,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_client_cannot_override_tenant_or_fingerprint(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Protected Event Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)

    payload = event_payload()
    payload["tenant_id"] = "00000000-0000-0000-0000-000000000001"
    payload["fingerprint"] = "a" * 64

    response = await client.post(
        f"/log-sources/{log_source_id}/events",
        headers=headers | {"X-Tenant-ID": tenant_id},
        json=payload,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_create_security_event_without_authentication(
    client: AsyncClient,
):
    response = await client.post(
        "/log-sources/00000000-0000-0000-0000-000000000001/events",
        headers={"X-Tenant-ID": "00000000-0000-0000-0000-000000000001"},
        json=event_payload(),
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_create_security_event_without_tenant_header(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)

    response = await client.post(
        "/log-sources/00000000-0000-0000-0000-000000000001/events",
        headers=headers,
        json=event_payload(),
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_external_id_and_fingerprint_conflict_returns_409(
    client: AsyncClient,
):
    headers = await get_auth_headers(client)
    tenant_id = await create_tenant(client, headers, "Identity Conflict Tenant")
    log_source_id = await create_log_source(client, headers, tenant_id)
    request_headers = headers | {"X-Tenant-ID": tenant_id}
    endpoint = f"/log-sources/{log_source_id}/events"

    first_response = await client.post(
        endpoint,
        headers=request_headers,
        json=event_payload(
            external_event_id="event-A",
            raw_event={"user": "alice"},
        ),
    )

    second_response = await client.post(
        endpoint,
        headers=request_headers,
        json=event_payload(
            external_event_id="event-B",
            raw_event={"user": "bob"},
        ),
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    conflict_response = await client.post(
        endpoint,
        headers=request_headers,
        json=event_payload(
            external_event_id="event-A",
            raw_event={"user": "bob"},
        ),
    )

    assert conflict_response.status_code == 409
