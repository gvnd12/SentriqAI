
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import async_sessionmaker

from sentriqai.core.security import decode_access_token
from sentriqai.models import User


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    response = await client.post(
        "/auth/register",
        json={
            "email": "analyst@example.com",
            "password": "StrongPassword123!",
            "full_name": "Test Analyst",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["email"] == "analyst@example.com"
    assert data["full_name"] == "Test Analyst"
    assert data["is_active"] is True
    assert "password_hash" not in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client: AsyncClient):
    payload = {
        "email": "analyst@example.com",
        "password": "StrongPassword123!",
    }

    first_response = await client.post("/auth/register", json=payload)

    second_response = await client.post(
        "/auth/register",
        json={
            **payload,
            "email": "ANALYST@example.com",
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 409


@pytest.mark.asyncio
async def test_register_invalid_email(client: AsyncClient):
    response = await client.post(
        "/auth/register",
        json={
            "email": "not-an-email",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_short_password(client: AsyncClient):
    response = await client.post(
        "/auth/register",
        json={
            "email": "analyst@example.com",
            "password": "short",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={
            "email": "analyst@example.com",
            "password": "StrongPassword123!",
        },
    )

    response = await client.post(
        "/auth/login",
        json={
            "email": "ANALYST@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["token_type"] == "bearer"
    assert "access_token" in data

    decoded = decode_access_token(data["access_token"])
    UUID(decoded["sub"])


@pytest.mark.asyncio
async def test_login_wrong_password(client: AsyncClient):
    await client.post(
        "/auth/register",
        json={
            "email": "analyst@example.com",
            "password": "StrongPassword123!",
        },
    )

    response = await client.post(
        "/auth/login",
        json={
            "email": "analyst@example.com",
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_login_unknown_email(client: AsyncClient):
    response = await client.post(
        "/auth/login",
        json={
            "email": "unknown@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_login_inactive_user(
    client: AsyncClient,
    test_engine,
):
    await client.post(
        "/auth/register",
        json={
            "email": "inactive@example.com",
            "password": "StrongPassword123!",
        },
    )

    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        await session.execute(
            update(User)
            .where(User.email == "inactive@example.com")
            .values(is_active=False)
        )
        await session.commit()

    response = await client.post(
        "/auth/login",
        json={
            "email": "inactive@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "This account is inactive"
