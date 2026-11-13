from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from sentriqai.models import TenantUser, User


async def register_and_login(
    client: AsyncClient,
    email: str,
) -> dict[str, str]:
    password = "StrongPassword123!"

    register_response = await client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Test Member",
        },
    )
    assert register_response.status_code == 201

    login_response = await client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert login_response.status_code == 200

    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


async def create_test_tenant(
    client: AsyncClient,
    owner_headers: dict[str, str],
) -> str:
    response = await client.post(
        "/tenants",
        headers=owner_headers,
        json={"name": "Member Test Organization"},
    )
    assert response.status_code == 201
    return response.json()["id"]


async def add_test_member(
    client: AsyncClient,
    test_engine,
    tenant_id: str,
    email: str,
    role: str,
) -> dict[str, str]:
    headers = await register_and_login(client, email)

    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        user = await session.scalar(select(User).where(User.email == email))
        assert user is not None

        membership = TenantUser(
            tenant_id=tenant_id,
            user_id=user.id,
            role=role,
        )
        session.add(membership)
        await session.commit()

    return headers


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["owner", "admin", "analyst", "viewer"])
async def test_all_roles_can_list_tenant_members(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(
        client,
        "owner@example.com",
    )
    tenant_id = await create_test_tenant(client, owner_headers)

    if role == "owner":
        headers = owner_headers
    else:
        headers = await add_test_member(
            client,
            test_engine,
            tenant_id,
            f"{role}@example.com",
            role,
        )

    response = await client.get(
        "/tenants/members",
        headers={**headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 200

    members = response.json()
    if role == "owner":
        assert len(members) == 1
        assert members[0]["role"] == "owner"
    else:
        assert len(members) == 2
        assert {member["role"] for member in members} == {"owner", role}


@pytest.mark.asyncio
async def test_list_members_only_returns_selected_tenant_members(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(
        client,
        "owner@example.com",
    )

    first_tenant_id = await create_test_tenant(client, owner_headers)

    second_tenant_response = await client.post(
        "/tenants",
        headers=owner_headers,
        json={"name": "Second Member Organization"},
    )
    assert second_tenant_response.status_code == 201
    second_tenant_id = second_tenant_response.json()["id"]

    await add_test_member(
        client,
        test_engine,
        first_tenant_id,
        "first-member@example.com",
        "analyst",
    )

    await add_test_member(
        client,
        test_engine,
        second_tenant_id,
        "second-member@example.com",
        "viewer",
    )

    response = await client.get(
        "/tenants/members",
        headers={
            **owner_headers,
            "X-Tenant-ID": first_tenant_id,
        },
    )

    assert response.status_code == 200

    emails = {member["email"] for member in response.json()}

    assert emails == {
        "owner@example.com",
        "first-member@example.com",
    }
    assert "second-member@example.com" not in emails


@pytest.mark.asyncio
async def test_list_members_without_tenant_membership(
    client: AsyncClient,
):
    owner_headers = await register_and_login(
        client,
        "owner@example.com",
    )
    tenant_id = await create_test_tenant(client, owner_headers)

    outsider_headers = await register_and_login(
        client,
        "outsider@example.com",
    )

    response = await client.get(
        "/tenants/members",
        headers={
            **outsider_headers,
            "X-Tenant-ID": tenant_id,
        },
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_members_without_authentication(client: AsyncClient):
    response = await client.get(
        "/tenants/members",
        headers={"X-Tenant-ID": "00000000-0000-0000-0000-000000000001"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_members_without_tenant_header(
    client: AsyncClient,
):
    headers = await register_and_login(
        client,
        "owner@example.com",
    )

    response = await client.get(
        "/tenants/members",
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
async def test_owner_can_add_member(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    await register_and_login(client, "new-member@example.com")

    response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"email": "new-member@example.com", "role": role},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new-member@example.com"
    assert data["role"] == role
    assert data["user_id"]
    assert data["joined_at"]


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["analyst", "viewer"])
async def test_admin_can_add_limited_roles(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await register_and_login(client, "new-member@example.com")

    response = await client.post(
        "/tenants/members",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
        json={"email": "new-member@example.com", "role": role},
    )

    assert response.status_code == 201
    assert response.json()["role"] == role


@pytest.mark.asyncio
async def test_admin_cannot_add_another_admin(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await register_and_login(client, "new-member@example.com")

    response = await client.post(
        "/tenants/members",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
        json={"email": "new-member@example.com", "role": "admin"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Only the tenant owner can add administrators."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["analyst", "viewer"])
async def test_read_only_roles_cannot_add_members(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    member_headers = await add_test_member(
        client, test_engine, tenant_id, f"{role}@example.com", role
    )
    await register_and_login(client, "new-member@example.com")

    response = await client.post(
        "/tenants/members",
        headers={**member_headers, "X-Tenant-ID": tenant_id},
        json={"email": "new-member@example.com", "role": "analyst"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_add_member_unknown_email_returns_404(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"email": "unknown@example.com", "role": "analyst"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_add_inactive_user_returns_409(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    await register_and_login(client, "inactive@example.com")

    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
    )
    async with session_factory() as session:
        user = await session.scalar(
            select(User).where(User.email == "inactive@example.com")
        )
        assert user is not None
        user.is_active = False
        await session.commit()

    response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"email": "inactive@example.com", "role": "analyst"},
    )

    assert response.status_code == 409


@pytest.mark.asyncio
async def test_add_existing_member_returns_409(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    await register_and_login(client, "existing@example.com")

    first_response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"email": "existing@example.com", "role": "analyst"},
    )
    assert first_response.status_code == 201

    second_response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"email": "existing@example.com", "role": "viewer"},
    )

    assert second_response.status_code == 409


@pytest.mark.asyncio
async def test_add_member_rejects_invalid_role(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)
    await register_and_login(client, "new-member@example.com")

    response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"email": "new-member@example.com", "role": "owner"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_add_member_rejects_extra_fields(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)
    await register_and_login(client, "new-member@example.com")

    response = await client.post(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={
            "email": "new-member@example.com",
            "role": "analyst",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_add_member_without_authentication(client: AsyncClient):
    response = await client.post(
        "/tenants/members",
        json={"email": "new-member@example.com", "role": "analyst"},
    )

    assert response.status_code == 401


async def get_tenant_member_id(
    client: AsyncClient,
    headers: dict[str, str],
    tenant_id: str,
    email: str,
) -> str:
    response = await client.get(
        "/tenants/members",
        headers={**headers, "X-Tenant-ID": tenant_id},
    )
    assert response.status_code == 200

    member = next(member for member in response.json() if member["email"] == email)
    return member["user_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_role", "new_role"),
    [
        ("analyst", "viewer"),
        ("analyst", "admin"),
        ("admin", "analyst"),
    ],
)
async def test_owner_can_update_member_role(
    client: AsyncClient,
    test_engine,
    initial_role: str,
    new_role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    await add_test_member(
        client,
        test_engine,
        tenant_id,
        "target@example.com",
        initial_role,
    )
    user_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "target@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"role": new_role},
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == user_id
    assert response.json()["role"] == new_role


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_role", "new_role"),
    [
        ("analyst", "viewer"),
        ("viewer", "analyst"),
    ],
)
async def test_admin_can_update_limited_roles(
    client: AsyncClient,
    test_engine,
    initial_role: str,
    new_role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await add_test_member(
        client, test_engine, tenant_id, "target@example.com", initial_role
    )
    user_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "target@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
        json={"role": new_role},
    )

    assert response.status_code == 200
    assert response.json()["role"] == new_role


@pytest.mark.asyncio
async def test_admin_cannot_promote_member_to_admin(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await add_test_member(
        client, test_engine, tenant_id, "target@example.com", "analyst"
    )
    user_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "target@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
        json={"role": "admin"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_cannot_modify_another_admin(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await add_test_member(
        client, test_engine, tenant_id, "other-admin@example.com", "admin"
    )
    user_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "other-admin@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
        json={"role": "analyst"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_cannot_change_own_role(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    user_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "admin@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
        json={"role": "analyst"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Admins cannot change their own role."


@pytest.mark.asyncio
async def test_owner_role_cannot_be_changed(
    client: AsyncClient,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)
    user_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "owner@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"role": "analyst"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == ("The tenant owner's role cannot be changed.")


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["analyst", "viewer"])
async def test_read_only_roles_cannot_update_member_roles(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    member_headers = await add_test_member(
        client, test_engine, tenant_id, f"{role}@example.com", role
    )
    await add_test_member(
        client, test_engine, tenant_id, "target@example.com", "analyst"
    )
    user_id = await get_tenant_member_id(
        client, member_headers, tenant_id, "target@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**member_headers, "X-Tenant-ID": tenant_id},
        json={"role": "viewer"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_update_member_from_another_tenant_returns_404(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    first_tenant_id = await create_test_tenant(client, owner_headers)

    second_tenant_response = await client.post(
        "/tenants",
        headers=owner_headers,
        json={"name": "Second Member Organization"},
    )
    assert second_tenant_response.status_code == 201
    second_tenant_id = second_tenant_response.json()["id"]

    await add_test_member(
        client,
        test_engine,
        second_tenant_id,
        "other-tenant-member@example.com",
        "analyst",
    )
    user_id = await get_tenant_member_id(
        client,
        owner_headers,
        second_tenant_id,
        "other-tenant-member@example.com",
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**owner_headers, "X-Tenant-ID": first_tenant_id},
        json={"role": "viewer"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Tenant member not found."


@pytest.mark.asyncio
async def test_update_unknown_member_returns_404(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    response = await client.patch(
        "/tenants/members/00000000-0000-0000-0000-000000000001",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"role": "analyst"},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_member_rejects_invalid_role(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)
    user_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "owner@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"role": "owner"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_member_rejects_extra_fields(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)
    user_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "owner@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
        json={"role": "analyst", "is_active": False},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_update_member_without_authentication(client: AsyncClient):
    response = await client.patch(
        "/tenants/members/00000000-0000-0000-0000-000000000001",
        headers={"X-Tenant-ID": "00000000-0000-0000-0000-000000000001"},
        json={"role": "analyst"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_update_member_without_tenant_header(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)
    user_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "owner@example.com"
    )

    response = await client.patch(
        f"/tenants/members/{user_id}",
        headers=owner_headers,
        json={"role": "analyst"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
async def test_owner_can_remove_member(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    await add_test_member(
        client, test_engine, tenant_id, "target@example.com", role
    )

    member_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "target@example.com"
    )

    response = await client.delete(
        f"/tenants/members/{member_id}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 204
    assert response.content == b""

    members_response = await client.get(
        "/tenants/members",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
    )
    assert members_response.status_code == 200
    assert all(
        member["user_id"] != member_id
        for member in members_response.json()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["analyst", "viewer"])
async def test_admin_can_remove_analyst_or_viewer(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await add_test_member(
        client, test_engine, tenant_id, "target@example.com", role
    )

    member_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "target@example.com"
    )

    response = await client.delete(
        f"/tenants/members/{member_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 204
    assert response.content == b""

    members_response = await client.get(
        "/tenants/members",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
    )
    assert all(
        member["user_id"] != member_id
        for member in members_response.json()
    )


@pytest.mark.asyncio
async def test_admin_cannot_remove_another_admin(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    await add_test_member(
        client, test_engine, tenant_id, "another-admin@example.com", "admin"
    )

    member_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "another-admin@example.com"
    )

    response = await client.delete(
        f"/tenants/members/{member_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Admins can only remove analysts and viewers."
    )


@pytest.mark.asyncio
async def test_admin_cannot_remove_self(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    admin_headers = await add_test_member(
        client, test_engine, tenant_id, "admin@example.com", "admin"
    )
    member_id = await get_tenant_member_id(
        client, admin_headers, tenant_id, "admin@example.com"
    )

    response = await client.delete(
        f"/tenants/members/{member_id}",
        headers={**admin_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Admins cannot remove themselves."


@pytest.mark.asyncio
async def test_owner_cannot_be_removed(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    owner_id = await get_tenant_member_id(
        client, owner_headers, tenant_id, "owner@example.com"
    )

    response = await client.delete(
        f"/tenants/members/{owner_id}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "The tenant owner cannot be removed."


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["analyst", "viewer"])
async def test_read_only_roles_cannot_remove_members(
    client: AsyncClient,
    test_engine,
    role: str,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    restricted_headers = await add_test_member(
        client, test_engine, tenant_id, f"{role}@example.com", role
    )
    await add_test_member(
        client, test_engine, tenant_id, "target@example.com", "viewer"
    )

    target_id = await get_tenant_member_id(
        client, restricted_headers, tenant_id, "target@example.com"
    )

    response = await client.delete(
        f"/tenants/members/{target_id}",
        headers={**restricted_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_remove_member_from_another_tenant_returns_404(
    client: AsyncClient,
    test_engine,
):
    owner_headers = await register_and_login(client, "owner@example.com")
    first_tenant_id = await create_test_tenant(client, owner_headers)

    second_owner_headers = await register_and_login(
        client, "second_owner@example.com"
    )

    second_tenant_response = await client.post(
        "/tenants",
        headers=second_owner_headers,
        json={"name": "Second Member Organization"},
    )

    assert second_tenant_response.status_code == 201
    second_tenant_id = second_tenant_response.json()["id"]

    await add_test_member(
        client,
        test_engine,
        second_tenant_id,
        "other-tenant-member@example.com",
        "analyst",
    )

    member_id = await get_tenant_member_id(
        client,
        second_owner_headers,
        second_tenant_id,
        "other-tenant-member@example.com",
    )

    response = await client.delete(
        f"/tenants/members/{member_id}",
        headers={**owner_headers, "X-Tenant-ID": first_tenant_id},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Tenant member not found."


@pytest.mark.asyncio
async def test_remove_unknown_member_returns_404(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")
    tenant_id = await create_test_tenant(client, owner_headers)

    response = await client.delete(
        f"/tenants/members/{uuid4()}",
        headers={**owner_headers, "X-Tenant-ID": tenant_id},
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_remove_member_without_authentication(client: AsyncClient):
    response = await client.delete(
        f"/tenants/members/{uuid4()}",
        headers={"X-Tenant-ID": str(uuid4())},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_remove_member_without_tenant_header(client: AsyncClient):
    owner_headers = await register_and_login(client, "owner@example.com")

    response = await client.delete(
        f"/tenants/members/{uuid4()}",
        headers=owner_headers,
    )

    assert response.status_code == 422
