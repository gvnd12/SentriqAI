
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from sentriqai.models import LogSource, Tenant


@pytest.mark.asyncio
async def test_create_log_source_for_tenant(test_engine):
    session_factory = async_sessionmaker(
        test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        tenant = Tenant(
            name="Log Source Organization",
            slug="log-source-organization",
        )
        session.add(tenant)
        await session.flush()

        log_source = LogSource(
            tenant_id=tenant.id,
            name="Microsoft Sentinel Production",
            provider="microsoft_sentinel",
        )

        session.add(log_source)
        await session.commit()

        assert log_source.id is not None
        assert log_source.tenant_id == tenant.id
        assert log_source.status == "pending"

        await session.refresh(tenant, ["log_sources"])

        assert len(tenant.log_sources) == 1
        assert tenant.log_sources[0].id == log_source.id


@pytest.mark.asyncio
async def test_log_source_name_unique_within_tenant(test_engine):
    session_factory = async_sessionmaker(
        test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        tenant = Tenant(
            name="Unique Source Organization",
            slug="unique-source-organization",
        )
        session.add(tenant)
        await session.flush()

        session.add_all([
            LogSource(
                tenant_id=tenant.id,
                name="Production Sentinel",
                provider="microsoft_sentinel",
            ),
            LogSource(
                tenant_id=tenant.id,
                name="production sentinel",
                provider="microsoft_sentinel",
            ),
        ])

        with pytest.raises(IntegrityError):
            await session.commit()

        await session.rollback()


@pytest.mark.asyncio
async def test_same_log_source_name_allowed_across_tenants(test_engine):
    session_factory = async_sessionmaker(
        test_engine,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        first_tenant = Tenant(
            name="First Log Organization",
            slug="first-log-organization",
        )
        second_tenant = Tenant(
            name="Second Log Organization",
            slug="second-log-organization",
        )

        session.add_all([first_tenant, second_tenant])
        await session.flush()

        session.add_all([
            LogSource(
                tenant_id=first_tenant.id,
                name="Production Sentinel",
                provider="microsoft_sentinel",
            ),
            LogSource(
                tenant_id=second_tenant.id,
                name="Production Sentinel",
                provider="microsoft_sentinel",
            ),
        ])

        await session.commit()

        result = await session.scalar(
            select(func.count(LogSource.id))
        )

        assert result == 2
