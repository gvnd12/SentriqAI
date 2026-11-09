
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from sentriqai.core.config import settings
from sentriqai.core.database import Base, get_db
from sentriqai.main import app


@pytest_asyncio.fixture
async def test_engine():
    engine = create_async_engine(
        settings.database_url,
        pool_pre_ping=True,
    )

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def client(test_engine):
    test_session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as test_client:
        yield test_client

    app.dependency_overrides.clear()
