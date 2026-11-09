
import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_database_connection(test_engine):
    async with test_engine.connect() as connection:
        result = await connection.execute(text("SELECT 1"))

        assert result.scalar_one() == 1
