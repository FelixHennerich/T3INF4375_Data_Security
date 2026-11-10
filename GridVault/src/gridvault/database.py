"""Database engine wiring for the SQLite backend.

Holds the async engine, a session factory and the startup routine that
creates all tables. Import the session factory here; the models live in
gridvault.db.
"""

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from gridvault.config import settings
from gridvault.db import Base

engine = create_async_engine(settings.database_url, echo=False)

SessionFactory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Create all tables if they do not exist yet (idempotent startup call)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a database session per request."""
    async with SessionFactory() as session:
        yield session
