"""Root conftest.py — sys.path fix + async API test fixtures."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).parent))

# ---------------------------------------------------------------------------
# Async SQLite engine for API tests (scope=session to reuse across all tests)
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
async def test_engine():
    from api.db.database import Base
    import api.models  # noqa: F401 — register all models with Base

    engine = create_async_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine):
    """Provide a fresh, auto-rolled-back session per test."""
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session


# ---------------------------------------------------------------------------
# FastAPI TestClient with DB override
# ---------------------------------------------------------------------------


@pytest.fixture
async def api_client(db_session: AsyncSession):
    """AsyncClient pointed at the FastAPI app with SQLite session injected."""
    from api.main import app
    from api.db.database import get_db

    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _create_tenant(db: AsyncSession, slug: str = "test-corp") -> object:
    from api.models.tenant import Tenant

    t = Tenant(name="Test Corp", slug=slug)
    db.add(t)
    await db.flush()
    return t


async def _create_user(db: AsyncSession, tenant_id: uuid.UUID, role: str, email: str) -> object:
    from api.models.user import User
    from api.services.auth_service import hash_password

    u = User(
        tenant_id=tenant_id,
        email=email,
        hashed_password=hash_password("Password123!"),
        full_name=f"{role} User",
        role=role,
    )
    db.add(u)
    await db.flush()
    return u


@pytest.fixture
async def seeded_db(db_session: AsyncSession):
    """Return dict with (tenant, admin, analyst, viewer) seeded in the test DB."""
    import random
    slug = f"test-corp-{random.randint(10000, 99999)}"
    tenant = await _create_tenant(db_session, slug=slug)
    admin = await _create_user(db_session, tenant.id, "ADMIN", f"admin-{slug}@test.corp")
    analyst = await _create_user(db_session, tenant.id, "ANALYST", f"analyst-{slug}@test.corp")
    viewer = await _create_user(db_session, tenant.id, "VIEWER", f"viewer-{slug}@test.corp")
    return {"tenant": tenant, "admin": admin, "analyst": analyst, "viewer": viewer}


def _make_token(user) -> str:
    from api.services.auth_service import create_access_token

    role_str = getattr(user.role, "value", str(user.role))
    return create_access_token(str(user.id), str(user.tenant_id), role_str)


@pytest.fixture
async def admin_token(seeded_db):
    return _make_token(seeded_db["admin"])


@pytest.fixture
async def analyst_token(seeded_db):
    return _make_token(seeded_db["analyst"])


@pytest.fixture
async def viewer_token(seeded_db):
    return _make_token(seeded_db["viewer"])
