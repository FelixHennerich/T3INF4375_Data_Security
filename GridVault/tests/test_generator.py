import asyncio
import importlib.util
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from gridvault.db import HourlyReading, MeteringPoint, Tenant, User
from gridvault.services import crypto
from gridvault.services.keys import get_master_key

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
_spec = importlib.util.spec_from_file_location(
    "generate_testdata", _SCRIPTS / "generate_testdata.py"
)
generate_testdata = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_testdata)

ALL_ROLES = {"kunde", "abrechnung", "netzanalyst", "stoerungsdienst", "leitstelle"}


def make_factory(database_url: str):
    engine = create_async_engine(database_url)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False), engine


@pytest.fixture()
def db_env(tmp_path: Path):
    """Generated dataset in a temporary DB + key directory."""
    database_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
    key_dir = tmp_path / "keys"
    counts = asyncio.run(generate_testdata.generate(database_url, key_dir=key_dir))
    return database_url, key_dir, counts


@pytest.mark.asyncio
async def test_entity_counts(db_env):
    database_url, _, counts = db_env
    assert counts == {
        "tenants": 2,
        "users": 6,
        "metering_points": 8,
        "readings": 8 * 24,
    }

    factory, engine = make_factory(database_url)
    async with factory() as session:
        assert await session.scalar(select(func.count(User.id))) == 6
        assert await session.scalar(select(func.count(MeteringPoint.id))) == 8
        assert await session.scalar(select(func.count(HourlyReading.id))) == 192
    await engine.dispose()


@pytest.mark.asyncio
async def test_users_cover_all_roles_and_both_tenants(db_env):
    database_url, _, _ = db_env
    factory, engine = make_factory(database_url)
    async with factory() as session:
        users = (await session.execute(select(User))).scalars().all()
        tenants = (await session.execute(select(Tenant))).scalars().all()

        assert {u.role for u in users} == ALL_ROLES
        # every user belongs to exactly one tenant (A1)
        for user in users:
            assert user.tenant_id is not None
        # at least one customer per tenant
        for tenant in tenants:
            customers = await session.scalar(
                select(func.count(User.id)).where(
                    User.tenant_id == tenant.id, User.role == "kunde"
                )
            )
            assert customers >= 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_customers_own_exactly_one_metering_point(db_env):
    database_url, _, _ = db_env
    factory, engine = make_factory(database_url)
    async with factory() as session:
        kunde_swn = await session.scalar(
            select(User).where(User.username == "kunde_swn")
        )
        mp_swn = await session.scalar(
            select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
        )
        owned = await session.scalar(
            select(func.count(MeteringPoint.id)).where(
                MeteringPoint.customer_user_id.isnot(None)
            )
        )
        assert mp_swn.customer_user_id == kunde_swn.id
        assert owned == 2  # kunde_swn -> SWN-001, kunde_swb -> SWB-001
    await engine.dispose()


@pytest.mark.asyncio
async def test_passwords_are_argon2_hashes_and_verifiable(db_env):
    database_url, _, _ = db_env
    factory, engine = make_factory(database_url)
    async with factory() as session:
        users = (await session.execute(select(User))).scalars().all()
    await engine.dispose()

    hasher = PasswordHasher()
    by_name = {u.username: u for u in users}
    for user in users:
        assert user.password_hash.startswith("$argon2id$")
        # plaintext passwords never reach the hash (an argon2 encoded
        # string cannot contain the '-' of our test passwords, so this
        # is a deterministic check, not-heuristics)
        assert "Kunde-SWN-2026" not in user.password_hash
        assert "Kunde-SWB-2026" not in user.password_hash

    # documented plaintexts verify against the stored hashes
    assert hasher.verify(by_name["kunde_swn"].password_hash, "Kunde-SWN-2026")
    assert hasher.verify(by_name["kunde_swb"].password_hash, "Kunde-SWB-2026")
    with pytest.raises(VerifyMismatchError):
        hasher.verify(by_name["kunde_swn"].password_hash, "wrongpassword")


@pytest.mark.asyncio
async def test_ciphertexts_decrypt_only_under_own_tenant_key(db_env):
    database_url, key_dir, _ = db_env
    key_swn = get_master_key("SWN", key_dir=key_dir)
    key_swb = get_master_key("SWB", key_dir=key_dir)

    factory, engine = make_factory(database_url)
    async with factory() as session:
        stmt = (
            select(MeteringPoint, HourlyReading, Tenant)
            .join(HourlyReading, HourlyReading.metering_point_id == MeteringPoint.id)
            .join(Tenant, Tenant.id == MeteringPoint.tenant_id)
        )
        rows = (await session.execute(stmt)).all()
    await engine.dispose()

    assert len(rows) == 192
    for mp, reading, tenant in rows:
        own_key = key_swn if tenant.code == "SWN" else key_swb
        other_key = key_swb if tenant.code == "SWN" else key_swn

        # data key itself unwraps only under the tenant master key
        data_key = crypto.unwrap_data_key(
            own_key, mp.enc_data_key, f"{tenant.code}:{mp.mp_id}"
        )
        with pytest.raises(crypto.IntegrityViolation):
            crypto.unwrap_data_key(
                other_key, mp.enc_data_key, f"{tenant.code}:{mp.mp_id}"
            )

        context = crypto.build_context(tenant.code, mp.mp_id, reading.timestamp)
        # own key succeeds, value is a plausible kWh number
        value = crypto.decrypt(reading.enc_value, data_key, context)
        assert float(value) > 0
        # foreign tenant key fails for the value as well
        with pytest.raises(crypto.IntegrityViolation):
            crypto.decrypt(reading.enc_value, other_key, context)


@pytest.mark.asyncio
async def test_name_and_address_decrypt_with_stammdaten_context(db_env):
    database_url, key_dir, _ = db_env
    factory, engine = make_factory(database_url)
    async with factory() as session:
        mp = await session.scalar(
            select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
        )
        tenant = await session.scalar(select(Tenant).where(Tenant.id == mp.tenant_id))
    await engine.dispose()

    data_key = crypto.unwrap_data_key(
        get_master_key("SWN", key_dir=key_dir), mp.enc_data_key, f"{tenant.code}:{mp.mp_id}"
    )
    static_context = crypto.build_context(tenant.code, mp.mp_id, "stammdaten")
    name = crypto.decrypt(mp.enc_name, data_key, static_context)
    address = crypto.decrypt(mp.enc_address, data_key, static_context)
    assert name == "Erika Mustermann"
    assert "Backnang" in address


@pytest.mark.asyncio
async def test_generator_rerun_is_reproducible(db_env):
    database_url, key_dir, counts = db_env
    counts_2 = await generate_testdata.generate(database_url, key_dir=key_dir)
    assert counts_2 == counts


@pytest.mark.asyncio
async def test_fresh_db_file_gets_all_tables(db_env, tmp_path):
    _, key_dir, _ = db_env
    fresh_url = f"sqlite+aiosqlite:///{tmp_path}/fresh.db"
    counts = await generate_testdata.generate(fresh_url, key_dir=key_dir)
    assert counts["readings"] == 192

    engine = create_async_engine(fresh_url)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda c: inspect(c).get_table_names()))
    await engine.dispose()
    assert {"tenants", "users", "metering_points", "hourly_readings"} <= tables
