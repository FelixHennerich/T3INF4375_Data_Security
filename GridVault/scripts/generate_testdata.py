"""
- 2 tenants (SWN, SWB)
- 6 users covering all 5 roles, at least one customer per tenant,
  each user belongs to exactly one tenant (A1)
- 8 metering points (4 per tenant) with 24 hourly values each (one full
  day), a realistic deterministic day/night profile (A2)
- Argon2 password hashes - plaintext passwords never touch the DB (A1)
- name/address and every single hourly value are real AES-256-GCM
  ciphertexts via the key service + crypto module; each metering point
  has its own data key wrapped with the tenant master key (A2 bonus)

Usage:
    uv run python scripts/generate_testdata.py
"""

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

from argon2 import PasswordHasher
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from gridvault.config import settings
from gridvault.db import Base, HourlyReading, MeteringPoint, Tenant, User
from gridvault.services import crypto
from gridvault.services.keys import KeyServiceError, create_master_key, get_master_key

DAY = datetime(2026, 10, 1, 0, 0)  # the one full day every MP carries (naive)

# Roles: kunde, abrechnung, netzanalyst, stoerungsdienst, leitstelle.
# Usernames/passwords match the Bruno collection (bruno/environments/Localhost.bru).
USERS: list[dict] = [
    {"username": "kunde_swn", "password": "Kunde-SWN-2026", "tenant": "SWN", "role": "kunde", "owns_mp": "SWN-001"},
    {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026", "tenant": "SWN", "role": "abrechnung"},
    {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026", "tenant": "SWN", "role": "netzanalyst"},
    {"username": "stoerung_swn", "password": "Stoerung-SWN-2026", "tenant": "SWN", "role": "stoerungsdienst"},
    {"username": "leitstelle_swn", "password": "Leitstelle-SWN-2026", "tenant": "SWN", "role": "leitstelle"},
    {"username": "kunde_swb", "password": "Kunde-SWB-2026", "tenant": "SWB", "role": "kunde", "owns_mp": "SWB-001"},
]

# PLZ layout: one PLZ with a >=3 cohort (T3 positive case) and one small
# cohort per tenant (Kleinzellenschutz rejection case).
METERING_POINTS: list[dict] = [
    {"mp_id": "SWN-001", "tenant": "SWN", "plz": "71543", "tariff": "Haushaltsstrom", "name": "Erika Mustermann", "address": "Bahnhofstrasse 3, 71543 Backnang", "scale": 1.0},
    {"mp_id": "SWN-002", "tenant": "SWN", "plz": "71543", "tariff": "Haushaltsstrom", "name": "Tobias Reiter", "address": "Marktplatz 7, 71543 Backnang", "scale": 1.3},
    {"mp_id": "SWN-003", "tenant": "SWN", "plz": "71543", "tariff": "Nachtstrom", "name": "Lena Weller", "address": "Willy-Brandt-Strasse 12, 71543 Backnang", "scale": 0.7},
    {"mp_id": "SWN-004", "tenant": "SWN", "plz": "71560", "tariff": "Haushaltsstrom", "name": "Jonas Braun", "address": "Schoenbacher Weg 4, 71560 Sulzbach", "scale": 1.6},
    {"mp_id": "SWB-001", "tenant": "SWB", "plz": "71332", "tariff": "Haushaltsstrom", "name": "Miriam Kohl", "address": "Hauptstrasse 21, 71332 Esslingen", "scale": 0.9},
    {"mp_id": "SWB-002", "tenant": "SWB", "plz": "71332", "tariff": "Gewerbestrom", "name": "Backerei Frisch AG", "address": "Kniestrasse 9, 71332 Esslingen", "scale": 2.4},
    {"mp_id": "SWB-003", "tenant": "SWB", "plz": "71332", "tariff": "Haushaltsstrom", "name": "Aylin Sever", "address": "Am Kanal 2, 71332 Esslingen", "scale": 1.1},
    {"mp_id": "SWB-004", "tenant": "SWB", "plz": "73431", "tariff": "Waermepumpe", "name": "Dieter Frank", "address": "Lindenhof 8, 73431 Aalen", "scale": 1.8},
]

# Deterministic day/night profile (kWh per hour, scale 1.0): night low,
# morning peak, midday plateau, evening peak ("Anwesenheitsprofil").
_BASE_CURVE = [
    0.30, 0.25, 0.22, 0.20, 0.20, 0.25,  # 00-05
    0.45, 0.80, 1.10, 0.95, 0.85, 0.90,  # 06-11
    0.95, 0.90, 0.85, 0.80, 0.85, 1.00,  # 12-17
    1.30, 1.45, 1.35, 1.05, 0.75, 0.45,  # 18-23
]

TENANTS = ("SWN", "SWB")


def hourly_kwh(hour: int, scale: float) -> str:
    return f"{_BASE_CURVE[hour] * scale:.3f}"


async def generate(database_url: str | None = None, key_dir: Path | str | None = None) -> dict:
    """(Re)create the test dataset. Returns the entity counts inserted."""
    # Fail-closed key handling: create missing tenant keys (a fresh clone
    # has no keys/ directory), never touch existing ones.
    for code in TENANTS:
        try:
            create_master_key(code, key_dir=key_dir)
            print(f"[keys] created missing master key for {code}")
        except KeyServiceError:
            pass  # key already exists - keep it, it protects existing data
    master_keys = {code: get_master_key(code, key_dir=key_dir) for code in TENANTS}

    hasher = PasswordHasher()
    engine = create_async_engine(database_url or settings.database_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Idempotent: drop and recreate all tables so re-runs are reproducible.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    counts = {"tenants": 0, "users": 0, "metering_points": 0, "readings": 0}
    # Which user owns which metering point (customer of the MP, A1).
    owner_of_mp = {u["owns_mp"]: u["username"] for u in USERS if "owns_mp" in u}
    async with factory() as session:
        tenant_ids: dict[str, int] = {}
        user_ids: dict[str, int] = {}

        for code, name in (("SWN", "Stadtwerke Neckartal"), ("SWB", "Stadtwerke Bergland")):
            tenant = Tenant(code=code, name=name)
            session.add(tenant)
            counts["tenants"] += 1
        await session.flush()
        rows = (await session.execute(select(Tenant))).scalars().all()
        tenant_ids = {t.code: t.id for t in rows}

        for spec in USERS:
            user = User(
                username=spec["username"],
                password_hash=hasher.hash(spec["password"]),
                tenant_id=tenant_ids[spec["tenant"]],
                role=spec["role"],
                is_active=True,
            )
            session.add(user)
            user_ids[spec["username"]] = user
            counts["users"] += 1
        await session.flush()

        for spec in METERING_POINTS:
            tenant_code = spec["tenant"]
            mp_id = spec["mp_id"]
            # Per-MP data key wrapped with the tenant master key (A2 bonus):
            # destroying enc_data_key makes all values unreadable (M9).
            data_key = crypto.generate_data_key()
            wrapped_key = crypto.wrap_data_key(
                master_keys[tenant_code], data_key, f"{tenant_code}:{mp_id}"
            )
            # Static contract data: context has no timestamp, just the
            # fixed marker "stammdaten" (Weg b binding still applies).
            static_context = crypto.build_context(tenant_code, mp_id, "stammdaten")
            mp = MeteringPoint(
                mp_id=mp_id,
                tenant_id=tenant_ids[tenant_code],
                plz=spec["plz"],
                tariff=spec["tariff"],
                enc_name=crypto.encrypt(spec["name"], data_key, static_context),
                enc_address=crypto.encrypt(spec["address"], data_key, static_context),
                enc_data_key=wrapped_key,
                customer_user_id=(
                    user_ids[owner_of_mp[mp_id]].id if mp_id in owner_of_mp else None
                ),
            )
            session.add(mp)
            counts["metering_points"] += 1
        await session.flush()

        mp_rows = {mp.mp_id: mp for mp in (await session.execute(select(MeteringPoint))).scalars()}

        for spec in METERING_POINTS:
            tenant_code, mp_id, scale = spec["tenant"], spec["mp_id"], spec["scale"]
            data_key = crypto.unwrap_data_key(
                master_keys[tenant_code],
                mp_rows[mp_id].enc_data_key,
                f"{tenant_code}:{mp_id}",
            )
            for hour in range(24):
                ts = DAY + timedelta(hours=hour)
                # Context (Weg b) is built from the row identity exactly as
                # the gateway will rebuild it later: naive DB timestamp.
                context = crypto.build_context(tenant_code, mp_id, ts)
                session.add(
                    HourlyReading(
                        metering_point_id=mp_rows[mp_id].id,
                        timestamp=ts,
                        enc_value=crypto.encrypt(hourly_kwh(hour, scale), data_key, context),
                    )
                )
                counts["readings"] += 1

        await session.commit()
    await engine.dispose()
    return counts


async def verify(database_url: str | None = None, key_dir: Path | str | None = None) -> bool:
    """Self-check: ciphertexts decrypt under their own tenant key only."""
    engine = create_async_engine(database_url or settings.database_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    master_keys = {code: get_master_key(code, key_dir=key_dir) for code in TENANTS}
    ok = True

    async with factory() as session:
        stmt = (
            select(MeteringPoint, HourlyReading, Tenant)
            .join(HourlyReading, HourlyReading.metering_point_id == MeteringPoint.id)
            .join(Tenant, Tenant.id == MeteringPoint.tenant_id)
            .order_by(HourlyReading.id)
        )
        rows = (await session.execute(stmt)).all()
        for mp, reading, tenant in rows:
            own = master_keys[tenant.code]
            data_key = crypto.unwrap_data_key(own, mp.enc_data_key, f"{tenant.code}:{mp.mp_id}")
            context = crypto.build_context(tenant.code, mp.mp_id, reading.timestamp)
            # own tenant key must succeed
            try:
                crypto.decrypt(reading.enc_value, data_key, context)
            except crypto.IntegrityViolation:
                print(f"[FAIL] {mp.mp_id} {reading.timestamp} does not decrypt under its own key")
                ok = False
            # the other tenant's key must fail
            other_code = "SWB" if tenant.code == "SWN" else "SWN"
            other = master_keys[other_code]
            try:
                crypto.unwrap_data_key(other, mp.enc_data_key, f"{tenant.code}:{mp.mp_id}")
                print(f"[FAIL] {mp.mp_id} unwraps under foreign tenant key {other_code}")
                ok = False
            except crypto.IntegrityViolation:
                pass  # expected
    await engine.dispose()
    return ok


def main() -> int:
    counts = asyncio.run(generate())
    print(
        f"[ok] generated: {counts['tenants']} tenants, {counts['users']} users, "
        f"{counts['metering_points']} metering points, {counts['readings']} hourly readings"
    )
    if not asyncio.run(verify()):
        print("verification FAILED")
        return 1
    print("[ok] verified: all ciphertexts decrypt under their own tenant key, foreign keys rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
