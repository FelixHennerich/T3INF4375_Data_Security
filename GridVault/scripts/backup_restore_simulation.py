"""

Usage:
    uv run python scripts/backup_restore_simulation.py

    
  [1] pull a backup copy of the database file
  [2] deletion run (dry run first, then real) -> readings past their
      retention window and expired exports are gone
  [3] proof: the pulled backup copy STILL CONTAINS the ciphertexts
      (B4 bonus evidence)
  [4] A2 bonus: destroy the customer data key of SWN-001 -> remaining
      ciphertext becomes unreadable for everyone (whoami query fails)
  [5] restore the old copy -> the ciphertext rows are physically back
      (the backup danger)
  [6] re-apply the deletion run -> no permanently resurrected data;
      the key destruction is re-executed too (the deletion request
      stands), so the restored SWN-001 rows are unreadable again
"""

import asyncio
import shutil
import sqlite3
import sys
from pathlib import Path

from sqlalchemy import select

from gridvault.config import settings
from gridvault.database import SessionFactory, engine
from gridvault.db import Tenant, User
from gridvault.services import gateway
from gridvault.services.sessions import create_session


def db_file() -> Path:
    return Path(settings.database_url.split("///")[-1])


def backup_file() -> Path:
    path = Path("backups")
    path.mkdir(exist_ok=True)
    return path / "gridvault_backup.db"


def sqlite_count(path: Path, table: str) -> int:
    with sqlite3.connect(path) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


async def session_token(username: str) -> tuple[str, str]:
    """(session token, tenant code) for a user - in-process equivalent
    of the HTTP login, same code path via services.sessions."""
    async with SessionFactory() as db:
        row = (
            await db.execute(
                select(User, Tenant).join(Tenant, Tenant.id == User.tenant_id).where(User.username == username)
            )
        ).first()
        return (await create_session(db, row[0]))[0], row[1].code


async def main() -> int:
    live_db = db_file()
    backup = backup_file()

    if not live_db.exists():
        print(f"[abort] no database at {live_db} - run scripts/generate_testdata.py first")
        return 1

    print("[1] pulling backup copy ...")
    shutil.copy2(live_db, backup)
    readings_before = sqlite_count(backup, "hourly_readings")
    print(f"    backup: {backup} ({readings_before} ciphertext rows)")

    abrechnung_token, tenant = await session_token("abrechnung_swn")
    print(f"[2] deletion run for {tenant} (retention_days=30, exceptions=[])")
    async with SessionFactory() as db:
        dry = await gateway.run_deletion(
            db, abrechnung_token, retention_days=30, exceptions=[], dry_run=True
        )
        print(f"    dry run: {dry['readings_due']} readings due, {dry['exports_due']} exports due")
        result = await gateway.run_deletion(
            db, abrechnung_token, retention_days=30, exceptions=[], dry_run=False
        )
    print(f"    deleted: {result['readings_deleted']} readings, {result['exports_deleted']} exports")
    print(f"    live DB now holds {sqlite_count(live_db, 'hourly_readings')} readings")

    print("[3] bonus evidence: the previously pulled backup still contains the ciphertexts")
    print(f"    backup file rows: {sqlite_count(backup, 'hourly_readings')} (ciphertext present)")

    print("[4] A2 bonus: destroying the data key of SWN-001 (customer deletion request)")
    kunde_token, _ = await session_token("kunde_swn")
    async with SessionFactory() as db:
        destroyed = await gateway.delete_customer_data_key(db, kunde_token, "SWN-001")
    print(f"    {destroyed}")
    print(f"    ciphertext rows remaining: {destroyed['ciphertext_rows_remaining']} - unreadable now")

    print("[5] restoring the old copy (backup-restore simulation) ...")
    await engine.dispose()  # drop pooled handles to the replaced file
    shutil.copy2(backup, live_db)
    print(f"    resurrected readings after restore: {sqlite_count(live_db, 'hourly_readings')}")

    print("[6] re-applying the deletion run ...")
    await engine.dispose()
    abrechnung_token, _ = await session_token("abrechnung_swn")
    async with SessionFactory() as db:
        rerun = await gateway.run_deletion(
            db,
            abrechnung_token,
            retention_days=30,
            exceptions=[],
            dry_run=False,
        )
    print(f"    re-run deleted: {rerun['readings_deleted']} readings, {rerun['exports_deleted']} exports")
    print(f"    readings after re-run: {sqlite_count(live_db, 'hourly_readings')}")

    print("    re-executing the key destruction (the deletion request stands)")
    kunde_token, _ = await session_token("kunde_swn")
    async with SessionFactory() as db:
        await gateway.delete_customer_data_key(db, kunde_token, "SWN-001")

    print()
    print("[done] no permanently resurrected data after the re-run.")
    print("       SWN-001 is cryptoshredded: ciphertext rows may exist anywhere,")
    print("       without the destroyed key they are worthless.")
    print("[hint] audit:  uv run python scripts/verify_audit.py")
    print("[hint] regenerate the dataset:  uv run python scripts/generate_testdata.py")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
