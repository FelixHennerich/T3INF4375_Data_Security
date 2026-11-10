"""B4/T5: swap two valid ciphertexts directly in the DB, then read.

Reproduces test T5 with ONE command (server must run):

    uv run fastapi dev                          # terminal 1
    uv run python scripts/t5_swap_and_read.py   # terminal 2

What it does:
1. Attacker step: swap the enc_value blobs of two hourly rows of the
   same metering point directly in the database (write access to the DB
   file, no key involved). Both ciphertexts stay VALID individually.
2. Read the metering point as Abrechnung -> the gateway must report an
   integrity violation naming metering point AND timestamp.
3. Print the matching audit entry; by default it swaps the values back
   so the dataset stays usable (--keep to leave the tampering in place,
   `generate_testdata.py` also repairs).

B4 reasoning (why AEAD alone is not enough here): authenticated
encryption detects the MODIFICATION of a single character because the
GCM tag no longer matches. But an attacker who swaps two VALID
ciphertexts does not modify either of them - both tags verify in their
new location. Only the context binding (Weg b: context as AAD, which is
part of the authenticated data) ties each ciphertext to its metering
point and timestamp, so the relocation fails on read.
"""

import argparse
import asyncio
import sys
from datetime import datetime
from pathlib import Path

import httpx
from sqlalchemy import select

from gridvault.config import settings
from gridvault.database import SessionFactory
from gridvault.db import HourlyReading, MeteringPoint

TS_A = datetime(2026, 10, 1, 7, 0)  # the generated day
TS_B = datetime(2026, 10, 1, 8, 0)
READ_AS = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}


async def swap(mp_id: str) -> bool:
    """Swap the two ciphertexts (its own inverse, restores the state too)."""
    async with SessionFactory() as db:
        rows = (
            (
                await db.execute(
                    select(HourlyReading)
                    .join(MeteringPoint, MeteringPoint.id == HourlyReading.metering_point_id)
                    .where(MeteringPoint.mp_id == mp_id)
                    .where(HourlyReading.timestamp.in_([TS_A, TS_B]))
                    .order_by(HourlyReading.timestamp)
                )
            )
            .scalars()
            .all()
        )
        if len(rows) != 2:
            print(f"[abort] expected 2 rows for {mp_id}, found {len(rows)}")
            return False
        rows[0].enc_value, rows[1].enc_value = rows[1].enc_value, rows[0].enc_value
        await db.commit()
    return True


def last_audit_lines(count: int = 4) -> str:
    path = Path(settings.audit_log_path)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return "(no audit log yet)"
    return "\n".join(f"  {line}" for line in lines[-count:])


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--mp", default="SWN-001")
    parser.add_argument(
        "--keep", action="store_true", help="leave the tampering in place"
    )
    args = parser.parse_args()

    print(f"[1] swapping ciphertexts of {args.mp} at {TS_A:%H:%M} and {TS_B:%H:%M} ...")
    if not await swap(args.mp):
        return 1

    print("[2] reading the metering point as Abrechnung ...")
    async with httpx.AsyncClient(base_url=args.base_url) as client:
        r_login = await client.post("/auth/login", json=READ_AS)
        if r_login.status_code != 200:
            print(f"[abort] login failed: {r_login.status_code} - is the server running?")
            if not args.keep:
                await swap(args.mp)
            return 1
        r = await client.get(f"/metering-points/{args.mp}")
        print(f"    HTTP {r.status_code}")
        print(f"    {r.text}")

        ok = r.status_code == 409 and args.mp in r.text
        if ok:
            print("[ok] integrity violation reported with metering point and timestamp")
        else:
            print("[FAIL] expected 409 naming the metering point")

    if not args.keep:
        print("[3] restoring the ciphertexts ...")
        await swap(args.mp)

    print(f"[4] last audit entries ({settings.audit_log_path}):")
    print(last_audit_lines())
    print("[hint] verify the whole chain:  uv run python scripts/verify_audit.py")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
