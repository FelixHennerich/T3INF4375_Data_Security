"""B4 protocol test T5 - integrity: swapped ciphertexts.

Console reproduction:

    uv run python test/t5_chiffrat_swap.py

B4/T5: swap the ciphertexts of two hourly values of the SAME metering
point directly in the database, then read as Abrechnung.
Expected: integrity violation naming metering point and timestamp,
plus an audit entry.

"""

import asyncio
import sys
from datetime import datetime

import common
from sqlalchemy import select

ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}
MP_ID = "SWN-001"
TS_A = datetime(2026, 10, 1, 7, 0)
TS_B = datetime(2026, 10, 1, 8, 0)


async def swap() -> bool:
    """Swap the enc_value blobs of TS_A and TS_B (its own inverse)."""
    from gridvault.database import SessionFactory
    from gridvault.db import HourlyReading, MeteringPoint

    async with SessionFactory() as db:
        rows = (
            (
                await db.execute(
                    select(HourlyReading)
                    .join(
                        MeteringPoint, MeteringPoint.id == HourlyReading.metering_point_id
                    )
                    .where(MeteringPoint.mp_id == MP_ID)
                    .where(HourlyReading.timestamp.in_([TS_A, TS_B]))
                    .order_by(HourlyReading.timestamp)
                )
            )
            .scalars()
            .all()
        )
        if len(rows) != 2:
            print(f"    [abort] 2 Zeilen fuer {MP_ID} erwartet, {len(rows)} gefunden")
            return False
        rows[0].enc_value, rows[1].enc_value = rows[1].enc_value, rows[0].enc_value
        await db.commit()
    return True


async def main() -> int:
    if not common.ensure_dataset():
        return 2
    p = common.Protocol("T5", "Integritätstest: vertauschte Chiffrate desselben Zählpunkts")
    snapshot = common.audit_snapshot()

    async with common.make_client() as client:
        await common.login(p, client, ABRECHNUNG)

        # Vertauschung
        p.step(1, "Angreifer: zwei gueltige Chiffrate direkt in der DB vertauschen")
        p.check("Vertauschung durchgeführt (07:00 <-> 08:00)", await swap())

        # Zählpunkt auslesen
        p.step(2, "Zählpunkt als Abrechnung lesen", f"GET /metering-points/{MP_ID}")
        r = await client.get(f"/metering-points/{MP_ID}")
        p.check(
            "HTTP 409 Integritätsverletzung",
            r.status_code == 409,
            "409",
            f"HTTP {r.status_code}",
        )
        p.check("Zählpunkt in der Meldung", MP_ID in r.text, MP_ID, r.text[:120])
        p.check("Zeitstempel in der Meldung", "2026-10-01T07:00:00" in r.text)
        print(f"    Antwort: {r.text}")

        # Ruecktausch: Protokoll fuehrt zum lesbaren Zustand zurueck,
        # alle Tests bleiben einzeln reproduzierbar
        p.step(3, "Chiffrate zuruecktauschen")
        p.check("Vertauschung rueckgaengig", await swap())
        r = await client.get(f"/metering-points/{MP_ID}")
        p.check(
            "Zählpunkt wieder lesbar",
            r.status_code == 200 and r.json().get("consumption_sum_kwh", 0) > 0,
        )


    print(f"\n")

    
    # Audit Trail
    entries = common.new_audit_entries(snapshot)
    common.print_audit("Audit-Eintraege dieses Tests", entries)

    return p.finish()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
