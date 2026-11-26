"""B4 protocol test T4 - outage approval chain.

Console reproduction:

    uv run python test/t4_freigabe.py

B4/T4: Störungsdienst without grant -> request -> grant by Leitstelle ->
access inside the segment -> access outside the segment -> access after
expiry.
Expected: denied / request open / granted / value visible with name
masked / denied / denied.
"""

import asyncio
import json
import sys
from datetime import timedelta

import common
from sqlalchemy import select

STOERUNG = {"username": "stoerung_swn", "password": "Stoerung-SWN-2026"}
LEITSTELLE = {"username": "leitstelle_swn", "password": "Leitstelle-SWN-2026"}

PLZ = "71543"  # SWN-001..003
OTHER_PLZ = "71560"
TICKET = "T-2026-4242"
REASON = "Gemeldeter Spannungsabfall im Netzsegment, Pruefung vor Ort erforderlich."


async def clear_old_grants() -> None:
    """T4 starts from the denied state: remove leftover granted tickets
    from earlier runs (fresh shift)."""
    from gridvault.database import SessionFactory
    from gridvault.db import ApprovalRequest

    async with SessionFactory() as db:
        rows = (
            (
                await db.execute(
                    select(ApprovalRequest).where(ApprovalRequest.state == "genehmigt")
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            await db.delete(row)
        await db.commit()


async def expire_grant(request_id: int) -> None:
    """Pull the grant window into the past (shortened for the test)."""
    from gridvault.database import SessionFactory
    from gridvault.db import ApprovalRequest

    async with SessionFactory() as db:
        row = await db.get(ApprovalRequest, request_id)
        row.valid_until = row.valid_until - timedelta(days=365)
        await db.commit()


async def main() -> int:
    if not common.ensure_dataset():
        return 2
    p = common.Protocol("T4", "Störungsdienst-Freigabekette inkl. ausserhalb/abgelaufen")
    snapshot = common.audit_snapshot()

    await clear_old_grants()

    async with common.make_client() as client:
        # Stördienst ohen Freigabe
        p.step(1, "ohne Freigabe", f"GET /outages/plz/{PLZ}/metering-points")
        await common.login(p, client, STOERUNG)
        r = await client.get(f"/outages/plz/{PLZ}/metering-points")
        p.check("HTTP 403", r.status_code == 403, "403", f"HTTP {r.status_code}")
        p.check(
            "generische Meldung", r.json() == {"detail": "Access denied"}, "", r.text
        )


        # Anfrage stellen
        p.step(2, "Anfrage fuer das Segment stellen", "POST /outages/approval-requests")
        r = await client.post(
            "/outages/approval-requests",
            json={"plz": PLZ, "ticket_number": TICKET, "reason": REASON},
        )
        p.check("HTTP 200 - Anfrage offen", r.status_code == 200)
        request_id = r.json().get("request_id") if r.status_code == 200 else None
        print(f"    Antwort: {r.text}")

        await common.logout(client)
        await common.login(p, client, LEITSTELLE)


        # Leitstelle sieht abfrage
        p.step(3, "Leitstelle sieht offene Anfrage", "GET /outages/approval-requests")
        r = await client.get("/outages/approval-requests")
        mine = [req for req in r.json() if req["ticket_number"] == TICKET]
        p.check("Anfrage mit Ticket + Begründung sichtbar (Vier-Augen-Sicht)", len(mine) == 1)
        if mine:
            print(f"    Ticket: {mine[0]['ticket_number']}  PLZ: {mine[0]['plz']}")
            print(f"    Begruendung: {mine[0]['reason']}")


        # Freigabe durch leitstelle
        p.step(4, "Freigabe durch die Leitstelle", f"POST /outages/approval-requests/{request_id}/grant")
        r = await client.post(f"/outages/approval-requests/{request_id}/grant")
        p.check("HTTP 200 - genehmigt (30 Min. Gueltigkeit)", r.status_code == 200)
        print(f"    Antwort: {r.text}")

        await common.logout(client)
        await common.login(p, client, STOERUNG)


        # Zugriff im Segment
        p.step(5, "Zugriff IM freigegebenen Segment", f"GET /outages/plz/{PLZ}/metering-points")
        r = await client.get(f"/outages/plz/{PLZ}/metering-points")
        p.check("HTTP 200", r.status_code == 200, "200", f"HTTP {r.status_code}")
        segment = r.json() if r.status_code == 200 else []
        p.check("3 Zählpunkte im Segment", len(segment) == 3, "3", str(len(segment)))
        if segment:
            p.check(
                "Wert sichtbar, Name maskiert",
                all(e["name"] == "[HIDDEN]" and e["last_reading"]["kwh"] > 0 for e in segment),
                'name="[HIDDEN]", kwh>0',
                json.dumps(segment[0]),
            )
            print(f"    Zählpunkte: {[e['mp_id'] for e in segment]}")
            print(f"    Name: {segment[0]['name']}  letzter Wert: {segment[0]['last_reading']}")



        # Zugriff außerhalb des Segments
        p.step(6, f"Zugriff AUSSERHALB des Segments (PLZ {OTHER_PLZ})")
        r = await client.get(f"/outages/plz/{OTHER_PLZ}/metering-points")
        p.check("HTTP 403", r.status_code == 403, "403", f"HTTP {r.status_code}")



        # Zugriff nach Ablauf der Freigabe
        p.step(7, "Zugriff nach Ablauf der Freigabe (Gueltigkeit verkuerzt)")
        await expire_grant(request_id)
        print("    (Gueltigkeitsfenster im Ticket direkt in die Vergangenheit gezogen)")
        r = await client.get(f"/outages/plz/{PLZ}/metering-points")
        p.check("HTTP 403", r.status_code == 403, "403", f"HTTP {r.status_code}")


    print(f"\n")

    
    # Audit Trail
    entries = common.new_audit_entries(snapshot)
    common.print_audit("Audit-Eintraege dieses Tests", entries)

    return p.finish()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
