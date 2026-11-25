"""B4 protocol test T2 - Abrechnung: own tenant, foreign tenant,
attempted role escalation.

Console reproduction:

    uv run python test/t2_abrechnung.py

B4/T2: (a) own-tenant metering point -> sum and amount, load profile
masked; (b) other tenant's metering point -> denied; (c) Abrechnung
attempting a Netzanalyst action -> denied.
"""

import asyncio
import sys

import common

ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}
EXPECTED_SUM = 18.17  # canonical generator value for SWN-001 (scale 1.0)


async def main() -> int:
    if not common.ensure_dataset():
        return 2
    p = common.Protocol(
        "T2", "Abrechnung fragt eigenen / fremden Zählpunkt ab, versucht Rollenwechsel"
    )

    async with common.make_client() as client:
        await common.login(p, client, ABRECHNUNG)

        # Abfrage EIGENES Stadtwerk
        p.step(1, "(a) Zählpunkt des EIGENEN Stadtwerks (SWN-001)", "GET /metering-points/SWN-001")
        r = await client.get("/metering-points/SWN-001")
        p.check("HTTP 200", r.status_code == 200, "200", f"HTTP {r.status_code}")
        body = r.json() if r.status_code == 200 else {}
        p.check(
            f"Summe = {EXPECTED_SUM} kWh",
            body.get("consumption_sum_kwh") == EXPECTED_SUM,
            str(EXPECTED_SUM),
            str(body.get("consumption_sum_kwh")),
        )
        p.check("Betrag vorhanden", body.get("amount_eur", 0) > 0)
        p.check(
            "Lastgang maskiert",
            body.get("lastprofil") == "[NICHT FREIGEGEBEN]",
            "[NICHT FREIGEGEBEN]",
            body.get("lastprofil", ""),
        )
        print(f"    Antwort: {r.text}")



        # Abfrage ANDERES Stadtwerk
        p.step(2, "(b) Zählpunkt des ANDEREN Stadtwerks (SWB-001)", "GET /metering-points/SWB-001")
        r = await client.get("/metering-points/SWB-001")
        p.check("HTTP 403", r.status_code == 403, "403", f"HTTP {r.status_code}")
        p.check(
            "Access denied",
            r.json() == {"detail": "Access denied"},
            '{"detail": "Access denied"}',
            r.text,
        )



        # Netzanalyst Aktion
        p.step(3, "(c) Netzanalysten-Aktion als Abrechnung", "GET /analysis/plz/71543/hourly-sum")
        r = await client.get("/analysis/plz/71543/hourly-sum")
        p.check("HTTP 403", r.status_code == 403, "403", f"HTTP {r.status_code}")
        p.check(
            "Access denied",
            r.json() == {"detail": "Access denied"},
            '{"detail": "Access denied"}',
            r.text,
        )


    return p.finish()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
