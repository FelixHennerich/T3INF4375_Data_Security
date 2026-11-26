"""B4 protocol test T3 - Netzanalyst: small-cell protection and export.

Console reproduction:

    uv run python test/t3_kohorte.py

B4/T3: cohort with n < 3 rejected stating n and k; cohort with n >= 3
returns the hourly sum; export contains only pseudonyms.
"""

import asyncio
import json
import sys

import common

NETZANALYST = {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026"}

PLZ_BIG = "71543"  # SWN-001..003 -> n = 3
PLZ_SMALL = "71560"  # only SWN-004 -> n = 1
HOUR_7_SUM = 2.4  # base 0.80 at 07:00, scales 1.0 + 1.3 + 0.7


async def main() -> int:
    if not common.ensure_dataset():
        return 2
    p = common.Protocol("T3", "Netzanalyst: Kohorte n<3 und n>=3, Export")
    snapshot = common.audit_snapshot()

    async with common.make_client() as client:
        await common.login(p, client, NETZANALYST)

        # Kokorte mit n Kleiner 3
        p.step(1, "Kohorte mit n < 3", f"GET /analysis/plz/{PLZ_SMALL}/hourly-sum")
        r = await client.get(f"/analysis/plz/{PLZ_SMALL}/hourly-sum")
        p.check("HTTP 403", r.status_code == 403, "403", f"HTTP {r.status_code}")
        body = r.json() if r.status_code == 403 else {}
        p.check("n angegeben", body.get("n") == 1, "1", str(body.get("n")))
        p.check("k angegeben", body.get("k") == 3, "3", str(body.get("k")))
        print(f"    Antwort: {r.text}")



        # Kohorte mit n >= 3
        p.step(2, "Kohorte mit n >= 3", f"GET /analysis/plz/{PLZ_BIG}/hourly-sum")
        r = await client.get(f"/analysis/plz/{PLZ_BIG}/hourly-sum")
        p.check("HTTP 200", r.status_code == 200, "200", f"HTTP {r.status_code}")
        body = r.json() if r.status_code == 200 else {}
        p.check("n = 3", body.get("n") == 3, "3", str(body.get("n")))
        sums = body.get("hourly_sums", [])
        p.check("24 Stundensummen", len(sums) == 24, "24", str(len(sums)))
        hour_7 = next((h for h in sums if h.get("timestamp") == "2026-10-01T07:00:00"), None)
        p.check(
            "Stundensumme 07:00 = 2.4",
            hour_7 is not None and hour_7.get("sum_kwh") == HOUR_7_SUM,
            str(HOUR_7_SUM),
            json.dumps(hour_7),
        )
        raw = json.dumps(body)
        p.check("keine Namen in der Antwort", "Mustermann" not in raw)
        p.check("keine Einzelwerte in der Antwort", "hourly_values" not in raw)
        print(f"    Stundensummen: {[h['sum_kwh'] for h in sums]}")



        # Datenexport
        p.step(3, "Export fuer das Analyseverfahren", f"POST /analysis/plz/{PLZ_BIG}/export")
        r = await client.post(f"/analysis/plz/{PLZ_BIG}/export")
        p.check("HTTP 200", r.status_code == 200, "200", f"HTTP {r.status_code}")
        body = r.json() if r.status_code == 200 else {}
        series = body.get("pseudonymized_series", [])
        p.check("3 Reihen", len(series) == 3, "3", str(len(series)))
        if series:
            p.check("Pseudonym = 64 Hex-Zeichen", len(series[0]["pseudonym"]) == 64)
            p.check("24 Stundenwerte je Reihe", len(series[0]["hourly_kwh"]) == 24)
        raw = json.dumps(body)
        p.check("keine Zählpunkt-IDs im Export", "SWN-001" not in raw)
        p.check("keine Namen im Export", "Mustermann" not in raw)
        print(f"    Pseudonyme: {[s['pseudonym'][:16] + '...' for s in series]}")



    print(f"\n")

    
    # Audit Trail
    entries = common.new_audit_entries(snapshot)
    common.print_audit("Audit-Eintraege dieses Tests", entries)

    return p.finish()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
