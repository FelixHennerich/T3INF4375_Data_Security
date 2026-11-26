"""B4 protocol test T1 - login wrong then correct.

Console reproduction:

    uv run python test/t1_login.py

B4/T1: Login mit falschem und dann korrektem Passwort.
Expected: rejection without a hint whether the user exists; success
with role and tenant; BOTH events in the audit trail.
"""

import asyncio
import sys

import common

GOOD = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}
WRONG_PW = {"username": "kunde_swn", "password": "falsches-passwort"}
UNKNOWN = {"username": "gibt_es_nicht", "password": "falsches-passwort"}


async def main() -> int:
    if not common.ensure_dataset():
        return 2
    p = common.Protocol("T1", "Login mit falschem und dann korrektem Passwort")
    snapshot = common.audit_snapshot()

    async with common.make_client() as client:
        # Login mit Falschem PW
        p.step(1, "Login mit falschem Passwort (bekannter Nutzer)")
        r_wrong = await client.post("/auth/login", json=WRONG_PW)
        p.check("HTTP 401", r_wrong.status_code == 401, "401", f"HTTP {r_wrong.status_code}")
        p.check(
            "kein Session-Cookie bei Ablehnung",
            "set-cookie" not in {k.lower() for k in r_wrong.headers},
        )
        print(f"    Antwort: {r_wrong.text}")


        # Login mit unbekanntem Nutzer
        p.step(2, "Login mit unbekanntem Nutzer")
        r_unknown = await client.post("/auth/login", json=UNKNOWN)
        p.check(
            f"Antwort: {r_wrong.text}",
            r_wrong.json() == r_unknown.json() and r_wrong.text == r_unknown.text,
            repr(r_wrong.text),
            repr(r_unknown.text),
        )

        # Login mit korrektem PW
        p.step(3, "Login mit korrektem Passwort")
        r_ok = await common.login(p, client, GOOD)
        if r_ok.status_code == 200:
            body = r_ok.json()
            p.check("Rolle im Sitzungszustand", body.get("role") == "kunde", "kunde", body.get("role", ""))
            p.check("Stadtwerk im Sitzungszustand", body.get("tenant") == "SWN", "SWN", body.get("tenant", ""))
            cookie = r_ok.headers.get("set-cookie", "")
            p.check("Session-Cookie HttpOnly", "httponly" in cookie.lower())


    print(f"\n")

    
    # Audit Trail
    entries = common.new_audit_entries(snapshot)
    common.print_audit("Audit-Eintraege dieses Tests", entries)
    return p.finish()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
