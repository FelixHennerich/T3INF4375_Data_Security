import json

from sqlalchemy import update

from gridvault.db import User

NETZANALYST = {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026"}
STOERUNG = {"username": "stoerung_swn", "password": "Stoerung-SWN-2026"}
KUNDE = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}
ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}

FORBIDDEN_NEEDLES = (
    "Erika Mustermann",   # name
    "Backnang",           # address
    "Spannungsabfall",    # free-text reason (ticket)
    "0.45",               # single load value (has a dot: never part of a hash)
    "Kunde-SWN-2026",     # any credential
)


async def login(client, credentials: dict) -> None:
    r = await client.post("/auth/login", json=credentials)
    assert r.status_code == 200, r.text


async def logout(client) -> None:
    await client.post("/auth/logout")


def entries(audit_log_path) -> list[dict]:
    if not audit_log_path.exists():
        return []
    return [json.loads(line) for line in audit_log_path.read_text().splitlines()]


def assert_data_poor(text: str) -> None:
    for needle in FORBIDDEN_NEEDLES:
        assert needle not in text, f"data-poor violation: {needle!r} leaked"


class TestA7RoleEnforcement:
    async def test_netzanalyst_never_gets_single_values(self, client):
        await login(client, NETZANALYST)
        # direct single-value route -> denied by purpose binding
        r = await client.get("/metering-points/SWN-001/readings")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        # direct meter read -> denied
        assert (await client.get("/metering-points/SWN-001")).status_code == 403
        # the cohort aggregate is the ONLY thing the analyst receives
        r = await client.get("/analysis/plz/71543/hourly-sum")
        assert r.status_code == 200
        body = json.dumps(r.json())
        assert "hourly_kwh" not in body  # no per-meter series
        assert "Mustermann" not in body  # never names

    async def test_stoerungsdienst_reads_nothing_without_grant(self, client):
        """The "technical support without fachlichen Lesezugriff" case:
        without a valid grant there is no read access anywhere."""
        await login(client, STOERUNG)
        # segment read without grant -> denied
        r = await client.get("/outages/plz/71543/metering-points")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        # and no access to the generic metering routes either
        assert (await client.get("/metering-points")).status_code == 403
        assert (await client.get("/metering-points/SWN-001")).status_code == 403
        assert (await client.get("/metering-points/SWN-001/readings")).status_code == 403

    async def test_permission_removal_takes_effect_before_next_query(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        from gridvault.database import SessionFactory

        await login(client, KUNDE)
        assert (await client.get("/metering-points/SWN-001")).status_code == 200

        # permission removal: deactivate the user mid-session
        async with SessionFactory() as db:
            await db.execute(
                update(User).where(User.username == "kunde_swn").values(is_active=False)
            )
            await db.commit()

        # the NEXT query is already denied - the session died instantly
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 401
        assert r.json() == {"detail": "Access denied"}
        denial_reasons = {
            e["reason"]
            for e in entries(audit_log_path)[start:]
            if e["action"] == "read_metering_point" and e["result"] == "denied"
        }
        assert "session_invalid" in denial_reasons

        # restore for the rest of the suite
        async with SessionFactory() as db:
            await db.execute(
                update(User).where(User.username == "kunde_swn").values(is_active=True)
            )
            await db.commit()
        assert (await client.get("/metering-points/SWN-001")).status_code == 200


class TestA8DataPoorProtocols:
    async def test_denial_leaks_nothing(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 403
        # HTTP response
        assert_data_poor(r.text)
        # audit trail entries written during the denial
        assert_data_poor(
            json.dumps(entries(audit_log_path)[start:])
        )

    async def test_deletion_run_leaks_nothing(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, ABRECHNUNG)
        r = await client.post("/admin/deletion-run", json={"retention_days": 3650})
        assert r.status_code == 200, r.text
        # HTTP response carries counts only - never deleted content
        assert_data_poor(r.text)
        # the audit entry documents the event only
        assert_data_poor(json.dumps(entries(audit_log_path)[start:]))
        deletion_entries = [
            e for e in entries(audit_log_path)[start:] if e["action"] == "deletion_run"
        ]
        assert deletion_entries
        assert deletion_entries[0]["object"].startswith("deletion_run:")
