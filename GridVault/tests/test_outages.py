import json
from datetime import timedelta

STOERUNG = {"username": "stoerung_swn", "password": "Stoerung-SWN-2026"}
LEITSTELLE = {"username": "leitstelle_swn", "password": "Leitstelle-SWN-2026"}
KUNDE = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}

PLZ = "71543"  # SWN-001..003
OTHER_PLZ = "71560"
TICKET = "T-2026-1001"
REASON = "Gemeldeter Spannungsabfall im Netzsegment, Pruefung vor Ort erforderlich."

REQUEST = {"plz": PLZ, "ticket_number": TICKET, "reason": REASON}


async def login(client, credentials: dict) -> None:
    r = await client.post("/auth/login", json=credentials)
    assert r.status_code == 200, r.text


async def logout(client) -> None:
    await client.post("/auth/logout")


def entries(audit_log_path) -> list[dict]:
    if not audit_log_path.exists():
        return []
    return [json.loads(line) for line in audit_log_path.read_text().splitlines()]


def reasons_since(audit_log_path, start: int, action: str) -> set[str]:
    return {
        e["reason"] for e in entries(audit_log_path)[start:] if e["action"] == action
    }


async def file_request(client) -> int:
    """Helper: as Stoerungsdienst, create the canonical request."""
    await login(client, STOERUNG)
    r = await client.post("/outages/approval-requests", json=REQUEST)
    assert r.status_code == 200, r.text
    return r.json()["request_id"]


class TestT4Chain:
    async def test_full_chain(self, client, audit_log_path):
        start = len(entries(audit_log_path))

        # [1] without grant -> denied
        await login(client, STOERUNG)
        r = await client.get(f"/outages/plz/{PLZ}/metering-points")
        assert r.status_code == 403
        assert "no_valid_grant" in reasons_since(audit_log_path, start, "read_outage_segment")

        # [2] request -> open
        await logout(client)
        request_id = await file_request(client)
        assert request_id > 0

        # [3] Leitstelle lists the open request (with reason - ticket view)
        await logout(client)
        await login(client, LEITSTELLE)
        listing = (await client.get("/outages/approval-requests")).json()
        mine = [req for req in listing if req["ticket_number"] == TICKET]
        assert len(mine) == 1
        assert mine[0]["reason"] == REASON
        assert mine[0]["plz"] == PLZ

        # [4] grant via four-eyes (Leitstelle != requester)
        r = await client.post(f"/outages/approval-requests/{request_id}/grant")
        assert r.status_code == 200, r.text
        assert r.json()["state"] == "genehmigt"
        assert r.json()["valid_until"]

        # [5] read inside the approved segment: value visible, name masked
        await logout(client)
        await login(client, STOERUNG)
        r = await client.get(f"/outages/plz/{PLZ}/metering-points")
        assert r.status_code == 200, r.text
        segment = r.json()
        assert len(segment) == 3
        for entry in segment:
            assert entry["name"] == "[HIDDEN]"
            assert entry["last_reading"]["kwh"] > 0
            assert entry["last_reading"]["timestamp"] == "2026-10-01T23:00:00"
        mp_ids = sorted(entry["mp_id"] for entry in segment)
        assert mp_ids == ["SWN-001", "SWN-002", "SWN-003"]

        # [6] read outside the approved segment -> denied
        r = await client.get(f"/outages/plz/{OTHER_PLZ}/metering-points")
        assert r.status_code == 403
        assert "no_valid_grant" in reasons_since(audit_log_path, start, "read_outage_segment")

        # [7] after expiry -> denied with grant_expired: pull the grant's
        # validity window into the past directly in the DB
        from gridvault.database import SessionFactory
        from gridvault.db import ApprovalRequest

        async with SessionFactory() as db:
            row = await db.get(ApprovalRequest, request_id)
            row.valid_until = row.valid_until - timedelta(days=365)
            await db.commit()

        r = await client.get(f"/outages/plz/{PLZ}/metering-points")
        assert r.status_code == 403
        assert "grant_expired" in reasons_since(audit_log_path, start, "read_outage_segment")


class TestFourEyes:
    async def test_stoerungsdienst_cannot_grant(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        request_id = await file_request(client)
        r = await client.post(f"/outages/approval-requests/{request_id}/grant")
        assert r.status_code == 403
        assert "role_not_allowed" in reasons_since(audit_log_path, start, "grant_outage_access")

    async def test_already_granted_request_cannot_be_granted_twice(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        request_id = await file_request(client)
        await logout(client)
        await login(client, LEITSTELLE)
        assert (await client.post(f"/outages/approval-requests/{request_id}/grant")).status_code == 200
        # second grant -> denied, the request is no longer open
        r = await client.post(f"/outages/approval-requests/{request_id}/grant")
        assert r.status_code == 403
        assert "request_not_open" in reasons_since(audit_log_path, start, "grant_outage_access")

    async def test_leitstelle_has_no_data_access(self, client):
        await login(client, LEITSTELLE)
        # the control centre itself cannot read the segment nor meter data
        assert (await client.get(f"/outages/plz/{PLZ}/metering-points")).status_code == 403
        assert (await client.get("/metering-points")).status_code == 403

    async def test_customer_cannot_request_or_read(self, client):
        await login(client, KUNDE)
        assert (await client.post("/outages/approval-requests", json=REQUEST)).status_code == 403
        assert (await client.get(f"/outages/plz/{PLZ}/metering-points")).status_code == 403


class TestSchemaValidation:
    async def test_short_reason_is_rejected_at_the_edge(self, client):
        await login(client, STOERUNG)
        bad = {"plz": PLZ, "ticket_number": TICKET, "reason": "zu kurz"}
        r = await client.post("/outages/approval-requests", json=bad)
        assert r.status_code == 422

    async def test_plz_must_be_five_digits(self, client):
        await login(client, STOERUNG)
        bad = {"plz": "12", "ticket_number": TICKET, "reason": REQUEST["reason"]}
        assert (await client.post("/outages/approval-requests", json=bad)).status_code == 422


class TestDataMinimizedAudit:
    async def test_reason_text_never_enters_the_audit_trail(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        request_id = await file_request(client)
        await logout(client)
        await login(client, LEITSTELLE)
        await client.post(f"/outages/approval-requests/{request_id}/grant")
        await logout(client)
        await login(client, STOERUNG)
        await client.get(f"/outages/plz/{PLZ}/metering-points")

        content = audit_log_path.read_text()
        # free text stays in the ticket system only (A4 + A8)
        assert "Spannungsabfall" not in content
        assert REASON not in content
        # but the ticket reference is recorded...
        ticket_refs = [
            e["object"]
            for e in entries(audit_log_path)[start:]
            if e["object"] == f"ticket:{TICKET}"
        ]
        assert ticket_refs, "ticket reference missing from audit trail"
        # ...for request AND grant:
        actions = {
            e["action"]
            for e in entries(audit_log_path)[start:]
            if e["object"] == f"ticket:{TICKET}"
        }
        assert {"request_outage_access", "grant_outage_access"} <= actions
