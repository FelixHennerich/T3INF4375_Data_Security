import json

KUNDE = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}
ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}
NETZANALYST = {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026"}


async def login(client, credentials: dict) -> None:
    r = await client.post("/auth/login", json=credentials)
    assert r.status_code == 200, r.text


def entries(audit_log_path) -> list[dict]:
    if not audit_log_path.exists():
        return []
    return [json.loads(line) for line in audit_log_path.read_text().splitlines()]


def reasons_since(audit_log_path, start: int, action: str) -> set[str]:
    return {
        e["reason"] for e in entries(audit_log_path)[start:] if e["action"] == action
    }


class TestListMeteringPoints:
    async def test_kunde_lists_only_own_metering_point(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.get("/metering-points")
        assert r.status_code == 200
        body = r.json()
        assert [mp["mp_id"] for mp in body] == ["SWN-001"]
        # cleartext fields only - a directory never decrypts names
        assert set(body[0]) == {"mp_id", "tenant", "plz", "tariff"}
        assert "name" not in body[0]
        assert "authorized" in reasons_since(audit_log_path, start, "list_metering_points")

    async def test_abrechnung_lists_all_own_tenant_points(self, client):
        await login(client, ABRECHNUNG)
        r = await client.get("/metering-points")
        assert r.status_code == 200
        assert [mp["mp_id"] for mp in r.json()] == ["SWN-001", "SWN-002", "SWN-003", "SWN-004"]
        assert all(mp["tenant"] == "SWN" for mp in r.json())

    async def test_netzanalyst_has_no_listing(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r = await client.get("/metering-points")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        assert "role_not_allowed" in reasons_since(audit_log_path, start, "list_metering_points")

    async def test_without_session_denied(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        r = await client.get("/metering-points")
        assert r.status_code == 401
        assert "session_invalid" in reasons_since(audit_log_path, start, "list_metering_points")


class TestReadingsRoute:
    async def test_kunde_reads_own_hourly_values(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-001/readings")
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 24
        assert body[0] == {"timestamp": "2026-10-01T00:00:00", "kwh": 0.3}
        assert body[7]["kwh"] == 0.8
        assert "authorized" in reasons_since(audit_log_path, start, "read_metering_readings")

    async def test_kunde_cannot_read_foreign_meter_readings(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-002/readings")
        assert r.status_code == 403
        assert "not_own_meter" in reasons_since(audit_log_path, start, "read_metering_readings")

    async def test_abrechnung_is_denied_single_values(self, client, audit_log_path):
        """A7/A3 purpose binding: Abrechnung never sees individual hourly
        values - only the sum computed inside the gateway."""
        start = len(entries(audit_log_path))
        await login(client, ABRECHNUNG)
        r = await client.get("/metering-points/SWN-001/readings")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        assert "role_not_allowed" in reasons_since(audit_log_path, start, "read_metering_readings")

    async def test_abrechnung_reads_own_tenant_sum_not_swapped_denials(
        self, client
    ):
        await login(client, ABRECHNUNG)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 200
        body = r.json()
        assert body["consumption_sum_kwh"] > 0
        assert body["lastprofil"] == "[NICHT FREIGEGEBEN]"
