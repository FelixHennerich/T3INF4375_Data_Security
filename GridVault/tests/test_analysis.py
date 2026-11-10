import json

NETZANALYST = {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026"}
ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}

# SWN-001 (scale 1.0) + SWN-002 (1.3) + SWN-003 (0.7) share PLZ 71543;
# hour 07:00 base curve is 0.80 -> 0.80 * (1.0+1.3+0.7) = 2.4
PLZ_BIG = "71543"
PLZ_SMALL = "71560"  # only SWN-004
IMPORTANT_HOUR_7 = 2.4


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


class TestCohortHourlySum:
    async def test_cohort_sum_returned(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r = await client.get(f"/analysis/plz/{PLZ_BIG}/hourly-sum")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["n"] == 3
        assert body["k"] == 3
        assert len(body["hourly_sums"]) == 24
        hour_7 = next(h for h in body["hourly_sums"] if h["timestamp"] == "2026-10-01T07:00:00")
        assert hour_7["sum_kwh"] == IMPORTANT_HOUR_7
        # no names, no single values - only cohort sums
        raw = json.dumps(body)
        assert "Mustermann" not in raw
        assert "hourly_values" not in raw
        assert "authorized" in reasons_since(audit_log_path, start, "read_cohort_hourly_sum")

    async def test_small_cohort_rejected_with_n_and_k(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r = await client.get(f"/analysis/plz/{PLZ_SMALL}/hourly-sum")
        assert r.status_code == 403
        body = r.json()
        assert body["n"] == 1
        assert body["k"] == 3
        assert "cohort too small" in body["detail"].lower()
        assert "cohort_too_small" in reasons_since(audit_log_path, start, "read_cohort_hourly_sum")

    async def test_foreign_tenant_plz_is_never_a_cohort(self, client, audit_log_path):
        """The SWN analyst querying a postcode that only SWB covers gets
        n = 0 (own-tenant scoping) - small-cell rejection, but no
        information about the other utility's points."""
        await login(client, NETZANALYST)
        r = await client.get("/analysis/plz/71332/hourly-sum")
        assert r.status_code == 403
        assert r.json()["n"] == 0

    async def test_no_session_denied(self, client):
        r = await client.get(f"/analysis/plz/{PLZ_BIG}/hourly-sum")
        assert r.status_code == 401


class TestCohortExport:
    async def test_export_contains_only_pseudonyms_and_is_stable(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r1 = await client.post(f"/analysis/plz/{PLZ_BIG}/export")
        assert r1.status_code == 200, r1.text
        body1 = r1.json()
        assert body1["n"] == 3
        assert len(body1["pseudonymized_series"]) == 3
        for series_entry in body1["pseudonymized_series"]:
            assert len(series_entry["pseudonym"]) == 64  # HMAC-SHA256 hex
            assert len(series_entry["hourly_kwh"]) == 24
        raw = json.dumps(body1)
        # pseudonyms replace mp ids - no ids, never names
        assert "SWN-001" not in raw
        assert "Mustermann" not in raw
        # retention date is set (picked up by the M9 deletion run)
        assert body1["retention_until"]

        # second export -> identical pseudonyms (stable per tenant key)
        r2 = await client.post(f"/analysis/plz/{PLZ_BIG}/export")
        pseuds_2 = [s["pseudonym"] for s in r2.json()["pseudonymized_series"]]
        pseuds_1 = [s["pseudonym"] for s in body1["pseudonymized_series"]]
        assert pseuds_1 == pseuds_2
        assert len(set(pseuds_1)) == 3  # distinct per metering point
        assert "authorized" in reasons_since(audit_log_path, start, "export_cohort")

    async def test_export_persisted_as_analysis_export_row(self, client):
        from gridvault.database import SessionFactory
        from gridvault.db import AnalysisExport

        await login(client, NETZANALYST)
        r = await client.post(f"/analysis/plz/{PLZ_BIG}/export")
        export_id = r.json()["export_id"]

        async with SessionFactory() as db:
            row = await db.get(AnalysisExport, export_id)
            assert row is not None
            payload = json.loads(row.payload.decode("utf-8"))
            # persisted payload: pseudonyms only, no mp ids
            assert "SWN-001" not in row.payload.decode("utf-8")
            assert len(payload["pseudonymized_series"]) == 3
            assert row.retention_until is not None

    async def test_small_cohort_export_rejected(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r = await client.post(f"/analysis/plz/{PLZ_SMALL}/export")
        assert r.status_code == 403
        assert r.json()["n"] == 1
        assert "cohort_too_small" in reasons_since(audit_log_path, start, "export_cohort")


class TestT2cRoleEscalation:
    async def test_abrechnung_cannot_perform_analyst_action(self, client, audit_log_path):
        """B4/T2 part (c): Abrechnung attempting a Netzanalyst action is
        denied by the gateway's role/purpose binding and audited."""
        start = len(entries(audit_log_path))
        await login(client, ABRECHNUNG)
        r = await client.get(f"/analysis/plz/{PLZ_BIG}/hourly-sum")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        assert "role_not_allowed" in reasons_since(audit_log_path, start, "read_cohort_hourly_sum")

    async def test_abrechnung_cannot_export(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, ABRECHNUNG)
        r = await client.post(f"/analysis/plz/{PLZ_BIG}/export")
        assert r.status_code == 403
        assert "role_not_allowed" in reasons_since(audit_log_path, start, "export_cohort")
