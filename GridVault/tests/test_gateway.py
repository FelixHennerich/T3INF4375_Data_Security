import json
from datetime import datetime

import pytest
from sqlalchemy import select, update

from gridvault.db import HourlyReading, MeteringPoint

KUNDE = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}
ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}
NETZANALYST = {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026"}
KUNDE_SWB = {"username": "kunde_swb", "password": "Kunde-SWB-2026"}

EXPECTED_SUM_SWN001 = 18.17  # base curve sum (scale 1.0), see generator


async def login(client, credentials: dict) -> None:
    r = await client.post("/auth/login", json=credentials)
    assert r.status_code == 200, r.text


def entries(audit_log_path) -> list[dict]:
    if not audit_log_path.exists():
        return []
    return [json.loads(line) for line in audit_log_path.read_text().splitlines()]


def reasons_since(audit_log_path, start: int, action: str = "read_metering_point") -> set[str]:
    """Reasons of entries appended after snapshot `start` (len before)."""
    return {
        e["reason"] for e in entries(audit_log_path)[start:] if e["action"] == action
    }


class TestProbeSuccess:
    async def test_kunde_reads_own_metering_point(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 200, r.text
        body = r.json()
        # decrypted, correct plaintext
        assert body["name"] == "Erika Mustermann"
        assert "Backnang" in body["address"]
        assert body["tenant"] == "SWN"
        assert body["tariff"] == "Haushaltsstrom"
        # full day of hourly values in cleartext
        assert len(body["hourly_values"]) == 24
        assert body["hourly_values"][0]["timestamp"] == "2026-10-01T00:00:00"
        assert body["hourly_values"][7]["kwh"] == pytest.approx(0.80)
        # and the successful read is audited
        assert "authorized" in reasons_since(audit_log_path, start)

    async def test_abrechnung_gets_sum_not_single_values(self, client, audit_log_path):
        await login(client, ABRECHNUNG)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["name"] == "Erika Mustermann"
        assert body["consumption_sum_kwh"] == pytest.approx(EXPECTED_SUM_SWN001)
        assert body["amount_eur"] == pytest.approx(
            round(EXPECTED_SUM_SWN001 * 0.35, 2), abs=0.005
        )
        assert body["lastprofil"] == "[NICHT FREIGEGEBEN]"
        # single values never leave the gateway
        assert "hourly_values" not in body
        raw = json.dumps(body)
        assert "0.8" not in raw  # no individual hourly value in the payload

    async def test_kunde_swb_reads_own_metering_point(self, client):
        await login(client, KUNDE_SWB)
        r = await client.get("/metering-points/SWB-001")
        assert r.status_code == 200
        assert r.json()["tenant"] == "SWB"


class TestDenials:
    async def test_no_session_denied(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 401
        assert r.json() == {"detail": "Access denied"}
        assert "session_invalid" in reasons_since(audit_log_path, start)

    async def test_expired_session_denied(self, client, audit_log_path, monkeypatch):
        start = len(entries(audit_log_path))
        from gridvault.config import settings

        monkeypatch.setattr(settings, "session_ttl_minutes", 0)
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 401
        assert "session_expired" in reasons_since(audit_log_path, start)

    async def test_role_purpose_binding_denied_for_netzanalyst(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        await login(client, NETZANALYST)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        assert "role_not_allowed" in reasons_since(audit_log_path, start)

    async def test_tenant_mismatch_denied(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, ABRECHNUNG)
        r = await client.get("/metering-points/SWB-001")
        assert r.status_code == 403
        assert r.json() == {"detail": "Access denied"}
        assert "tenant_mismatch" in reasons_since(audit_log_path, start)

    async def test_kunde_cannot_read_foreign_meter(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-002")
        assert r.status_code == 403
        assert "not_own_meter" in reasons_since(audit_log_path, start)

    async def test_unknown_object_denied(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.get("/metering-points/DE-DOES-NOT-EXIST")
        assert r.status_code == 403
        assert "object_not_found" in reasons_since(audit_log_path, start)

    async def test_all_denials_share_one_generic_client_message(self, client):
        # role denial
        await login(client, NETZANALYST)
        body_role = (await client.get("/metering-points/SWN-001")).json()
        # object reference denial
        await client.post("/auth/logout")
        await login(client, KUNDE)
        body_object = (await client.get("/metering-points/SWN-002")).json()
        # tenant denial
        await client.post("/auth/logout")
        await login(client, ABRECHNUNG)
        body_tenant = (await client.get("/metering-points/SWB-001")).json()
        assert body_role == body_object == body_tenant == {"detail": "Access denied"}


class TestCheckOrder:
    """Prove the mandated order via the audited reasons (A3)."""

    async def test_role_is_checked_before_tenant(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        # a Netzanalyst probing a FOREIGN tenant MP fails on role, not tenant
        await login(client, NETZANALYST)
        await client.get("/metering-points/SWB-001")
        since = reasons_since(audit_log_path, start)
        assert "role_not_allowed" in since
        assert "tenant_mismatch" not in since

    async def test_tenant_is_checked_before_object_reference(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        # Abrechnung SWN on a foreign MP fails on tenant, never on the
        # object reference
        await login(client, ABRECHNUNG)
        await client.get("/metering-points/SWB-001")
        since = reasons_since(audit_log_path, start)
        assert "tenant_mismatch" in since
        assert "not_own_meter" not in since


class TestIntegrityViolation:
    async def test_swapped_ciphertext_detected_named_and_audited(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)

        # attacker with DB write access swaps two valid ciphertexts
        from gridvault.database import SessionFactory

        async with SessionFactory() as db:
            rows = (
                (
                    await db.execute(
                        select(HourlyReading)
                        .join(MeteringPoint, MeteringPoint.id == HourlyReading.metering_point_id)
                        .where(MeteringPoint.mp_id == "SWN-001")
                        .where(
                            HourlyReading.timestamp.in_(
                                [datetime(2026, 10, 1, 7, 0), datetime(2026, 10, 1, 8, 0)]
                            )
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 2
            rows[0].enc_value, rows[1].enc_value = rows[1].enc_value, rows[0].enc_value
            await db.commit()

        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 409
        detail = r.json()["detail"]
        # integrity violation names metering point and timestamp (T5)
        assert "SWN-001" in detail
        assert "2026-10-01T07:00:00" in detail
        # and it is audited with the failing row identified
        integrity = [
            e
            for e in entries(audit_log_path)[start:]
            if e["reason"] == "integrity_violation"
        ]
        assert integrity, "integrity violation not audited"
        assert integrity[0]["object"] == "mp:SWN-001:2026-10-01T07:00:00"

    async def test_tampered_ciphertext_detected(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        from gridvault.database import SessionFactory

        async with SessionFactory() as db:
            reading = (
                (
                    await db.execute(
                        select(HourlyReading)
                        .join(MeteringPoint, MeteringPoint.id == HourlyReading.metering_point_id)
                        .where(MeteringPoint.mp_id == "SWN-001")
                        .order_by(HourlyReading.timestamp)
                    )
                )
                .scalars()
                .first()
            )
            blob = bytearray(reading.enc_value)
            blob[-1] ^= 0x01
            await db.execute(
                update(HourlyReading)
                .where(HourlyReading.id == reading.id)
                .values(enc_value=bytes(blob))
            )
            await db.commit()

        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 409
        assert "SWN-001" in r.json()["detail"]
        assert "integrity_violation" in reasons_since(audit_log_path, start)
