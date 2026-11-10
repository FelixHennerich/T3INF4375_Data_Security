import json
from datetime import datetime, timedelta

from sqlalchemy import func, select, update

from gridvault.db import (
    AnalysisExport,
    DeletionRun,
    HourlyReading,
    MeteringPoint,
    Tenant,
)
from gridvault.services import crypto
from gridvault.services.keys import get_master_key

KUNDE = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}
ABRECHNUNG = {"username": "abrechnung_swn", "password": "Abrechnung-SWN-2026"}
NETZANALYST = {"username": "netzanalyst_swn", "password": "Netzanalyst-SWN-2026"}

ALL_DUE_DAYS = 30  # canonical readings (~40 days old) are all due
NONE_DUE_DAYS = 3650  # only explicitly aged marker rows are due

MARKER_TS = datetime(2016, 1, 1, 12, 0)  # aged far beyond every window
HOUR12 = datetime(2026, 10, 1, 12, 0)  # original canonical timestamp


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


class TestDeletionRun:
    async def test_dry_run_deletes_nothing(self, client):
        from gridvault.database import SessionFactory

        await login(client, ABRECHNUNG)
        async with SessionFactory() as db:
            before = await db.scalar(select(func.count(HourlyReading.id)))
        r = await client.post(
            "/admin/deletion-run",
            json={"retention_days": ALL_DUE_DAYS, "dry_run": True},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["dry_run"] is True
        assert body["readings_due"] == 96  # all four own-tenant MPs are due
        async with SessionFactory() as db:
            after = await db.scalar(select(func.count(HourlyReading.id)))
        assert after == before  # nothing was deleted

    async def test_deletes_only_due_readings_and_keeps_exceptions(
        self, client, audit_log_path
    ):
        """Two marker rows are aged into the past; one belongs to a
        justified exception. The run deletes exactly the due row, keeps
        the exception, records both traceably - and everything is
        restored afterwards for the rest of the suite."""
        start = len(entries(audit_log_path))
        from gridvault.database import SessionFactory

        async with SessionFactory() as db:
            # age SWN-002's 12:00 row (to be deleted) and SWN-003's 12:00
            # row (kept via exception)
            for mp_id in ("SWN-002", "SWN-003"):
                await db.execute(
                    update(HourlyReading)
                    .where(
                        HourlyReading.timestamp == HOUR12,
                        HourlyReading.metering_point_id
                        == select(MeteringPoint.id)
                        .where(MeteringPoint.mp_id == mp_id)
                        .scalar_subquery(),
                    )
                    .values(timestamp=MARKER_TS)
                )
            await db.commit()

        await login(client, ABRECHNUNG)
        r = await client.post(
            "/admin/deletion-run",
            json={
                "retention_days": NONE_DUE_DAYS,
                "exceptions": [{"mp_id": "SWN-003", "reason": "legal_dispute"}],
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["readings_deleted"] == 1  # only SWN-002's marker row
        assert body["deletion_run_id"]

        async with SessionFactory() as db:
            count_swn002 = await db.scalar(
                select(func.count(HourlyReading.id))
                .join(MeteringPoint, MeteringPoint.id == HourlyReading.metering_point_id)
                .where(MeteringPoint.mp_id == "SWN-002")
            )
            count_swn003 = await db.scalar(
                select(func.count(HourlyReading.id))
                .join(MeteringPoint, MeteringPoint.id == HourlyReading.metering_point_id)
                .where(MeteringPoint.mp_id == "SWN-003")
            )
            run_row = await db.get(DeletionRun, body["deletion_run_id"])
        assert count_swn002 == 23  # marker row deleted
        assert count_swn003 == 24  # exception survived
        assert run_row.loads_deleted == 1
        assert run_row.retention_exceptions == "SWN-003:legal_dispute"
        assert "retention_over" in reasons_since(audit_log_path, start, "deletion_run")

        # --- restore: exception row back to its original timestamp, and
        # the deleted marker row re-inserted with a correctly encrypted
        # value (curve hour 12, scale 1.3 -> "1.235")
        async with SessionFactory() as db:
            await db.execute(
                update(HourlyReading)
                .where(
                    HourlyReading.timestamp == MARKER_TS,
                    HourlyReading.metering_point_id
                    == select(MeteringPoint.id)
                    .where(MeteringPoint.mp_id == "SWN-003")
                    .scalar_subquery(),
                )
                .values(timestamp=HOUR12)
            )
            mp2 = await db.scalar(
                select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-002")
            )
            data_key = crypto.unwrap_data_key(
                get_master_key("SWN"), mp2.enc_data_key, "SWN:SWN-002"
            )
            context = crypto.build_context("SWN", "SWN-002", HOUR12)
            db.add(
                HourlyReading(
                    metering_point_id=mp2.id,
                    timestamp=HOUR12,
                    enc_value=crypto.encrypt("1.235", data_key, context),
                )
            )
            await db.commit()

        # the restored domain is fully readable again
        await logout(client)
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-002")
        assert r.status_code == 403  # not the kunde's meter - but valid denial
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 200 and len(r.json()["hourly_values"]) == 24

    async def test_exports_past_retention_deleted(self, client):
        from gridvault.database import SessionFactory

        async with SessionFactory() as db:
            swn = await db.scalar(select(Tenant).where(Tenant.code == "SWN"))
            now = datetime.now()
            db.add_all(
                [
                    AnalysisExport(
                        tenant_id=swn.id, plz="71543", created_by_user_id=2,
                        created_at=now - timedelta(days=200),
                        retention_until=now - timedelta(days=110),
                        payload=b"{}",
                    ),
                    AnalysisExport(
                        tenant_id=swn.id, plz="71543", created_by_user_id=2,
                        created_at=now, retention_until=now + timedelta(days=90),
                        payload=b"{}",
                    ),
                ]
            )
            await db.commit()

        await login(client, ABRECHNUNG)
        r = await client.post("/admin/deletion-run", json={"retention_days": NONE_DUE_DAYS})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["readings_deleted"] == 0  # window spares the readings
        assert body["exports_deleted"] == 1  # but the expired export is gone

        async with SessionFactory() as db:
            now = datetime.now()
            overdue = await db.scalar(
                select(func.count(AnalysisExport.id)).where(
                    AnalysisExport.retention_until <= now
                )
            )
        assert overdue == 0  # nothing past its retention date remains

    async def test_roles_restricted(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        assert (
            await client.post("/admin/deletion-run", json={"retention_days": 30})
        ).status_code == 401
        await login(client, NETZANALYST)
        assert (
            await client.post("/admin/deletion-run", json={"retention_days": 30})
        ).status_code == 403
        assert "role_not_allowed" in reasons_since(audit_log_path, start, "deletion_run")


class TestCryptoShredding:
    async def test_ciphertext_rows_remain_but_become_unreadable(
        self, client, audit_log_path
    ):
        start = len(entries(audit_log_path))
        from gridvault.database import SessionFactory

        # keep the original key material so this test can restore it
        async with SessionFactory() as db:
            mp = await db.scalar(
                select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
            )
            original_key = mp.enc_data_key

        await login(client, KUNDE)
        r = await client.delete("/admin/metering-points/SWN-001/data-key")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["data_key_destroyed"] is True
        assert body["ciphertext_rows_remaining"] == 24  # ciphertext stays
        assert body["readable"] is False
        assert "deletion_request" in reasons_since(
            audit_log_path, start, "delete_customer_data"
        )

        # every read now fails - the values are unreadable, not "gone"
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 409
        assert "SWN-001" in r.json()["detail"]
        await logout(client)
        await login(client, ABRECHNUNG)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 409

        # restore the key material so later tests can read SWN-001 again
        async with SessionFactory() as db:
            mp = await db.scalar(
                select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
            )
            mp.enc_data_key = original_key
            await db.commit()

    async def test_kunde_cannot_destroy_foreign_key(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, KUNDE)
        r = await client.delete("/admin/metering-points/SWN-002/data-key")
        assert r.status_code == 403
        assert "not_own_meter" in reasons_since(
            audit_log_path, start, "delete_customer_data"
        )


class TestDataMinimizedDeletionAudit:
    async def test_audit_contains_events_but_no_content(self, client, audit_log_path):
        start = len(entries(audit_log_path))
        await login(client, ABRECHNUNG)
        r = await client.post("/admin/deletion-run", json={"retention_days": NONE_DUE_DAYS})
        assert r.status_code == 200

        deletion_entries = [
            e for e in entries(audit_log_path)[start:] if e["action"] == "deletion_run"
        ]
        assert deletion_entries, "deletion run not audited"
        line = json.dumps(deletion_entries[0])
        # no values, no names, no counts in the audit entry (A8)
        for needle in ("0.45", "Mustermann", "Backnang", "readings_deleted"):
            assert needle not in line
        # the minimized object reference carries only the run identity
        assert deletion_entries[0]["object"].startswith("deletion_run:")


class TestBackupRestoreSemantics:
    async def test_restored_ciphertext_without_key_stays_unreadable(self, client):
        """Core of the A2 bonus: a backup copy containing the ciphertext
        rows is restored AFTER the data key was destroyed - the rows
        exist again physically, but nobody can decrypt them."""
        from gridvault.database import SessionFactory

        # save the ciphertext rows + key material (the "backup copy")
        async with SessionFactory() as db:
            mp = await db.scalar(
                select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
            )
            original_key = mp.enc_data_key
            saved_rows = [
                (r.timestamp, r.enc_value)
                for r in (
                    await db.execute(
                        select(HourlyReading).where(HourlyReading.metering_point_id == mp.id)
                    )
                ).scalars().all()
            ]
            for row in (
                await db.execute(
                    select(HourlyReading).where(HourlyReading.metering_point_id == mp.id)
                )
            ).scalars():
                await db.delete(row)
            await db.commit()

        # deletion request: destroy the key of SWN-001
        await login(client, KUNDE)
        r = await client.delete("/admin/metering-points/SWN-001/data-key")
        assert r.status_code == 200

        # "backup restore": the pulled copy brings the ciphertext rows back
        async with SessionFactory() as db:
            mp = await db.scalar(
                select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
            )
            for ts, enc in saved_rows:
                db.add(
                    HourlyReading(
                        metering_point_id=mp.id, timestamp=ts, enc_value=enc
                    )
                )
            await db.commit()

        # the rows exist again - yet they are worthless without the key
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 409
        assert "SWN-001" in r.json()["detail"]

        # cleanup for the rest of the suite: restore the key material
        async with SessionFactory() as db:
            mp = await db.scalar(
                select(MeteringPoint).where(MeteringPoint.mp_id == "SWN-001")
            )
            mp.enc_data_key = original_key
            await db.commit()
        await logout(client)
        await login(client, KUNDE)
        r = await client.get("/metering-points/SWN-001")
        assert r.status_code == 200
        assert len(r.json()["hourly_values"]) == 24
