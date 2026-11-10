import json
from pathlib import Path

from sqlalchemy import update

GOOD = {"username": "kunde_swn", "password": "Kunde-SWN-2026"}
WRONG_PW = {"username": "kunde_swn", "password": "nope"}
UNKNOWN = {"username": "does_not_exist", "password": "nope"}


def audit_entries(audit_log_path: Path) -> list[dict]:
    if not audit_log_path.exists():
        return []
    return [json.loads(line) for line in audit_log_path.read_text().splitlines()]




class TestLoginT1:
    async def test_wrong_password_rejected_generically(self, client, audit_log_path):
        r_wrong = await client.post("/auth/login", json=WRONG_PW)
        r_unknown = await client.post("/auth/login", json=UNKNOWN)
        assert r_wrong.status_code == 401
        assert r_unknown.status_code == 401
        # identical response - no hint whether the user exists (A1)
        assert r_wrong.json() == r_unknown.json()
        assert r_wrong.text == r_unknown.text
        # no session cookie on failure
        assert "set-cookie" not in {k.lower() for k in r_wrong.headers}

    async def test_correct_login_returns_session_with_role_and_tenant(
        self, client, audit_log_path
    ):
        r = await client.post("/auth/login", json=GOOD)
        assert r.status_code == 200
        body = r.json()
        assert body["username"] == "kunde_swn"
        assert body["tenant"] == "SWN"
        assert body["role"] == "kunde"
        assert body["expires_at"]

        cookie = r.headers["set-cookie"]
        assert "gridvault_session=" in cookie
        assert "httponly" in cookie.lower()  # session as HttpOnly cookie (A1)
        assert "samesite=lax" in cookie.lower()

    async def test_both_login_events_are_audited(self, client, audit_log_path):
        await client.post("/auth/login", json=WRONG_PW)
        await client.post("/auth/login", json=GOOD)
        logins = [e for e in audit_entries(audit_log_path) if e["action"] == "login"]
        results = {e["result"] for e in logins}
        assert "denied" in results
        assert "success" in results
        # the true denial reason lives ONLY in the audit trail (A5)
        assert any(e["reason"] == "password_wrong" for e in logins)
        assert any(e["reason"] == "credentials_ok" for e in logins)
        # data minimization: no plaintext password anywhere in the log
        content = audit_log_path.read_text()
        assert "Kunde-SWN-2026" not in content
        # and no names - only pseudonyms
        assert "kunde_swn" not in content


class TestSessionUse:
    async def test_whoami_roundtrip(self, client, audit_log_path):
        await client.post("/auth/login", json=GOOD)
        r = await client.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["tenant"] == "SWN"
        assert r.json()["role"] == "kunde"

    async def test_whoami_without_session_denied(self, client, audit_log_path):
        r = await client.get("/auth/me")
        assert r.status_code == 401

    async def test_logout_invalidates_session(self, client, audit_log_path):
        await client.post("/auth/login", json=GOOD)
        assert (await client.post("/auth/logout")).status_code == 200
        # cookie was told to expire and the server row is gone
        assert (await client.get("/auth/me")).status_code == 401

    async def test_expired_session_denied(self, client, audit_log_path, monkeypatch):
        from gridvault.config import settings

        monkeypatch.setattr(settings, "session_ttl_minutes", 0)
        await client.post("/auth/login", json=GOOD)
        assert (await client.get("/auth/me")).status_code == 401
        reasons = {
            e["reason"] for e in audit_entries(audit_log_path) if e["action"] == "whoami"
        }
        assert "session_expired" in reasons

    async def test_unknown_cookie_is_rejected(self, client, audit_log_path):
        await client.post("/auth/login", json=GOOD)
        client.cookies.set("gridvault_session", "forged-token")
        assert (await client.get("/auth/me")).status_code == 401

    async def test_deactivated_user_session_dies(self, client, audit_log_path):
        await client.post("/auth/login", json=GOOD)
        # flip is_active directly in the DB (permission removal, A7)
        from gridvault.database import SessionFactory
        from gridvault.db import User

        async with SessionFactory() as db:
            await db.execute(
                update(User).where(User.username == "kunde_swn").values(is_active=False)
            )
            await db.commit()
        assert (await client.get("/auth/me")).status_code == 401
        # reactivation for other tests
        async with SessionFactory() as db:
            await db.execute(
                update(User).where(User.username == "kunde_swn").values(is_active=True)
            )
            await db.commit()
        assert (await client.post("/auth/login", json=GOOD)).status_code == 200


class TestAuditStaysIntact:
    async def test_audit_chain_verifies_after_logins(self, client, audit_log_path):
        import importlib.util
        from pathlib import Path

        await client.post("/auth/login", json=WRONG_PW)
        await client.post("/auth/login", json=GOOD)
        await client.get("/auth/me")
        await client.post("/auth/logout")

        spec = importlib.util.spec_from_file_location(
            "verify_audit",
            Path(__file__).resolve().parents[1] / "scripts" / "verify_audit.py",
        )
        verify_audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify_audit)

        findings = verify_audit.verify(
            audit_log_path,
            audit_log_path.parent / "audit_anchor" / "audit_anchor.json",
        )
        assert findings == []
