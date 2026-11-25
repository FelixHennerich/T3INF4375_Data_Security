import json
from pathlib import Path

from gridvault.config import settings


class Protocol:
    """Collects the checks of one B4 test and prints the summary."""

    def __init__(self, test_id: str, title: str) -> None:
        self.test_id = test_id
        self.title = title
        self.checks = 0
        self.failures = 0
        print(f"B4/{test_id} - {title}")
        print("=" * len(f"B4/{test_id} - {title}"))
        print()

    def step(self, number: int, text: str, result: str | None = None) -> None:
        line = f"[{number}] {text}"
        if result is not None:
            line += f"  ->  {result}"
        print(line)

    def check(self, label: str, ok: bool, expected: str = "", actual: str = "") -> None:
        self.checks += 1
        if ok:
            print(f"    ok   {label}")
        else:
            self.failures += 1
            print(f"    FAIL {label}")
            if expected:
                print(f"         erwartet: {expected}")
            if actual:
                print(f"         erhalten:  {actual}")

    def finish(self) -> int:
        print()
        if self.failures:
            print(f"ERGEBNIS: B4/{self.test_id} FEHLGESCHLAGEN")
            print(f"          {self.failures} von {self.checks} Pruefungen nicht erfuellt")
            return 1
        print(f"ERGEBNIS: B4/{self.test_id} bestanden ({self.checks}/{self.checks} Pruefungen)")
        return 0


def make_client():
    """In-process HTTP client against the app (no server needed)."""
    from httpx import ASGITransport, AsyncClient

    from gridvault.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://b4")


def ensure_dataset() -> bool:
    """Abort with a hint if the database does not exist yet."""
    db_path = settings.database_url.split("///")[-1]
    if not Path(db_path).exists():
        print(f"[abort] Datenbank nicht gefunden: {db_path}")
        print("        Zuerst Testdaten erzeugen:")
        print("        uv run python scripts/generate_testdata.py")
        return False
    return True


async def login(protocol: Protocol, client, credentials: dict, expected: int = 200):
    r = await client.post("/auth/login", json=credentials)
    protocol.check(
        f"Login {credentials['username']} -> HTTP {expected}",
        r.status_code == expected,
        str(expected),
        f"HTTP {r.status_code} {r.text}",
    )
    return r


async def logout(client) -> None:
    await client.post("/auth/logout")


def audit_lines() -> list[str]:
    path = Path(settings.audit_log_path)
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def audit_snapshot() -> int:
    """Number of entries - a marker for 'entries appended after this'."""
    return len(audit_lines())


def new_audit_entries(since: int) -> list[dict]:
    """Parse the audit entries appended after snapshot `since`."""
    return [json.loads(line) for line in audit_lines()[since:]]


def print_audit(header: str, entries: list[dict]) -> None:
    """Print entries as the protocol evidence (data-minimized per line)."""
    print(f"{header} ({settings.audit_log_path}):")
    if not entries:
        print("  (keine neuen Eintraege)")
    for e in entries:
        print(
            f"  seq={e['seq']} ts={e['timestamp']} tenant={e['tenant']} "
            f"user={e['user']} role={e['role']} action={e['action']} "
            f"object={e['object']} result={e['result']} reason={e['reason']}"
        )
    print()
