"""B4 protocol test T6 - audit trail tampering detection.

Console reproduction:

    uv run python test/t6_audit_kette.py

B4/T6: (a) delete a middle entry, (b) cut off the last entry, run the
verification tool after each manipulation.
Expected: (a) chain break with line number; (b) detection via the
anchor.

"""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import common

from gridvault.config import settings

MIN_ENTRIES = 10
BAD_LOGIN = {"username": "kunde_swn", "password": "falsches-passwort"}

_script = importlib.util.spec_from_file_location(
    "verify_audit", Path(__file__).resolve().parents[1] / "scripts" / "verify_audit.py"
)
verify_audit = importlib.util.module_from_spec(_script)
_script.loader.exec_module(verify_audit)


def log_path() -> Path:
    return Path(settings.audit_log_path)


def anchor_dir() -> Path:
    return Path(settings.audit_anchor_dir)


def lines() -> list[str]:
    return common.audit_lines()


def rewrite(new_lines: list[str]) -> None:
    # Attacker simulation: direct write access to the log file,
    # bypassing the append-only service.
    log_path().write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def run_tool() -> tuple[int, str]:
    """Run the standalone verification tool; its console output is the
    protocol evidence, so it prints here AND gets captured."""
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = verify_audit.main(
            ["--log", str(log_path()), "--anchor-dir", str(anchor_dir())]
        )
    output = buffer.getvalue()
    print(output, end="")
    return code, output


async def main() -> int:
    if not common.ensure_dataset():
        return 2
    p = common.Protocol("T6", "Audit-Trail: mittleren Eintrag löschen / Ende abschneiden")
    snapshot = common.audit_snapshot()

    # make sure the trail has enough entries for a MIDDLE deletion
    while len(lines()) < MIN_ENTRIES:
        async with common.make_client() as client:
            r = await client.post("/auth/login", json=BAD_LOGIN)
            assert r.status_code == 401
    p.check(f"mindestens {MIN_ENTRIES} Einträge im Audit-Trail", len(lines()) >= MIN_ENTRIES)




    # middle entry
    original = log_path().read_bytes()
    current = lines()
    middle = len(current) // 2
    deleted_seq = json.loads(current[middle])["seq"]

    p.step(
        1,
        "(a) mittleren Eintrag löschen",
        f"Zeile {middle + 1} (seq {deleted_seq}) entfernt -> Pruefwerkzeug:",
    )
    del current[middle]
    rewrite(current)
    code, out = run_tool()
    p.check("Pruefwerkzeug Exit-Code 1", code == 1, "1", str(code))
    p.check(f"Kettenbruch mit Zeilenangabe (Zeile {middle + 1})", f"CHAIN BREAK at line {middle + 1}" in out)
    print()

    p.step(2, "Eintrag zurueckspielen -> Pruefwerkzeug:")
    log_path().write_bytes(original)
    code, out = run_tool()
    p.check("Kette wieder intakt (Exit 0)", code == 0, "0", str(code))
    print()


    

    # Tail Cutoff
    original = log_path().read_bytes()
    current = lines()
    removed = json.loads(current[-1])

    p.step(3, "(b) letzten Eintrag abschneiden", f"seq {removed['seq']} entfernt -> Pruefwerkzeug:")
    rewrite(current[:-1])

    truncated = verify_audit.load_entries(log_path())
    p.check(
        "Hash-Kette allein erkennt (b) NICHT",
        verify_audit.verify_chain(truncated) == [],
        "keine Befunde ohne Anker",
        "Befunde vorhanden",
    )
    code, out = run_tool()
    p.check("Pruefwerkzeug Exit-Code 1", code == 1, "1", str(code))
    p.check("abschnittenes Ende nur über den ANKER erkannt", "TRUNCATED TAIL" in out)
    print()

    p.step(4, "Eintrag zurueckspielen -> Pruefwerkzeug:")
    log_path().write_bytes(original)
    code, out = run_tool()
    p.check("Kette wieder intakt (Exit 0)", code == 0, "0", str(code))
    print()


    print(f"\n")

    
    # Audit Trail
    entries = common.new_audit_entries(snapshot)
    common.print_audit("Audit-Eintraege dieses Tests", entries)

    return p.finish()





if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
