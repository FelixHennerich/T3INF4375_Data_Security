"""Standalone audit-trail verification tool (A5, test T6).

Runs WITHOUT a login session - verification itself must not touch the
application. Pure stdlib, no app imports, no database access.

What it checks and how it distinguishes tampering:

1. Per-entry integrity: recompute each entry's SHA-256 over the canonical
   JSON of its fields. A mismatch means the entry was MODIFIED after it
   was written (reported with its line number).
2. Chain linkage: entry.seq must increment by 1 and entry.prev_hash must
   equal the previous entry's hash. A break means an entry was DELETED
   (or reordered); reported with the line where the break appears and the
   sequence number that is missing.
3. Tail vs anchor: the anchor file (in a directory separate from the log,
   standing in for WORM storage) holds the sequence number and hash of
   the last entry at the time it was written. If the log's last hash does
   not match the anchor, the log was truncated or its last entry was
   modified after the anchor write.
   Why the hash chain alone cannot detect a cut tail (B4/T6 reasoning):
   an attacker who truncates the log removes the evidence with it - all
   remaining entries still form a perfectly valid chain. Only the
   comparison against the external anchor exposes the missing tail.

Exit codes: 0 = chain and anchor intact, 1 = tampering detected,
2 = files unreadable/missing.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

GENESIS_HASH = "0" * 64

REQUIRED_FIELDS = (
    "seq",
    "timestamp",
    "tenant",
    "user",
    "role",
    "action",
    "object",
    "result",
    "reason",
    "prev_hash",
    "hash",
)


def entry_hash(entry: dict) -> str:
    # Internal helpers (e.g. "_line") are excluded alongside "hash" so the
    # recomputation matches the service-side canonical form exactly.
    payload = {
        k: v
        for k, v in entry.items()
        if k != "hash" and not k.startswith("_")
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_entries(log_path: Path) -> list[dict]:
    entries: list[dict] = []
    with open(log_path, encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_number}: not valid JSON") from exc
            missing = [field for field in REQUIRED_FIELDS if field not in entry]
            if missing:
                raise ValueError(
                    f"line {line_number}: missing mandatory fields {missing}"
                )
            entry["_line"] = line_number
            entries.append(entry)
    return entries


def verify_chain(entries: list[dict]) -> list[str]:
    """Detect modified entries and broken chain links (cases a)."""
    findings: list[str] = []
    prev_hash = GENESIS_HASH
    prev_seq = 0
    for entry in entries:
        line = entry["_line"]
        if entry["prev_hash"] != prev_hash:
            findings.append(
                f"CHAIN BREAK at line {line}: prev_hash does not match the hash of "
                f"the previous entry - entry with seq {prev_seq + 1} was deleted "
                f"or reordered before this line"
            )
        if entry["seq"] != prev_seq + 1:
            findings.append(
                f"SEQUENCE GAP at line {line}: expected seq {prev_seq + 1}, "
                f"got {entry['seq']} - an entry was deleted or reordered"
            )
        recomputed = entry_hash(entry)
        if recomputed != entry["hash"]:
            findings.append(
                f"MODIFIED ENTRY at line {line} (seq {entry['seq']}): "
                f"stored hash does not match recomputed content"
            )
        prev_hash = entry["hash"]
        prev_seq = entry["seq"]
    return findings


def verify_against_anchor(entries: list[dict], anchor_path: Path) -> list[str]:
    """Detect a truncated tail or a modified last entry (case b)."""
    findings: list[str] = []
    if not anchor_path.is_file():
        if entries:
            findings.append(
                "MISSING ANCHOR: entries exist but the anchor file does not - "
                "the anchor was deleted or never written"
            )
        return findings

    try:
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError("anchor file is unreadable") from exc

    if not entries:
        findings.append(
            f"TRUNCATED LOG: no entries left, but the anchor records seq "
            f"{anchor.get('seq')} - the entire trail was removed"
        )
        return findings

    last = entries[-1]
    if anchor.get("hash") != last["hash"]:
        if anchor.get("seq", 0) > last["seq"]:
            missing = anchor["seq"] - last["seq"]
            findings.append(
                f"TRUNCATED TAIL detected via anchor: log ends at seq "
                f"{last['seq']} (line {last['_line']}), but the anchor records "
                f"seq {anchor['seq']} - {missing} trailing entr"
                f"{'ies were' if missing > 1 else 'y was'} cut off. The chain "
                f"alone cannot show this: the removed entries took their "
                f"evidence with them; only the external anchor exposes it."
            )
        else:
            findings.append(
                f"LAST ENTRY MODIFIED after the anchor write: line "
                f"{last['_line']} (seq {last['seq']}) does not match the "
                f"hash in the anchor"
            )
    return findings


def verify(log_path: Path, anchor_path: Path) -> list[str]:
    entries = load_entries(log_path)
    findings = verify_chain(entries)
    findings.extend(verify_against_anchor(entries, anchor_path))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the GridVault audit trail")
    parser.add_argument("--log", default="audit_trail.log", help="path to audit_trail.log")
    parser.add_argument(
        "--anchor-dir", default="audit_anchor", help="directory holding the anchor file"
    )
    args = parser.parse_args(argv)

    log_path = Path(args.log)
    anchor_path = Path(args.anchor_dir) / "audit_anchor.json"

    if not log_path.is_file():
        if not anchor_path.is_file():
            print("OK: no audit log and no anchor (nothing logged yet)")
            return 0
        print("TAMPERING: anchor exists but the audit log is missing")
        return 1

    try:
        findings = verify(log_path, anchor_path)
    except ValueError as exc:
        print(f"UNREADABLE: {exc}")
        return 2

    if findings:
        print("TAMPERING DETECTED:")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    with open(log_path, encoding="utf-8") as log_file:
        entry_count = sum(1 for line in log_file if line.strip())
    print(f"OK: chain intact, anchor matches ({entry_count} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
