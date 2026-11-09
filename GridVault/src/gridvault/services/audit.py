"""Audit trail as a hash chain with an external anchor (A5).

Design decisions behind this module (documented for B1):

- Every action (login success/failure, every read, every denial, integrity
  violations, grants, deletions) produces exactly one entry in
  `audit_trail.log`. The file is ONLY ever opened in append mode - the
  application has no code path that rewrites or truncates it.
- Chain: each entry stores the hash of its predecessor and its own hash,
  computed over the canonical JSON of all other fields. The first entry
  chains to 64 zeros. Any modified or deleted entry therefore breaks the
  chain.
- Anchor: after appending an entry, the last sequence number and hash are
  mirrored into an anchor file in a SEPARATE directory. It stands in for
  WORM/Object-Lock storage an application administrator cannot control:
  an attacker who truncates the log (removing the evidence) cannot update
  the anchor - the mismatch exposes the truncation. The hash chain alone
  cannot detect a cut tail (T6b): all remaining entries still verify.

Data minimization (A8, by construction):
- Entries contain pseudonymous user identifiers (user_pseudonym), role,
  result and REASON CODES - never names, never cleartext load profiles,
  never free-text justifications. A free-text `reason` is rejected here so
  free text cannot leak into the log through a later caller.
"""

import hashlib
import json
import os
import re
import threading
from datetime import UTC, datetime
from pathlib import Path

from gridvault.config import settings

GENESIS_HASH = "0" * 64

# Field validations: codes only, no free text (A8).
_RE_TENANT = re.compile(r"^[A-Za-z0-9_-]{1,10}$")
_RE_PSEUDONYM = re.compile(r"^u\d+$")
_RE_ROLE = re.compile(r"^[a-z0-9_]{1,20}$")
_RE_RESULT = re.compile(r"^[a-z0-9_]{1,30}$")
_RE_CODE = re.compile(r"^[a-z0-9_]{1,40}$")
# Minimized object reference, e.g. "mp:DE0000000001", "plz:71543".
_RE_OBJECT = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")


class AuditError(Exception):
    """Raised when an audit entry cannot be written or the chain is broken."""


def user_pseudonym(user_id: int) -> str:
    """Stable pseudonymous identifier for audit entries (no names)."""
    return f"u{user_id}"


def entry_hash(entry: dict) -> str:
    """SHA-256 over the canonical JSON of all fields except "hash"."""
    payload = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditTrail:
    """Append-only audit log with hash chain and external anchor."""

    def __init__(self, log_path: Path | str, anchor_dir: Path | str) -> None:
        self.log_path = Path(log_path)
        self.anchor_path = Path(anchor_dir) / "audit_anchor.json"
        self._lock = threading.Lock()

    def log_action(
        self,
        *,
        tenant: str,
        user: str,
        role: str,
        action: str,
        object_ref: str,
        result: str,
        reason: str,
    ) -> dict:
        """Append one entry and mirror the last hash into the anchor file.

        `user` must be a pseudonym (user_pseudonym), never a name.
        `reason` must be a snake_case code - free text is rejected so
        justifications (e.g. outage ticket texts) never reach the log.
        """
        self._validate(tenant, user, role, action, object_ref, result, reason)

        with self._lock:
            seq, prev_hash = self._tail_state()
            entry = {
                "seq": seq + 1,
                "timestamp": datetime.now(UTC).isoformat(
                    timespec="seconds"
                ),
                "tenant": tenant,
                "user": user,
                "role": role,
                "action": action,
                "object": object_ref,
                "result": result,
                "reason": reason,
                "prev_hash": prev_hash,
            }
            entry["hash"] = entry_hash(entry)

            # The log is only ever opened with mode "a" (append-only, A5).
            with open(self.log_path, "a", encoding="utf-8") as log_file:
                log_file.write(
                    json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
                )
                log_file.flush()
                os.fsync(log_file.fileno())

            self._write_anchor(entry["seq"], entry["hash"])
            return entry

    def _tail_state(self) -> tuple[int, str]:
        """(seq, hash) of the last entry; genesis state for an empty log."""
        if not self.log_path.exists():
            return 0, GENESIS_HASH
        last_line = self._read_last_line()
        if not last_line:
            return 0, GENESIS_HASH
        try:
            entry = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AuditError("audit log tail is not valid JSON") from exc
        try:
            return int(entry["seq"]), entry["hash"]
        except KeyError as exc:
            raise AuditError("audit log tail is missing fields") from exc

    def _read_last_line(self) -> str:
        with open(self.log_path, "rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            pos = log_file.tell() - 1
            buf = b""
            while pos >= 0:
                log_file.seek(pos)
                char = log_file.read(1)
                if char == b"\n" and buf:
                    break
                if char != b"\n":
                    buf = char + buf
                pos -= 1
            return buf.decode("utf-8")

    def _write_anchor(self, seq: int, hash_value: str) -> None:
        """Atomically write the anchor mirror in its own directory."""
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"seq": seq, "hash": hash_value}, sort_keys=True)
        tmp_path = self.anchor_path.with_suffix(".json.tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as anchor_file:
            anchor_file.write(payload)
            anchor_file.flush()
            os.fsync(anchor_file.fileno())
        os.replace(tmp_path, self.anchor_path)

    @staticmethod
    def _validate(
        tenant: str,
        user: str,
        role: str,
        action: str,
        object_ref: str,
        result: str,
        reason: str,
    ) -> None:
        if not _RE_TENANT.fullmatch(tenant):
            raise ValueError(f"tenant must be a short code, got: {tenant!r}")
        if not _RE_PSEUDONYM.fullmatch(user):
            raise ValueError(f"user must be a pseudonym (user_pseudonym), got: {user!r}")
        if not _RE_ROLE.fullmatch(role):
            raise ValueError(f"role must be a lowercase code, got: {role!r}")
        if not _RE_CODE.fullmatch(action):
            raise ValueError(f"action must be a code, got: {action!r}")
        if not _RE_OBJECT.fullmatch(object_ref):
            raise ValueError(f"object ref must be a minimized identifier, got: {object_ref!r}")
        if not _RE_RESULT.fullmatch(result):
            raise ValueError(f"result must be a code, got: {result!r}")
        if not _RE_CODE.fullmatch(reason):
            raise ValueError(
                f"reason must be a code - free text must not reach the audit log (A8), got: {reason!r}"
            )


_default: AuditTrail | None = None


def get_audit() -> AuditTrail:
    """Singleton audit trail wired via settings (used by all services)."""
    global _default
    if _default is None:
        _default = AuditTrail(settings.audit_log_path, settings.audit_anchor_dir)
    return _default
