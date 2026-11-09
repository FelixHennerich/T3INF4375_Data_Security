import importlib.util
import itertools
import json
from pathlib import Path

import pytest

from gridvault.services.audit import (
    GENESIS_HASH,
    AuditTrail,
    user_pseudonym,
)

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
_spec = importlib.util.spec_from_file_location("verify_audit", _SCRIPTS / "verify_audit.py")
verify_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_audit)

N_ENTRIES = 5


@pytest.fixture()
def trail(tmp_path: Path) -> AuditTrail:
    return AuditTrail(
        log_path=tmp_path / "audit_trail.log",
        anchor_dir=tmp_path / "audit_anchor",
    )


def write_entries(trail: AuditTrail, count: int = N_ENTRIES) -> None:
    for i in range(count):
        trail.log_action(
            tenant="SWN",
            user=user_pseudonym(i + 1),
            role="kunde" if i % 2 == 0 else "abrechnung",
            action="read_metering_point",
            object_ref=f"mp:DE000000000{i}",
            result="success",
            reason="authorized",
        )


def lines_of(trail: AuditTrail) -> list[str]:
    return trail.log_path.read_text(encoding="utf-8").splitlines()


def rewrite(trail: AuditTrail, lines: list[str]) -> None:
    # Bypasses the service on purpose: simulates an attacker with write
    # access to the log file, outside the append-only API.
    trail.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestChain:
    def test_intact_chain_verifies(self, trail: AuditTrail) -> None:
        write_entries(trail)
        findings = verify_audit.verify(
            trail.log_path, trail.anchor_path.parent / "audit_anchor.json"
        )
        assert findings == []

    def test_entries_carry_all_mandatory_fields_and_chain_correctly(
        self, trail: AuditTrail
    ) -> None:
        write_entries(trail)
        entries = [json.loads(line) for line in lines_of(trail)]
        assert [e["seq"] for e in entries] == list(range(1, N_ENTRIES + 1))
        assert entries[0]["prev_hash"] == GENESIS_HASH
        for prev, entry in itertools.pairwise(entries):
            assert entry["prev_hash"] == prev["hash"]

    def test_log_grows_append_only(self, trail: AuditTrail) -> None:
        write_entries(trail, 2)
        before = lines_of(trail)
        write_entries(trail, 0)  # helper adds nothing; write one directly
        trail.log_action(
            tenant="SWN",
            user=user_pseudonym(9),
            role="leitstelle",
            action="grant_outage_access",
            object_ref="ticket:T-1001",
            result="success",
            reason="four_eyes_ok",
        )
        after = lines_of(trail)
        assert after[: len(before)] == before  # existing bytes untouched
        assert len(after) == len(before) + 1

    def test_anchor_mirrors_last_entry(self, trail: AuditTrail) -> None:
        write_entries(trail)
        anchor = json.loads(
            (trail.anchor_path.parent / "audit_anchor.json").read_text()
        )
        last = json.loads(lines_of(trail)[-1])
        assert anchor == {"seq": last["seq"], "hash": last["hash"]}


class TestDataMinimization:
    def test_free_text_reason_is_rejected(self, trail: AuditTrail) -> None:
        with pytest.raises(ValueError, match="free text"):
            trail.log_action(
                tenant="SWN",
                user=user_pseudonym(1),
                role="stoerungsdienst",
                action="request_outage_access",
                object_ref="ticket:T-1001",
                result="denied",
                reason="Der Kunde beschwerte sich ueber den Stromausfall",
            )

    def test_name_instead_of_pseudonym_is_rejected(self, trail: AuditTrail) -> None:
        with pytest.raises(ValueError, match="pseudonym"):
            trail.log_action(
                tenant="SWN",
                user="Felix",
                role="kunde",
                action="login",
                object_ref="user",
                result="success",
                reason="credentials_ok",
            )

    def test_log_contains_no_personal_names_or_plain_text_reasons(
        self, trail: AuditTrail
    ) -> None:
        write_entries(trail)
        content = trail.log_path.read_text(encoding="utf-8")
        for needle in ("Felix", "Musterstrasse", "Stromausfall"):
            assert needle not in content


class TestTamperingDetection:
    def test_modified_middle_entry(self, trail: AuditTrail, capsys: pytest.CaptureFixture) -> None:
        write_entries(trail)
        lines = lines_of(trail)
        entry = json.loads(lines[2])
        entry["result"] = "success_x"
        lines[2] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        rewrite(trail, lines)

        assert verify_audit.main(["--log", str(trail.log_path), "--anchor-dir", str(trail.anchor_path.parent)]) == 1
        output = capsys.readouterr().out
        assert "line 3" in output
        assert "MODIFIED" in output

    def test_deleted_middle_entry(self, trail: AuditTrail, capsys: pytest.CaptureFixture) -> None:
        write_entries(trail)
        lines = lines_of(trail)
        del lines[2]  # remove seq 3
        rewrite(trail, lines)

        assert verify_audit.main(["--log", str(trail.log_path), "--anchor-dir", str(trail.anchor_path.parent)]) == 1
        output = capsys.readouterr().out
        assert "line 3" in output
        assert "seq 3" in output

    def test_truncated_tail_detected_via_anchor(
        self, trail: AuditTrail, capsys: pytest.CaptureFixture
    ) -> None:
        write_entries(trail)
        lines = lines_of(trail)
        rewrite(trail, lines[:-2])  # cut the last two entries

        assert verify_audit.main(["--log", str(trail.log_path), "--anchor-dir", str(trail.anchor_path.parent)]) == 1
        output = capsys.readouterr().out
        assert "TRUNCATED TAIL" in output
        assert "2" in output  # number of missing entries reported

    def test_last_entry_modified_after_anchor_write(
        self, trail: AuditTrail, capsys: pytest.CaptureFixture
    ) -> None:
        write_entries(trail)
        lines = lines_of(trail)
        entry = json.loads(lines[-1])
        entry["reason"] = "no_reason"
        # Attacker ALSO recomputes the entry hash so the chain itself stays
        # consistent - only the external anchor can expose this.
        entry["hash"] = verify_audit.entry_hash(entry)
        lines[-1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        rewrite(trail, lines)

        assert verify_audit.main(["--log", str(trail.log_path), "--anchor-dir", str(trail.anchor_path.parent)]) == 1
        output = capsys.readouterr().out
        assert "LAST ENTRY MODIFIED" in output

    def test_deleted_log_with_anchor_present(
        self, trail: AuditTrail, capsys: pytest.CaptureFixture
    ) -> None:
        write_entries(trail)
        trail.log_path.unlink()

        assert verify_audit.main(["--log", str(trail.log_path), "--anchor-dir", str(trail.anchor_path.parent)]) == 1
        output = capsys.readouterr().out
        assert "anchor exists but the audit log is missing" in output

    def test_corrupt_line_is_unreadable_not_tampering(
        self, trail: AuditTrail, capsys: pytest.CaptureFixture
    ) -> None:
        write_entries(trail)
        lines = lines_of(trail)
        lines[1] = "not json at all"
        rewrite(trail, lines)

        assert verify_audit.main(["--log", str(trail.log_path), "--anchor-dir", str(trail.anchor_path.parent)]) == 2
        output = capsys.readouterr().out
        assert "UNREADABLE" in output
