from datetime import datetime
from pathlib import Path

import pytest

from gridvault.services import crypto
from gridvault.services.crypto import IntegrityViolation
from gridvault.services.keys import (
    KeyServiceError,
    create_master_key,
    get_master_key,
)

TENANT_A = "SWN"
TENANT_B = "SWB"
MP_ID = "DE0000000001"
T1 = datetime(2026, 10, 1, 7, 0)
T2 = datetime(2026, 10, 1, 8, 0)


@pytest.fixture()
def keys(tmp_path: Path) -> dict[str, bytes]:
    """Master keys for two tenants, stored in a temporary key directory."""
    for tenant in (TENANT_A, TENANT_B):
        create_master_key(tenant, key_dir=tmp_path)
    return {t: get_master_key(t, key_dir=tmp_path) for t in (TENANT_A, TENANT_B)}


class TestKeyService:
    def test_keys_are_created_and_loaded(self, keys: dict[str, bytes]) -> None:
        assert len(keys[TENANT_A]) == 32
        assert len(keys[TENANT_B]) == 32
        assert keys[TENANT_A] != keys[TENANT_B]

    def test_unknown_tenant_fails_closed(self, tmp_path: Path) -> None:
        with pytest.raises(KeyServiceError):
            get_master_key("SWX", key_dir=tmp_path)

    def test_tenant_code_allowlist_blocks_traversal(self, tmp_path: Path) -> None:
        for code in ("../etc", "A/B", "x", "way_too_long_tenant", "SW N"):
            with pytest.raises(KeyServiceError):
                create_master_key(code, key_dir=tmp_path)
        assert list(tmp_path.iterdir()) == []  # nothing was written anywhere

    def test_existing_key_is_never_silently_overwritten(
        self, tmp_path: Path
    ) -> None:
        create_master_key(TENANT_A, key_dir=tmp_path)
        with pytest.raises(KeyServiceError):
            create_master_key(TENANT_A, key_dir=tmp_path)

    def test_key_file_permissions_restricted_to_owner(
        self, tmp_path: Path
    ) -> None:
        create_master_key(TENANT_A, key_dir=tmp_path)
        mode = (tmp_path / f"{TENANT_A}.key").stat().st_mode & 0o777
        assert mode == 0o600


class TestCryptoRoundtrip:
    def test_roundtrip(self, keys: dict[str, bytes]) -> None:
        ctx = crypto.build_context(TENANT_A, MP_ID, T1)
        blob = crypto.encrypt("1.238", keys[TENANT_A], ctx)
        assert crypto.decrypt(blob, keys[TENANT_A], ctx) == "1.238"

    def test_context_format_is_deterministic_for_datetime_and_iso_string(
        self,
    ) -> None:
        via_dt = crypto.build_context(TENANT_A, MP_ID, T1)
        via_str = crypto.build_context(TENANT_A, MP_ID, T1.isoformat())
        assert via_dt == via_str == f"SWN:{MP_ID}:2026-10-01T07:00:00"


class TestTenantSeparation:
    def test_decrypt_with_other_tenants_master_key_fails(
        self, keys: dict[str, bytes]
    ) -> None:
        """A2: an access with the other Stadtwerk's key must fail."""
        ctx = crypto.build_context(TENANT_A, MP_ID, T1)
        blob = crypto.encrypt("1.238", keys[TENANT_A], ctx)
        with pytest.raises(IntegrityViolation):
            crypto.decrypt(blob, keys[TENANT_B], ctx)


class TestSwapDetection:
    """Mechanics of B4/T5: relocate two VALID ciphertexts between rows."""

    def test_swapped_ciphertext_of_same_mp_is_detected(
        self, keys: dict[str, bytes]
    ) -> None:
        key = keys[TENANT_A]
        ctx_1 = crypto.build_context(TENANT_A, MP_ID, T1)
        ctx_2 = crypto.build_context(TENANT_A, MP_ID, T2)
        ct_1 = crypto.encrypt("0.412", key, ctx_1)
        ct_2 = crypto.encrypt("1.238", key, ctx_2)

        # Attacker with DB write access swaps the two blobs. Reading row 1
        # now uses ciphertext of row 2 (and vice versa): both must fail
        # and the message must name mp_id and timestamp.
        with pytest.raises(IntegrityViolation) as exc_info:
            crypto.decrypt(ct_2, key, ctx_1)
        assert MP_ID in str(exc_info.value)
        assert T1.isoformat() in str(exc_info.value)

        with pytest.raises(IntegrityViolation) as exc_info:
            crypto.decrypt(ct_1, key, ctx_2)
        assert MP_ID in str(exc_info.value)
        assert T2.isoformat() in str(exc_info.value)

    def test_ciphertext_modified_in_place_is_detected(
        self, keys: dict[str, bytes]
    ) -> None:
        ctx = crypto.build_context(TENANT_A, MP_ID, T1)
        blob = bytearray(crypto.encrypt("1.238", keys[TENANT_A], ctx))
        blob[-1] ^= 0x01  # single character changed
        with pytest.raises(IntegrityViolation):
            crypto.decrypt(bytes(blob), keys[TENANT_A], ctx)

    def test_wrong_context_without_touching_the_ciphertext_is_detected(
        self, keys: dict[str, bytes]
    ) -> None:
        ctx_1 = crypto.build_context(TENANT_A, MP_ID, T1)
        ctx_2 = crypto.build_context(TENANT_A, "DE0000000002", T1)
        blob = crypto.encrypt("1.238", keys[TENANT_A], ctx_1)
        with pytest.raises(IntegrityViolation):
            crypto.decrypt(blob, keys[TENANT_A], ctx_2)


class TestDataKeyWrapping:
    """A2 bonus: per-metering-point data keys wrapped with the master key."""

    def test_wrap_unwrap_roundtrip(self, keys: dict[str, bytes]) -> None:
        data_key = crypto.generate_data_key()
        ctx = f"{TENANT_A}:{MP_ID}"
        wrapped = crypto.wrap_data_key(keys[TENANT_A], data_key, ctx)
        assert crypto.unwrap_data_key(keys[TENANT_A], wrapped, ctx) == data_key

    def test_unwrap_with_other_tenants_master_key_fails(
        self, keys: dict[str, bytes]
    ) -> None:
        data_key = crypto.generate_data_key()
        wrapped = crypto.wrap_data_key(keys[TENANT_A], data_key, f"{TENANT_A}:{MP_ID}")
        with pytest.raises(IntegrityViolation):
            crypto.unwrap_data_key(keys[TENANT_B], wrapped, f"{TENANT_A}:{MP_ID}")

    def test_wrapped_data_key_cannot_be_swapped_between_metering_points(
        self, keys: dict[str, bytes]
    ) -> None:
        data_key = crypto.generate_data_key()
        wrapped = crypto.wrap_data_key(keys[TENANT_A], data_key, f"{TENANT_A}:{MP_ID}")
        with pytest.raises(IntegrityViolation):
            # wrapped key relocated to another metering point
            crypto.unwrap_data_key(
                keys[TENANT_A], wrapped, f"{TENANT_A}:DE0000000002"
            )
