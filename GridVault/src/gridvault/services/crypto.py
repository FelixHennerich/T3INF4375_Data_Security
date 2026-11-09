import os
from datetime import datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
_NONCE_BYTES = 12


class IntegrityViolation(Exception):
    """Ciphertext, key or bound context do not match (T5)."""

    def __init__(self, context: str) -> None:
        self.context = context
        super().__init__(
            f"integrity violation: ciphertext does not match key or bound context '{context}'"
        )


def build_context(tenant_code: str, mp_id: str, timestamp: datetime | str) -> str:
    """Stable context string bound into every encryption."""
    ts = timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp
    return f"{tenant_code}:{mp_id}:{ts}"


def encrypt(value: str, key: bytes, context: str) -> bytes:
    """Encrypt a UTF-8 string with AES-256-GCM, bound to `context` (AAD)."""
    _check_key(key)
    nonce = os.urandom(_NONCE_BYTES)
    body = AESGCM(key).encrypt(nonce, value.encode("utf-8"), context.encode("utf-8"))
    return nonce + body


def decrypt(ciphertext: bytes, key: bytes, context: str) -> str:
    """Decrypt an AES-256-GCM blob created by `encrypt`."""
    _check_key(key)
    if len(ciphertext) < _NONCE_BYTES + 16:
        # Too short to contain nonce + tag: modified or garbage.
        raise IntegrityViolation(context)
    nonce, body = ciphertext[:_NONCE_BYTES], ciphertext[_NONCE_BYTES:]
    try:
        plaintext = AESGCM(key).decrypt(nonce, body, context.encode("utf-8"))
    except InvalidTag:
        # from None: no need to chain the library exception, the condition
        # is fully described by the context we failed to authenticate.
        raise IntegrityViolation(context) from None
    return plaintext.decode("utf-8")


def generate_data_key() -> bytes:
    """Fresh 256-bit per-metering-point data key (never stored unwrapped)."""
    return os.urandom(KEY_BYTES)


def wrap_data_key(master_key: bytes, data_key: bytes, context: str) -> bytes:
    """Wrap a data key with the tenant master key, bound to its context."""
    _check_key(data_key)
    return encrypt_bytes(data_key, master_key, context)


def unwrap_data_key(master_key: bytes, wrapped: bytes, context: str) -> bytes:
    """Unwrap a data key; IntegrityViolation on wrong key or context."""
    return decrypt_bytes(wrapped, master_key, context)


def encrypt_bytes(value: bytes, key: bytes, context: str) -> bytes:
    """Byte-level AES-256-GCM (used for key wrapping; AAD-bound too)."""
    _check_key(key)
    nonce = os.urandom(_NONCE_BYTES)
    body = AESGCM(key).encrypt(nonce, value, context.encode("utf-8"))
    return nonce + body


def decrypt_bytes(blob: bytes, key: bytes, context: str) -> bytes:
    """Inverse of encrypt_bytes; IntegrityViolation on any mismatch."""
    _check_key(key)
    if len(blob) < _NONCE_BYTES + 16:
        raise IntegrityViolation(context)
    nonce, body = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, body, context.encode("utf-8"))
    except InvalidTag:
        raise IntegrityViolation(context) from None


def _check_key(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise ValueError(f"AES-256 key must be {KEY_BYTES} bytes, got {len(key)}")
