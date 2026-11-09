import os
import re
import secrets
from pathlib import Path

from gridvault.config import settings

_MASTER_KEY_BYTES = 32

# Conservative allowlist: no separators, no dots, no traversal possible.
_TENANT_CODE_RE = re.compile(r"^[A-Za-z0-9]{2,10}$")


class KeyServiceError(Exception):
    """Raised when a master key cannot be created or loaded safely."""


def _validate_tenant_code(tenant_code: str) -> None:
    if not _TENANT_CODE_RE.fullmatch(tenant_code):
        raise KeyServiceError(f"invalid tenant code: {tenant_code!r}")


def _key_path(tenant_code: str, key_dir: Path | str | None = None) -> Path:
    base = Path(key_dir) if key_dir is not None else Path(settings.key_dir)
    _validate_tenant_code(tenant_code)
    return base / f"{tenant_code}.key"


def create_master_key(
    tenant_code: str, key_dir: Path | str | None = None, *, overwrite: bool = False
) -> bytes:
    """Create and persist a fresh 256-bit master key for a tenant."""
    path = _key_path(tenant_code, key_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists() and not overwrite:
        raise KeyServiceError(f"master key for {tenant_code!r} already exists")

    key = secrets.token_bytes(_MASTER_KEY_BYTES)

    # O_EXCL: even with overwrite=True the file is replaced atomically-ish
    # via write-to-temp + rename to avoid a partially written key file.
    tmp_path = path.with_suffix(".key.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(key.hex())
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)
    return key


def get_master_key(tenant_code: str, key_dir: Path | str | None = None) -> bytes:
    """Return the 32-byte master key of the given tenant."""
    path = _key_path(tenant_code, key_dir)
    if not path.is_file():
        raise KeyServiceError(f"no master key for tenant {tenant_code!r}")

    key = bytes.fromhex(path.read_text(encoding="ascii").strip())
    if len(key) != _MASTER_KEY_BYTES:
        raise KeyServiceError(f"master key for {tenant_code!r} has wrong length")
    return key
