import importlib.util
import os
import tempfile
from pathlib import Path

import pytest

_TEST_ROOT = Path(tempfile.mkdtemp(prefix="gridvault-pytest-"))

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_ROOT / 'test.db'}"
os.environ["KEY_DIR"] = str(_TEST_ROOT / "keys")
os.environ["HMAC_KEY_DIR"] = str(_TEST_ROOT / "hmac_keys")
os.environ["AUDIT_LOG_PATH"] = str(_TEST_ROOT / "audit_trail.log")
os.environ["AUDIT_ANCHOR_DIR"] = str(_TEST_ROOT / "audit_anchor")

_SPEC = importlib.util.spec_from_file_location(
    "generate_testdata",
    Path(__file__).resolve().parents[1] / "scripts" / "generate_testdata.py",
)
generate_testdata = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(generate_testdata)

_testdata_ready = False


async def _ensure_testdata() -> None:
    """Create tables + canonical test dataset once per test session."""
    global _testdata_ready
    if _testdata_ready:
        return
    # Uses the env-overridden settings: tmp DB, tmp key dir.
    await generate_testdata.generate()
    _testdata_ready = True


@pytest.fixture()
async def client():
    """Async HTTP client against the app, with the test dataset in place."""
    await _ensure_testdata()
    from httpx import ASGITransport, AsyncClient

    from gridvault.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as http_client:
        yield http_client


@pytest.fixture()
def audit_log_path() -> Path:
    """Path of the (isolated) audit trail the app writes to in tests."""
    return _TEST_ROOT / "audit_trail.log"
