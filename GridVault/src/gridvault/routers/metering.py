from fastapi import APIRouter

router = APIRouter(prefix="/metering-points", tags=["Metering Points"])


@router.get("")
async def list_metering_points() -> list[dict]:
    """Metering points visible to the caller (customer: only their own).
    Returns only cleartext fields: metering point ID, utility, postcode, tariff."""


@router.get("/{mp_id}")
async def get_metering_point(mp_id: str) -> dict | None:
    """Role-specific detail view. Customer: all fields including hourly values.
    Billing: name, tariff, consumption sum, amount; load profile reported as [NICHT FREIGEGEBEN].
    The sum is computed inside the gateway; individual values never leave it."""


@router.get("/{mp_id}/readings")
async def get_readings(mp_id: str) -> list[dict]:
    """Hourly values (customer role, own metering point only).
    Decryption is context-checked: each ciphertext is bound to metering point and timestamp (T5)."""
