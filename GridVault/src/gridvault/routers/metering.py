from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.database import get_db
from gridvault.services import gateway
from gridvault.services.sessions import COOKIE_NAME

router = APIRouter(prefix="/metering-points", tags=["Metering Points"])


@router.get("")
async def list_metering_points(
    request: Request, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    """Metering points visible to the caller (customer: only their own).
    Returns only cleartext fields: metering point ID, utility, postcode,
    tariff. A directory listing never decrypts names or addresses."""
    return await gateway.list_meter_points(db, request.cookies.get(COOKIE_NAME))


@router.get("/{mp_id}")
async def get_metering_point(
    mp_id: str, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """Role-specific detail view via the central gateway (A3).

    Kunde: all fields including hourly values, own metering point only.
    Abrechnung: name, tariff, consumption sum, amount; load profile
    masked - the sum is computed inside the gateway, single values
    never leave it. Denials are audited in the gateway with the true
    reason; the client gets the same generic message for every denial.
    """
    return await gateway.read_meter_point(db, request.cookies.get(COOKIE_NAME), mp_id)


@router.get("/{mp_id}/readings")
async def get_readings(
    mp_id: str, request: Request, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    """Hourly values via the gateway - customer role only (A3/A7):
    single values are purpose-bound to the customer.

    Decryption is context-checked: each ciphertext is bound to metering
    point and timestamp (Weg b AAD), so a swapped ciphertext is reported
    as an integrity violation naming both (T5)."""
    return await gateway.list_hourly_readings(
        db, request.cookies.get(COOKIE_NAME), mp_id
    )
