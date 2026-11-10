from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.database import get_db
from gridvault.services import gateway
from gridvault.services.sessions import COOKIE_NAME

router = APIRouter(prefix="/analysis", tags=["Network Analysis"])


@router.get("/plz/{plz}/hourly-sum")
async def cohort_hourly_sum(
    plz: str, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """Hourly sum of a cohort (all metering points of one postcode, own
    utility only) via the gateway. Network analyst role only.

    Small-cell protection: the cohort must contain at least k = 3 metering
    points, otherwise the request is rejected with n and k disclosed."""
    return await gateway.cohort_hourly_sum(db, request.cookies.get(COOKIE_NAME), plz)


@router.post("/plz/{plz}/export")
async def export_cohort(
    plz: str, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """Export a cohort for the analysis environment via the gateway.

    Only pseudonyms (HMAC over the metering point ID, per-utility key,
    not the master key); never names. Persisted with a retention date
    for the deletion run (M9)."""
    return await gateway.export_cohort(db, request.cookies.get(COOKIE_NAME), plz)
