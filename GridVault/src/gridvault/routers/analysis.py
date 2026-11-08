"""Network analysis endpoints (A3, test T3)."""

from fastapi import APIRouter

router = APIRouter(prefix="/analysis", tags=["Network Analysis"])

# Declaration only – no implementation yet.


@router.get("/plz/{plz}/hourly-sum")
async def cohort_hourly_sum(plz: str) -> dict | None:
    """Hourly sum of a cohort (all metering points of one postcode, own utility only).
    Small-cell protection: the cohort must contain at least k = 3 metering points,
    otherwise the request is rejected with n and k disclosed."""


@router.post("/plz/{plz}/export")
async def export_cohort(plz: str) -> dict | None:
    """Export a cohort for the analysis environment.
    Only pseudonyms (HMAC over the metering point ID, per-utility key, not the master key); never names."""
