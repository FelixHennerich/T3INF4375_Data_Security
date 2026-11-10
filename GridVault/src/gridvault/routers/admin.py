from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.database import get_db
from gridvault.services import gateway
from gridvault.services.sessions import COOKIE_NAME

router = APIRouter(prefix="/admin", tags=["Administration"])


class RetentionException(BaseModel):
    """A justified retention exception: readings of this metering point
    are kept and the reason is recorded traceably in the DeletionRun."""

    mp_id: str = Field(min_length=1, max_length=50)
    reason: str = Field(pattern=r"^[a-z0-9_]{1,40}$", description="reason CODE, no free text")


class DeletionRunIn(BaseModel):
    retention_days: int = Field(ge=0, le=3650)
    exceptions: list[RetentionException] = Field(default_factory=list)
    dry_run: bool = False


@router.post("/deletion-run")
async def run_deletion(
    payload: DeletionRunIn, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """Configurable deletion run for load profiles and analysis exports
    (A6): readings whose retention window (start = measurement
    timestamp) has expired, plus exports past their retention date, are
    removed - own tenant only. Justified exceptions (mp_id + reason
    code) are kept and recorded in the DeletionRun row.

    The audit log records the EVENT without any deleted content (A8);
    counts live in the DeletionRun bookkeeping row."""
    return await gateway.run_deletion(
        db,
        request.cookies.get(COOKIE_NAME),
        retention_days=payload.retention_days,
        exceptions=[exc.model_dump() for exc in payload.exceptions],
        dry_run=payload.dry_run,
    )


@router.delete("/metering-points/{mp_id}/data-key")
async def destroy_data_key(
    mp_id: str, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """A2 bonus - customer deletion via crypto-shredding: the wrapped
    data key of the metering point is destroyed. All ciphertext rows
    (values, name, address) remain - even in already pulled backups -
    but can no longer be decrypted by anyone, because the key material
    is gone. The customer may destroy their own key; Abrechnung may
    execute staff-side deletion requests for the own tenant."""
    return await gateway.delete_customer_data_key(
        db, request.cookies.get(COOKIE_NAME), mp_id
    )
