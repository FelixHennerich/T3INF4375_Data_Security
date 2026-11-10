from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.config import settings
from gridvault.database import get_db
from gridvault.services import gateway
from gridvault.services.sessions import COOKIE_NAME

router = APIRouter(prefix="/outages", tags=["Outage Approval"])


class OutageRequestIn(BaseModel):
    """Schema validation happens at the API edge (422 on malformed
    input); the business workflow itself runs through the gateway."""

    plz: str = Field(pattern=r"^\d{5}$", description="network segment (postcode)")
    ticket_number: str = Field(
        min_length=3, max_length=30, pattern=r"^[A-Za-z0-9\-]+$"
    )
    reason: str = Field(
        min_length=settings.outage_reason_min_length,
        max_length=1000,
        description="free-text justification; stays in the ticket system",
    )


@router.post("/approval-requests")
async def create_approval_request(
    payload: OutageRequestIn, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """Outage service requests access to a network segment (postcode)
    with a ticket number and a free-text justification (minimum length
    enforced). The justification stays in the protected ticket system
    and never enters the audit log - only the ticket reference does."""
    return await gateway.create_outage_request(
        db,
        request.cookies.get(COOKIE_NAME),
        plz=payload.plz,
        ticket_number=payload.ticket_number,
        reason=payload.reason,
    )


@router.get("/approval-requests")
async def list_open_approval_requests(
    request: Request, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    """Open requests of the caller's own utility (control centre role,
    no data access). This view is the protected ticket system surface;
    it shows the justification, the audit trail does not."""
    return await gateway.list_outage_requests(db, request.cookies.get(COOKIE_NAME))


@router.post("/approval-requests/{request_id}/grant")
async def grant_approval(
    request_id: int, request: Request, db: AsyncSession = Depends(get_db)
) -> dict:
    """Control centre grants a request. Requester and approver must
    differ (four-eyes), approval is valid only for the requested postcode
    and for the configured window (30 minutes default); afterwards every
    access is rejected (B4/T4 shortens the window via configuration)."""
    return await gateway.grant_outage_request(
        db, request.cookies.get(COOKIE_NAME), request_id
    )


@router.get("/plz/{plz}/metering-points")
async def segment_metering_points(
    plz: str, request: Request, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    """Metering points in an approved segment: ID, postcode, last reading;
    name masked as [HIDDEN]. Requires a valid, non-expired approval for
    exactly this segment."""
    return await gateway.read_outage_segment(db, request.cookies.get(COOKIE_NAME), plz)
