"""Outage approval endpoints: four-eyes principle, time-limited, segment-bound (A4, test T4)."""

from fastapi import APIRouter

router = APIRouter(prefix="/outages", tags=["Outage Approval"])

# Declaration only – no implementation yet.


@router.post("/approval-requests")
async def create_approval_request(payload: dict) -> dict | None:
    """Outage service requests access to a network segment (postcode) with a ticket
    number and a free-text justification (minimum length required).
    The justification stays in the protected ticket system and never enters the audit log."""


@router.get("/approval-requests")
async def list_open_approval_requests() -> list[dict]:
    """Open requests of the caller's own utility (control centre role, no data access)."""


@router.post("/approval-requests/{request_id}/grant")
async def grant_approval(request_id: str) -> dict | None:
    """Control centre grants a request. Requester and approver must differ,
    approval is valid only for the requested postcode and for 30 minutes (configurable);
    afterwards every access is rejected."""


@router.get("/plz/{plz}/metering-points")
async def segment_metering_points(plz: str) -> list[dict]:
    """Metering points in an approved segment: ID, postcode, last reading; name masked as [HIDDEN].
    Requires a valid, non-expired approval for exactly this segment."""
