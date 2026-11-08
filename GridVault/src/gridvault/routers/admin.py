from fastapi import APIRouter

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.post("/deletion-run")
async def run_deletion() -> dict | None:
    """Start a configurable deletion run for load profiles and analysis exports
    (traceable retention start, justified retention exceptions).
    The event is recorded without any deleted content in the audit log."""
