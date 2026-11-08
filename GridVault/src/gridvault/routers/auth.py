from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login")
async def login(payload: dict) -> dict | None:
    """Log in and create a session holding user ID, utility, role and expiry time.
    Failed logins return a generic error that does not reveal whether the user exists."""


@router.post("/logout")
async def logout() -> None:
    """End the current session (recorded in the audit trail)."""


@router.get("/me")
async def whoami() -> dict | None:
    """Show the caller's own session: user, utility, role and remaining lifetime."""
