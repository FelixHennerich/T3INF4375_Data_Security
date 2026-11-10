"""Auth router (M4, A1, B4/T1).

Login creates a server-side session (HttpOnly cookie); every other
action authorizes exclusively against that session.

Security properties (A1):
- Argon2 verification (argon2-cffi verifies in constant time and embeds
  a per-hash random salt).
- No user-existence hint: unknown username and wrong password produce
  the same work (verify against a cached dummy hash), the same response
  status and the same error message. Only the audit trail records the
  real reason - it is never returned to the client.
- Login success AND failure each produce an audit entry (A5).
- Passwords are never logged, neither in plaintext nor hashed.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.database import get_db
from gridvault.db import Tenant, User
from gridvault.services.audit import get_audit, user_pseudonym
from gridvault.services.sessions import (
    COOKIE_NAME,
    CurrentSession,
    create_session,
    delete_session,
    is_expired,
    resolve_session,
)

router = APIRouter(prefix="/auth", tags=["Auth"])

GENERIC_LOGIN_ERROR = "Invalid username or password"
GENERIC_SESSION_ERROR = "Not authenticated"

_password_hasher = PasswordHasher()
_dummy_hash: str | None = None


def _dummy_argon2_hash() -> str:
    """Fixed dummy hash so a login attempt for a NON-EXISTING user costs
    the same Argon2 work as one for an existing user - otherwise the
    response time would reveal which usernames exist (enumeration)."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _password_hasher.hash("gridvault-anti-enumeration")
    return _dummy_hash


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(
    payload: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)
) -> dict:
    audit = get_audit()

    def reject(reason: str) -> HTTPException:
        # The audit entry carries the true reason; the client only ever
        # sees the same generic message (A1).
        audit.log_action(
            tenant=tenant_code,
            user=pseudonym,
            role=role,
            action="login",
            object_ref="user",
            result="denied",
            reason=reason,
        )
        return HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    user = await db.scalar(select(User).where(User.username == payload.username))
    if user is None:
        tenant_code, pseudonym, role = "-", "u0", "unknown"
        try:
            _password_hasher.verify(_dummy_argon2_hash(), payload.password)
        except VerificationError:
            pass
        raise reject("user_unknown")

    tenant_code = (
        await db.scalar(select(Tenant.code).where(Tenant.id == user.tenant_id)) or "-"
    )
    pseudonym = user_pseudonym(user.id)
    role = user.role

    try:
        password_ok = _password_hasher.verify(user.password_hash, payload.password)
    except VerificationError:
        password_ok = False

    if not password_ok:
        raise reject("password_wrong")

    if not user.is_active:
        raise reject("user_disabled")

    if _password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _password_hasher.hash(payload.password)
        await db.commit()

    token, current = await create_session(db, user)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=current.seconds_remaining + 60,
        httponly=True,
        samesite="lax",
        # secure=True once served over HTTPS (A1); localhost uses plain
        # HTTP in the prototype.
    )
    audit.log_action(
        tenant=current.tenant_code,
        user=user_pseudonym(current.user_id),
        role=current.role,
        action="login",
        object_ref="user",
        result="success",
        reason="credentials_ok",
    )
    return {
        "username": current.username,
        "tenant": current.tenant_code,
        "role": current.role,
        "expires_at": current.expires_at.isoformat(),
    }


async def _resolve_or_raise(request: Request, db: AsyncSession, action: str) -> CurrentSession:
    """Resolve the session cookie; audit and reject otherwise.

    Denials distinguish only what the server knows internally
    (session_expired vs session_invalid) - the client gets the same
    generic 401 for both.
    """
    audit = get_audit()
    current = await resolve_session(db, request.cookies.get(COOKIE_NAME))
    if current is None:
        audit.log_action(
            tenant="-",
            user="u0",
            role="unknown",
            action=action,
            object_ref="session",
            result="denied",
            reason="session_invalid",
        )
        raise HTTPException(status_code=401, detail=GENERIC_SESSION_ERROR)
    if is_expired(current):
        audit.log_action(
            tenant=current.tenant_code,
            user=user_pseudonym(current.user_id),
            role=current.role,
            action=action,
            object_ref="session",
            result="denied",
            reason="session_expired",
        )
        raise HTTPException(status_code=401, detail=GENERIC_SESSION_ERROR)
    return current


@router.post("/logout")
async def logout(
    request: Request, response: Response, db: AsyncSession = Depends(get_db)
) -> dict:
    current = await _resolve_or_raise(request, db, action="logout")
    await delete_session(db, request.cookies.get(COOKIE_NAME) or "")
    response.delete_cookie(COOKIE_NAME)
    get_audit().log_action(
        tenant=current.tenant_code,
        user=user_pseudonym(current.user_id),
        role=current.role,
        action="logout",
        object_ref="session",
        result="success",
        reason="user_logout",
    )
    return {"status": "logged_out"}


@router.get("/me")
async def whoami(request: Request, db: AsyncSession = Depends(get_db)) -> dict:
    current = await _resolve_or_raise(request, db, action="whoami")
    get_audit().log_action(
        tenant=current.tenant_code,
        user=user_pseudonym(current.user_id),
        role=current.role,
        action="whoami",
        object_ref="session",
        result="success",
        reason="authorized",
    )
    return {
        "username": current.username,
        "tenant": current.tenant_code,
        "role": current.role,
        "expires_at": current.expires_at.isoformat(),
        "seconds_remaining": current.seconds_remaining,
    }
