"""Session management (A1).

Sessions are server-side rows identified by a random 256-bit token that
is handed to the client exclusively as an HttpOnly cookie. Only the
SHA-256 of the token is stored - the cookie value itself never touches
the database, so a stolen DB dump cannot be used to hijack sessions.

Every further action authorizes ONLY against the session (M5 gateway
builds on resolve_session). Tenant and role are a snapshot from login
time; an expired or missing session is treated as "no session".
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.config import settings
from gridvault.db import Session, Tenant, User

COOKIE_NAME = "gridvault_session"


@dataclass(slots=True)
class CurrentSession:
    """Everything a route may learn about the caller (from the session
    alone, never from client input)."""

    session_id: str
    user_id: int
    username: str
    tenant_id: int
    tenant_code: str
    role: str
    expires_at: datetime

    @property
    def seconds_remaining(self) -> int:
        now = datetime.now(UTC).replace(tzinfo=None)
        return max(0, int((self.expires_at - now).total_seconds()))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_session(db: AsyncSession, user: User) -> tuple[str, CurrentSession]:
    """Create a session row; returns (cookie token, resolved session).

    The caller keeps the token only for the Set-Cookie header and drops
    it - persistence works via the token hash alone.
    """
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC).replace(tzinfo=None)
    db.add(
        Session(
            id=str(uuid.uuid4()),
            token_hash=_hash_token(token),
            user_id=user.id,
            tenant_id=user.tenant_id,
            role=user.role,
            created_at=now,
            expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
        )
    )
    await db.commit()
    current = await resolve_session(db, token)
    assert current is not None
    return token, current


async def resolve_session(
    db: AsyncSession, token: str | None
) -> CurrentSession | None:
    """Resolve a cookie token to its session, or None.

    None covers "no cookie", "unknown token" and "user deactivated" -
    callers deliberately cannot distinguish these, which prevents
    session probing (part of the M5 denial design).
    """
    if not token:
        return None
    stmt = (
        select(Session, User, Tenant)
        .join(User, User.id == Session.user_id)
        .join(Tenant, Tenant.id == Session.tenant_id)
        .where(Session.token_hash == _hash_token(token))
    )
    row = (await db.execute(stmt)).first()
    if row is None:
        return None
    session, user, tenant = row
    # Deactivated users lose their sessions immediately (A7: permission
    # removal takes effect before the next query).
    if not user.is_active:
        return None
    return CurrentSession(
        session_id=session.id,
        user_id=user.id,
        username=user.username,
        tenant_id=tenant.id,
        tenant_code=tenant.code,
        role=session.role,
        expires_at=session.expires_at,
    )


def is_expired(current: CurrentSession) -> bool:
    now = datetime.now(UTC).replace(tzinfo=None)
    return current.expires_at <= now


async def delete_session(db: AsyncSession, token: str) -> bool:
    """Delete the session row for a token; True if one existed."""
    result = await db.execute(
        delete(Session).where(Session.token_hash == _hash_token(token))
    )
    await db.commit()
    return bool(result.rowcount)
