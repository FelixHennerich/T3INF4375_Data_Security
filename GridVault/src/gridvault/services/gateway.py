from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.db import HourlyReading, MeteringPoint, Tenant
from gridvault.services import crypto
from gridvault.services.audit import get_audit, user_pseudonym
from gridvault.services.keys import get_master_key
from gridvault.services.sessions import (
    CurrentSession,
    is_expired,
    resolve_session,
)

# Price per kWh (EUR) for the amount the Abrechnung role reports (A3).
TARIFF_PRICES_EUR = {
    "Haushaltsstrom": 0.35,
    "Nachtstrom": 0.28,
    "Gewerbestrom": 0.29,
    "Waermepumpe": 0.26,
}

MASKED_PROFILE = "[NICHT FREIGEGEBEN]"

GENERIC_DENIAL_MESSAGE = "Access denied"

# Status per internal reason - the client message stays generic either way.
_REASON_STATUS = {
    "session_invalid": 401,
    "session_expired": 401,
    "role_not_allowed": 403,
    "tenant_mismatch": 403,
    "not_own_meter": 403,
    "object_not_found": 403,
    "no_valid_grant": 403,  # A4/M8: Störungsdienst without/without expired grant
}


class GatewayDenied(Exception):
    """Raised after a denial has been audited.

    `reason` is an audit code only - never returned to the client; the
    client sees exc.client_message, identical for every denial.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        self.status = _REASON_STATUS.get(reason, 403)
        self.client_message = GENERIC_DENIAL_MESSAGE
        super().__init__(GENERIC_DENIAL_MESSAGE)


def _deny(
    current: CurrentSession | None,
    *,
    action: str,
    object_ref: str,
    reason: str,
) -> None:
    """Audit a denial (step 7) and raise GatewayDenied."""
    get_audit().log_action(
        tenant=current.tenant_code if current else "-",
        user=user_pseudonym(current.user_id) if current else "u0",
        role=current.role if current else "unknown",
        action=action,
        object_ref=object_ref,
        result="denied",
        reason=reason,
    )
    raise GatewayDenied(reason)


async def _require_session(
    db: AsyncSession, token: str | None, *, action: str, object_ref: str
) -> CurrentSession:
    """Step 1: session must exist and must not be expired."""
    current = await resolve_session(db, token)
    if current is None:
        _deny(None, action=action, object_ref=object_ref, reason="session_invalid")
    assert current is not None
    if is_expired(current):
        _deny(current, action=action, object_ref=object_ref, reason="session_expired")
    return current


def _require_role(
    current: CurrentSession, *, action: str, object_ref: str, allowed_roles: set[str]
) -> None:
    """Step 2: purpose binding - the role must be allowed for the action."""
    if current.role not in allowed_roles:
        _deny(current, action=action, object_ref=object_ref, reason="role_not_allowed")


def _require_tenant(
    current: CurrentSession,
    *,
    action: str,
    object_ref: str,
    object_tenant: str | None,
) -> None:
    """Step 3: multi-tenancy - object must belong to the caller's Stadtwerk."""
    if object_tenant is not None and current.tenant_code != object_tenant:
        _deny(current, action=action, object_ref=object_ref, reason="tenant_mismatch")


async def authorize(
    db: AsyncSession,
    token: str | None,
    *,
    action: str,
    allowed_roles: set[str],
    object_ref: str,
    object_tenant: str | None = None,
) -> CurrentSession:
    """Steps 1-3 of the mandated chain (see module docstring)."""
    current = await _require_session(db, token, action=action, object_ref=object_ref)
    _require_role(current, action=action, object_ref=object_ref, allowed_roles=allowed_roles)
    _require_tenant(current, action=action, object_ref=object_ref, object_tenant=object_tenant)
    return current


async def read_meter_point(
    db: AsyncSession, token: str | None, mp_id: str
) -> dict:
    """Full gateway run for reading one metering point (probe, A3).

    Kunde: own metering point only, all fields including hourly values.
    Abrechnung: metering points of the own tenant - name, tariff,
    consumption sum, amount; the load profile is masked. The sum is
    computed INSIDE this function; single values never leave it.
    """
    action = "read_metering_point"
    object_ref = f"mp:{mp_id}"

    stmt = select(MeteringPoint, Tenant).join(Tenant, Tenant.id == MeteringPoint.tenant_id).where(MeteringPoint.mp_id == mp_id)
    row = (await db.execute(stmt)).first()
    mp, tenant = (row if row else (None, None))

    # Steps 1-3 (unknown object -> tenant check against None, then step 4).
    current = await authorize(
        db,
        token,
        action=action,
        allowed_roles={"kunde", "abrechnung"},
        object_ref=object_ref,
        object_tenant=tenant.code if row else None,
    )
    if not row:
        _deny(current, action=action, object_ref=object_ref, reason="object_not_found")
    assert mp is not None and tenant is not None

    # Step 4: object reference - a customer may only read the metering
    # point linked to their account (ID-Match account <-> metering point).
    if current.role == "kunde" and mp.customer_user_id != current.user_id:
        _deny(current, action=action, object_ref=object_ref, reason="not_own_meter")

    # Step 5: decrypt with context check (Weg b AAD). The data key is
    # unwrapped with the tenant master key and bound to this metering
    # point; every hourly value is additionally bound to its timestamp.
    master_key = get_master_key(tenant.code)
    data_key = crypto.unwrap_data_key(master_key, mp.enc_data_key, f"{tenant.code}:{mp_id}")
    static_context = crypto.build_context(tenant.code, mp_id, "stammdaten")
    name = crypto.decrypt(mp.enc_name, data_key, static_context)
    address = crypto.decrypt(mp.enc_address, data_key, static_context)

    readings = (
        await db.execute(
            select(HourlyReading)
            .where(HourlyReading.metering_point_id == mp.id)
            .order_by(HourlyReading.timestamp)
        )
    ).scalars().all()
    values: list[float] = []
    for reading in readings:
        context = crypto.build_context(tenant.code, mp_id, reading.timestamp)
        try:
            values.append(float(crypto.decrypt(reading.enc_value, data_key, context)))
        except crypto.IntegrityViolation:
            # T5: unlike authorization denials, an integrity violation IS
            # reported with metering point and timestamp - the chain is
            # broken and the reader must see which row failed. The generic
            # client message does not apply here; the raised exception
            # carries the bound context. The audit entry names both too.
            get_audit().log_action(
                tenant=current.tenant_code,
                user=user_pseudonym(current.user_id),
                role=current.role,
                action=action,
                object_ref=f"mp:{mp_id}:{reading.timestamp.isoformat()}",
                result="denied",
                reason="integrity_violation",
            )
            raise

    # Step 6: role-adapted output. For Abrechnung the single values stay
    # inside this function - only the aggregate leaves it.
    if current.role == "kunde":
        result = {
            "mp_id": mp_id,
            "tenant": tenant.code,
            "plz": mp.plz,
            "tariff": mp.tariff,
            "name": name,
            "address": address,
            "hourly_values": [
                {"timestamp": reading.timestamp.isoformat(), "kwh": value}
                for reading, value in zip(readings, values)
            ],
        }
    else:  # abrechnung
        consumption_sum = round(sum(values), 3)
        price = TARIFF_PRICES_EUR.get(mp.tariff, 0.30)
        result = {
            "mp_id": mp_id,
            "name": name,
            "tariff": mp.tariff,
            "consumption_sum_kwh": consumption_sum,
            "amount_eur": round(consumption_sum * price, 2),
            "lastprofil": MASKED_PROFILE,
        }

    # Step 7 (success): audit emitted here, never in the route.
    get_audit().log_action(
        tenant=current.tenant_code,
        user=user_pseudonym(current.user_id),
        role=current.role,
        action=action,
        object_ref=object_ref,
        result="success",
        reason="authorized",
    )
    return result
