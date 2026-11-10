import hashlib
import hmac as hmac_lib
import json as json_lib
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gridvault.config import settings
from gridvault.db import AnalysisExport, HourlyReading, MeteringPoint, Tenant
from gridvault.services import crypto
from gridvault.services.audit import get_audit, user_pseudonym
from gridvault.services.keys import get_hmac_key, get_master_key
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


class CohortTooSmall(Exception):
    """Small-cell rejection (A3): the cohort has n < k metering points.

    Unlike authorization denials, the task REQUIRES the response to state
    n and k - the analyst needs to know how far the cohort is below the
    threshold (n and k are cohort sizes, not personal data).
    """

    def __init__(self, n: int, k: int) -> None:
        self.n = n
        self.k = k
        super().__init__(f"cohort too small: n={n} < k={k}")


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


def _unwrap_data_key(tenant_code: str, mp: MeteringPoint) -> bytes:
    """Per-metering-point data key, unwrapped with the tenant master key."""
    return crypto.unwrap_data_key(
        get_master_key(tenant_code), mp.enc_data_key, f"{tenant_code}:{mp.mp_id}"
    )


async def _load_mp(db: AsyncSession, mp_id: str):
    """Metering point + owning tenant row, or None (object resolution)."""
    stmt = (
        select(MeteringPoint, Tenant)
        .join(Tenant, Tenant.id == MeteringPoint.tenant_id)
        .where(MeteringPoint.mp_id == mp_id)
    )
    return (await db.execute(stmt)).first()


async def _decrypt_hourly(
    db: AsyncSession,
    current: CurrentSession,
    tenant_code: str,
    mp_id: str,
    mp_row_id: int,
    action: str,
) -> tuple[list[HourlyReading], list[float]]:
    """Step 5: unwrap the data key and decrypt every hourly value with
    its context (Weg b). An integrity violation is audited with the
    exact failing row (mp_id + timestamp) and re-raised."""
    mp = await db.get(MeteringPoint, mp_row_id)
    assert mp is not None
    data_key = _unwrap_data_key(tenant_code, mp)
    readings = (
        (
            await db.execute(
                select(HourlyReading)
                .where(HourlyReading.metering_point_id == mp_row_id)
                .order_by(HourlyReading.timestamp)
            )
        )
        .scalars()
        .all()
    )
    values: list[float] = []
    for reading in readings:
        context = crypto.build_context(tenant_code, mp_id, reading.timestamp)
        try:
            values.append(float(crypto.decrypt(reading.enc_value, data_key, context)))
        except crypto.IntegrityViolation:
            # T5: unlike authorization denials, an integrity violation IS
            # reported with metering point and timestamp - the reader must
            # see which row fails. The generic client message does not
            # apply here; the raised exception carries the bound context.
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
    return readings, values


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

    row = await _load_mp(db, mp_id)
    # Steps 1-3 (unknown object -> tenant check against None, then step 4).
    current = await authorize(
        db,
        token,
        action=action,
        allowed_roles={"kunde", "abrechnung"},
        object_ref=object_ref,
        object_tenant=row[1].code if row else None,
    )
    if not row:
        _deny(current, action=action, object_ref=object_ref, reason="object_not_found")
    mp, tenant = row
    assert mp is not None and tenant is not None

    # Step 4: object reference - a customer may only read the metering
    # point linked to their account (ID-Match account <-> metering point).
    if current.role == "kunde" and mp.customer_user_id != current.user_id:
        _deny(current, action=action, object_ref=object_ref, reason="not_own_meter")

    # Step 5: decrypt with context check (Weg b AAD).
    data_key = _unwrap_data_key(tenant.code, mp)
    static_context = crypto.build_context(tenant.code, mp_id, "stammdaten")
    name = crypto.decrypt(mp.enc_name, data_key, static_context)
    address = crypto.decrypt(mp.enc_address, data_key, static_context)
    readings, values = await _decrypt_hourly(
        db, current, tenant.code, mp_id, mp.id, action
    )

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


async def list_meter_points(db: AsyncSession, token: str | None) -> list[dict]:
    """Cleartext directory of metering points via the gateway (A3).

    Abrechnung: all metering points of the own tenant. Kunde: only the
    own one. Output carries ONLY the cleartext fields - names and
    addresses are not decrypted for a directory listing at all (A8,
    data minimization). For a list the tenant check (step 3) and the
    object reference (step 4) collapse into the query scope.
    """
    action = "list_metering_points"
    object_ref = "mp_list"

    current = await authorize(
        db,
        token,
        action=action,
        allowed_roles={"kunde", "abrechnung"},
        object_ref=object_ref,
    )

    stmt = select(MeteringPoint).where(MeteringPoint.tenant_id == current.tenant_id)
    if current.role == "kunde":
        # step 4 for the customer: exactly the own metering point
        stmt = stmt.where(MeteringPoint.customer_user_id == current.user_id)
    rows = (await db.execute(stmt.order_by(MeteringPoint.mp_id))).scalars().all()

    result = [
        {"mp_id": row.mp_id, "tenant": current.tenant_code, "plz": row.plz, "tariff": row.tariff}
        for row in rows
    ]

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


async def list_hourly_readings(
    db: AsyncSession, token: str | None, mp_id: str
) -> list[dict]:
    """Hourly values via the gateway - customer role only (A3/A7).

    Single values are purpose-bound to the customer; every other role is
    denied here (e.g. Abrechnung, which only ever receives the sum).
    """
    action = "read_metering_readings"
    object_ref = f"mp:{mp_id}"

    row = await _load_mp(db, mp_id)
    current = await authorize(
        db,
        token,
        action=action,
        allowed_roles={"kunde"},
        object_ref=object_ref,
        object_tenant=row[1].code if row else None,
    )
    if not row:
        _deny(current, action=action, object_ref=object_ref, reason="object_not_found")
    mp, tenant = row

    if mp.customer_user_id != current.user_id:
        _deny(current, action=action, object_ref=object_ref, reason="not_own_meter")

    readings, values = await _decrypt_hourly(
        db, current, tenant.code, mp_id, mp.id, action
    )
    result = [
        {"timestamp": reading.timestamp.isoformat(), "kwh": value}
        for reading, value in zip(readings, values)
    ]

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


async def _cohort(
    db: AsyncSession, current: CurrentSession, plz: str
) -> list[MeteringPoint]:
    """Cohort = all metering points of one PLZ, scoped to the caller's
    tenant only (steps 3+4 for a cohort collapse into the query scope:
    foreign-tenant points are never part of any cohort the caller sees)."""
    rows = await db.execute(
        select(MeteringPoint)
        .where(
            MeteringPoint.tenant_id == current.tenant_id,
            MeteringPoint.plz == plz,
        )
        .order_by(MeteringPoint.mp_id)
    )
    return list(rows.scalars().all())


def _require_cohort_size(
    current: CurrentSession,
    mps: list[MeteringPoint],
    *,
    action: str,
    object_ref: str,
    k: int,
) -> None:
    """Small-cell protection (A3): cohorts with n < k are rejected WITH
    disclosure of n and k (task wording), after being audited."""
    n = len(mps)
    if n >= k:
        return
    get_audit().log_action(
        tenant=current.tenant_code,
        user=user_pseudonym(current.user_id),
        role=current.role,
        action=action,
        object_ref=object_ref,
        result="denied",
        reason="cohort_too_small",
    )
    raise CohortTooSmall(n, k)


def _pseudonym(tenant_code: str, mp_id: str) -> str:
    """HMAC-SHA256 over the metering point ID with the per-tenant
    pseudonym key (NOT the master key): stable across exports, but not
    guessable without the key. A plain SHA-256 would be reversible by
    simply guessing metering point IDs (rainbow table) - noted for B2.
    """
    key = get_hmac_key(tenant_code)
    return hmac_lib.new(key, mp_id.encode("utf-8"), hashlib.sha256).hexdigest()


async def cohort_hourly_sum(
    db: AsyncSession, token: str | None, plz: str
) -> dict:
    """Hourly cohort sum for the Netzanalyst role (A3, B4/T3).

    Output is ONLY the hourly sum over the whole cohort - never names,
    never single values of a household (single values stay inside this
    function).
    """
    action = "read_cohort_hourly_sum"
    object_ref = f"plz:{plz}"
    k = settings.cohort_k

    current = await authorize(
        db,
        token,
        action=action,
        allowed_roles={"netzanalyst"},
        object_ref=object_ref,
    )
    mps = await _cohort(db, current, plz)
    _require_cohort_size(current, mps, action=action, object_ref=object_ref, k=k)

    # Step 5: decrypt every member with context check, step 6: aggregate
    # per hour. Individual household values never leave this function.
    sums: dict[object, float] = {}
    for mp in mps:
        readings, values = await _decrypt_hourly(
            db, current, current.tenant_code, mp.mp_id, mp.id, action
        )
        for reading, value in zip(readings, values):
            sums[reading.timestamp] = sums.get(reading.timestamp, 0.0) + value

    result = {
        "plz": plz,
        "n": len(mps),
        "k": k,
        "hourly_sums": [
            {"timestamp": ts.isoformat(), "sum_kwh": round(v, 3)}
            for ts, v in sorted(sums.items())
        ],
    }

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


async def export_cohort(
    db: AsyncSession, token: str | None, plz: str
) -> dict:
    """Pseudonymized cohort export for the analysis environment (A3).

    Replaces metering point IDs with HMAC pseudonyms (per-tenant key,
    NOT the master key). The export row carries a retention date for
    the M9 deletion run. The small-cell rule applies here too: a small
    cohort export would enable exactly the re-identification the sum
    queries prevent.
    """
    action = "export_cohort"
    object_ref = f"plz:{plz}"
    k = settings.cohort_k

    current = await authorize(
        db,
        token,
        action=action,
        allowed_roles={"netzanalyst"},
        object_ref=object_ref,
    )
    mps = await _cohort(db, current, plz)
    _require_cohort_size(current, mps, action=action, object_ref=object_ref, k=k)

    series = []
    for mp in mps:
        _readings, values = await _decrypt_hourly(
            db, current, current.tenant_code, mp.mp_id, mp.id, action
        )
        series.append(
            {
                "pseudonym": _pseudonym(current.tenant_code, mp.mp_id),
                "hourly_kwh": [round(v, 3) for v in values],
            }
        )

    payload = {"plz": plz, "pseudonymized_series": series}
    now = datetime.now(UTC).replace(tzinfo=None)
    export_row = AnalysisExport(
        tenant_id=current.tenant_id,
        plz=plz,
        created_by_user_id=current.user_id,
        created_at=now,
        retention_until=now + timedelta(days=settings.export_retention_days),
        payload=json_lib.dumps(payload).encode("utf-8"),
    )
    db.add(export_row)
    await db.commit()

    result = {
        "export_id": export_row.id,
        "plz": plz,
        "n": len(mps),
        "k": k,
        "created_at": now.isoformat(),
        "retention_until": export_row.retention_until.isoformat(),
        "pseudonymized_series": series,
    }

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
