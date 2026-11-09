from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    """A Stadtwerk acting as a tenant (mandant). At least two exist (A1)."""

    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(10), unique=True)  # e.g. "SWN", "SWB"
    name: Mapped[str] = mapped_column(String(100))


class User(Base):
    """A user belonging to exactly one tenant (A1).

    password_hash stores an Argon2 hash (salt embedded by the algorithm);
    there is no separate salt column and no plaintext or reversible form.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    role: Mapped[str] = mapped_column(String(20)) #kunde, abrechnung, netzanalyst, stoerungsdienst, leitstelle
    is_active: Mapped[bool] = mapped_column(default=True)


class Session(Base):
    """Server-side session created at login (A1, routes /auth/*).

    Holds user ID, tenant, role and expiry. Only a hash of the session token
    is stored, never the token itself.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]


class MeteringPoint(Base):
    """A metering point (Zaehlpunkt), owned by one tenant (A2, A3).

    Cleartext: mp_id, tenant, plz, tariff
    Encrypted: name, address, per-data-key

    Why exactly these stay cleartext (A2): mp_id/tenant_id are technical
    routing identifiers needed to locate and separate rows before any
    decryption; plz enables cohort queries (A3) without crypto access and
    is region-level, not unique to a person; tariff is a product parameter,
    not personal data. None of them reveal identity or behaviour on their
    own - unlike name/address (direct identifiers) and the hourly values
    (presence profile), which stay encrypted.
    """

    __tablename__ = "metering_points"

    id: Mapped[int] = mapped_column(primary_key=True)

    # This data is not personal data and therefore does not need to be encrypted
    mp_id: Mapped[str] = mapped_column(String(50), index=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    plz: Mapped[str] = mapped_column(String(5), index=True) 
    tariff: Mapped[str] = mapped_column(String(30)) 

    enc_name: Mapped[bytes] 
    enc_address: Mapped[bytes]

    # Data Key for encryption
    enc_data_key: Mapped[bytes]

    customer_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )


class HourlyReading(Base):
    """A single hourly consumption value (A2).

    Timestamp and metering_point_id stay cleartext: they are the row
    identity needed to build the AAD context (Weg b) before decryption.
    The consumption value itself is always ciphertext.
    """

    __tablename__ = "hourly_readings"

    id: Mapped[int] = mapped_column(primary_key=True)
    metering_point_id: Mapped[int] = mapped_column(
        ForeignKey("metering_points.id"), index=True
    )
    timestamp: Mapped[datetime]
    enc_value: Mapped[bytes] 
    retention_until: Mapped[datetime | None] = mapped_column(nullable=True)

    __table_args__ = (
        UniqueConstraint("metering_point_id", "timestamp", name="uq_reading_point_time"),
    )


class ApprovalRequest(Base):
    """Outage approval request with the four-eyes workflow (A4, routes /outages/*)"""

    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    requesting_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    plz: Mapped[str] = mapped_column(String(5))
    ticket_number: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(String(1000)) 
    state: Mapped[str] = mapped_column(String(15), default="offen")
    granted_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime]
    valid_until: Mapped[datetime | None] = mapped_column(nullable=True)


class AnalysisExport(Base):
    """A pseudonymised cohort export for the analysis environment (A3, A6).

    payload contains only HMAC pseudonyms and hourly sums, never names.
    retention_until supports the deletion run (A6).
    """

    __tablename__ = "analysis_exports"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"))
    plz: Mapped[str] = mapped_column(String(5))
    created_by_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime]
    retention_until: Mapped[datetime]
    payload: Mapped[bytes]


class DeletionRun(Base):
    """Bookkeeping for a configurable deletion run (A6, route /admin/deletion-run).

    Records counts and exceptions only - never deleted content (A8).
    """

    __tablename__ = "deletion_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    loads_deleted: Mapped[int] = mapped_column(default=0)
    exports_deleted: Mapped[int] = mapped_column(default=0)
    retention_exceptions: Mapped[str] = mapped_column(
        default=""
    )  # comma-separated reasons
