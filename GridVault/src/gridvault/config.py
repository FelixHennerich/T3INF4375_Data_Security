from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite+aiosqlite:///./gridvault.db"

    key_dir: str = "keys"
    hmac_key_dir: str = "hmac_keys"

    audit_log_path: str = "audit_trail.log"
    audit_anchor_dir: str = "audit_anchor"

    session_ttl_minutes: int = 30


    cohort_k: int = 3

    export_retention_days: int = 90

    # Outages
    grant_validity_minutes: int = 30
    outage_reason_min_length: int = 20


settings = Settings()
