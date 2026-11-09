from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite+aiosqlite:///./gridvault.db"

    key_dir: str = "keys"

    audit_log_path: str = "audit_trail.log"
    audit_anchor_dir: str = "audit_anchor"


settings = Settings()
