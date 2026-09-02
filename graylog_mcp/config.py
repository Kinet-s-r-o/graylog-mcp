from pathlib import Path
from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_path: str = "/mcp"
    ui_username: str = "admin"
    ui_password: SecretStr
    ui_session_ttl_seconds: int = 8 * 60 * 60
    ui_max_sessions: int = 1000
    ui_login_max_attempts: int = 5
    ui_login_window_seconds: int = 15 * 60
    ui_login_max_clients: int = 10_000
    ui_cookie_secure: bool = False
    trusted_proxy_cidrs: str = ""
    secret_encryption_key: SecretStr | None = None
    log_level: str = "INFO"
    # Kept optional for backwards-compatible .env files. Graylog servers are
    # now managed in SQLite through the admin UI.
    graylog_url: str | None = None
    graylog_api_token: str | None = None
    graylog_verify_tls: bool = True
    graylog_timeout_seconds: float = 30
    graylog_default_limit: int = 100
    graylog_max_limit: int = 1000
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str | None = None
    openai_max_tool_rounds: int = 5
    query_catalog_path: Path = Path("queries.yaml")
    audit_db_path: Path = Path("/data/audit.db")
    audit_retention_days: int = 30
    audit_max_rows: int = 100000
    audit_max_payload_chars: int = 100000
    audit_redact_fields: str = "authorization,api_key,api_token,password,secret,token"

    @field_validator("secret_encryption_key", mode="before")
    @classmethod
    def validate_secret_encryption_key(cls, value):
        if value is None or value == "":
            return None
        raw = value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        if len(raw) < 32:
            raise ValueError("SECRET_ENCRYPTION_KEY must contain at least 32 characters")
        return value

    @property
    def normalized_graylog_url(self) -> str | None:
        return self.graylog_url.rstrip("/") if self.graylog_url else None

    @property
    def trusted_proxy_networks(self) -> tuple[str, ...]:
        return tuple(item for item in self.trusted_proxy_cidrs.replace(",", " ").split() if item)

    @property
    def audit_redacted_field_names(self) -> set[str]:
        return {item.strip().lower() for item in self.audit_redact_fields.split(",") if item.strip()}
