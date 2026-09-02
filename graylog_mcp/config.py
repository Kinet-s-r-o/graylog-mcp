from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_path: str = "/mcp"
    ui_username: str = "admin"
    ui_password: str
    log_level: str = "INFO"
    graylog_url: str
    graylog_username: str
    graylog_password: str
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

    @property
    def normalized_graylog_url(self) -> str:
        return self.graylog_url.rstrip("/")
