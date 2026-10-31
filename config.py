"""Validated environment configuration; secrets are never included in logs."""
from typing import Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIEM_", env_file=".env", extra="ignore")
    redis_url: SecretStr
    elasticsearch_url: str
    elasticsearch_api_key: SecretStr
    ingest_api_key: SecretStr | None = None  # Deprecated; never grants access.
    webhook_url: SecretStr
    webhook_signing_secret: SecretStr
    dashboard_api_key: SecretStr | None = None
    identity_db_path: str = "data/identities.sqlite3"
    public_origin: str | None = None
    allow_insecure_local: bool = False
    ca_certs: str | None = None
    login_actions: frozenset[str] = frozenset({"user_login", "login", "logon"})
    max_body_bytes: int = Field(default=2_000_000, ge=1024, le=10_000_000)
    max_batch: int = Field(default=200, ge=1, le=500)
    queue_capacity: int = Field(default=100_000, ge=1000)
    bulk_size: int = Field(default=200, ge=1, le=1000)
    reclaim_idle_ms: int = Field(default=120_000, ge=60_000)
    shutdown_seconds: int = Field(default=30, ge=1, le=120)
    webhook_attempts: int = Field(default=6, ge=1, le=10)
    dedup_seconds: int = Field(default=86400, ge=3600)

    @model_validator(mode="after")
    def security(self) -> Self:
        optional = tuple(s for s in (self.dashboard_api_key, self.ingest_api_key) if s is not None)
        for secret in (self.elasticsearch_api_key, self.webhook_signing_secret, *optional):
            if secret.get_secret_value().strip().upper().startswith("REPLACE"):
                raise ValueError("Replace all placeholder secrets before starting")
        for secret in (self.webhook_signing_secret, *optional):
            value = secret.get_secret_value()
            if not self.allow_insecure_local and len(set(value)) < 2:
                raise ValueError("Repeated-character secrets are forbidden outside local mode")
            if len(value) < 32:
                raise ValueError("Authentication and signing keys must have at least 32 characters")
        for raw, schemes in (
            (self.redis_url.get_secret_value(), {"redis", "rediss"}),
            (self.elasticsearch_url, {"http", "https"}),
            (self.webhook_url.get_secret_value(), {"http", "https"}),
        ):
            parsed = urlsplit(raw)
            if parsed.scheme not in schemes or not parsed.hostname or parsed.fragment:
                raise ValueError("Invalid service URL")
            if not self.allow_insecure_local and parsed.scheme not in {"https", "rediss"}:
                raise ValueError("TLS is required; insecure mode is for isolated local testing only")
        if self.public_origin:
            origin = urlsplit(self.public_origin)
            if (origin.scheme != "https" or not origin.hostname or origin.path or origin.query
                    or origin.fragment or origin.username or origin.password):
                raise ValueError("SIEM_PUBLIC_ORIGIN must be an HTTPS origin without path, credentials or trailing slash")
        if not self.allow_insecure_local and not self.public_origin:
            raise ValueError("Set SIEM_PUBLIC_ORIGIN for shared deployments")
        return self
