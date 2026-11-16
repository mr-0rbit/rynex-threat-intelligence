"""Application configuration via environment variables. No secrets in code."""

import ipaddress
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Rynex Threat Intelligence Platform"
    APP_TAGLINE: str = "DETECT. ANALYZE. RESPOND."
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./rtip.db"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Auth
    JWT_SECRET_KEY: str = "CHANGE_ME_in_production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Initial admin bootstrap (first run only)
    ADMIN_EMAIL: str = "admin@rynex.local"
    ADMIN_PASSWORD: str = "ChangeMeNow!2024"
    DEFAULT_ORGANIZATION_NAME: str = "Default Organization"

    # Notifications
    TELEGRAM_BOT_TOKEN: str | None = None
    TELEGRAM_CHAT_ID: str | None = None
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM: str | None = None
    WEBHOOK_URL: str | None = None

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Collector HTTP behaviour
    COLLECTOR_TIMEOUT_SECONDS: float = 30.0
    COLLECTOR_MAX_RETRIES: int = 3
    COLLECTOR_BACKOFF_BASE: float = 2.0
    COLLECTOR_USER_AGENT: str = "RTIP/0.1 (+https://rynex.tech; threat-intel-platform)"

    # SSRF protection for user-configurable feeds
    ALLOW_PRIVATE_NETWORK_SOURCES: bool = False

    # Auth hardening
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_LOGIN_MAX_ATTEMPTS: int = 10  # per IP per window
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: int = 300
    # Comma-separated proxy CIDRs. Forwarded headers are ignored unless the
    # direct peer belongs to one of these trusted proxy networks.
    TRUSTED_PROXY_CIDRS: str = ""

    # Data retention (days); 0 disables the cleanup task
    RETENTION_COLLECTION_JOBS_DAYS: int = 90

    # Optional NVD enrichment (API key raises the rate limit; free at https://nvd.nist.gov/developers/request-an-api-key)
    NVD_API_KEY: str | None = None
    NVD_MAX_AGE_DAYS: int = 7

    # Enterprise Distributed Event Bus
    REDIS_ALERT_CHANNEL: str = "rtip:events:alerts"

    # Enterprise Single Sign-On (OIDC / OAuth2)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER_URL: str | None = None
    OIDC_CLIENT_ID: str | None = None
    OIDC_CLIENT_SECRET: str | None = None
    OIDC_REDIRECT_URI: str | None = None
    OIDC_SCOPES: str = "openid profile email"
    OIDC_DEFAULT_ROLE: str = "viewer"
    OIDC_ORGANIZATION_SLUG: str = "default"
    OIDC_STATE_COOKIE_NAME: str = "rtip_oidc_state"

    # Enterprise Audit Integrity
    AUDIT_HMAC_KEY: str = "audit-hmac-secret-key-change-in-production"

    # TAXII 2.1 Specification
    TAXII_ENABLED: bool = True
    TAXII_TITLE: str = "RTIP TAXII 2.1 Server"
    TAXII_DESCRIPTION: str = "Rynex Threat Intelligence Platform OASIS TAXII 2.1 Server"
    TAXII_MAX_CONTENT_LENGTH: int = 10485760  # 10 MB

    # Multi-tenancy & Organization Scoping
    MULTI_TENANCY_ENABLED: bool = True

    # IOC Lifecycle & Decay Engine
    IOC_DECAY_ENABLED: bool = True
    IOC_DECAY_IP_DAYS: int = 30
    IOC_DECAY_DOMAIN_DAYS: int = 60

    @model_validator(mode="after")
    def validate_production_secrets(self):
        if self.ENVIRONMENT.lower() != "production":
            self._validate_trusted_proxies()
            self._validate_oidc_role()
            return self

        placeholders = ("change_me", "changethis", "change-this", "example", "password2025")
        if self.DEBUG:
            raise ValueError("DEBUG must be false in production")
        if not self.DATABASE_URL.startswith(("postgresql+asyncpg://", "postgresql+psycopg://")):
            raise ValueError("Production DATABASE_URL must use an async PostgreSQL driver")
        if "*" in self.CORS_ORIGINS:
            raise ValueError("Wildcard CORS origins are not allowed in production")
        required_secrets = {
            "JWT_SECRET_KEY": self.JWT_SECRET_KEY,
            "AUDIT_HMAC_KEY": self.AUDIT_HMAC_KEY,
            "ADMIN_PASSWORD": self.ADMIN_PASSWORD,
        }
        for name, value in required_secrets.items():
            normalized = value.strip().lower()
            if len(value) < 32 or any(marker in normalized for marker in placeholders):
                raise ValueError(f"{name} must be set to a strong, unique production secret")
        if self.JWT_SECRET_KEY == self.AUDIT_HMAC_KEY:
            raise ValueError("JWT_SECRET_KEY and AUDIT_HMAC_KEY must be different secrets")
        if self.OIDC_ENABLED:
            oidc_values = (
                self.OIDC_ISSUER_URL,
                self.OIDC_CLIENT_ID,
                self.OIDC_CLIENT_SECRET,
                self.OIDC_REDIRECT_URI,
            )
            if not all(value and value.strip() for value in oidc_values):
                raise ValueError("OIDC_ENABLED requires issuer, client ID/secret, and redirect URI")
            if not self.OIDC_ISSUER_URL.startswith("https://"):
                raise ValueError("Production OIDC issuer must use HTTPS")
            if not self.OIDC_REDIRECT_URI.startswith("https://"):
                raise ValueError("Production OIDC redirect URI must use HTTPS")
        if self.TAXII_MAX_CONTENT_LENGTH < 1024:
            raise ValueError("TAXII_MAX_CONTENT_LENGTH must be at least 1024 bytes")
        self._validate_trusted_proxies()
        self._validate_oidc_role()
        return self

    def _validate_trusted_proxies(self) -> None:
        for value in self.TRUSTED_PROXY_CIDRS.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid TRUSTED_PROXY_CIDRS entry: {value}") from exc
            if network.prefixlen == 0:
                raise ValueError("TRUSTED_PROXY_CIDRS must not trust all IP addresses")

    def _validate_oidc_role(self) -> None:
        if self.OIDC_DEFAULT_ROLE not in {
            "soc_lead",
            "analyst",
            "triage",
            "auditor",
            "viewer",
        }:
            raise ValueError("OIDC_DEFAULT_ROLE must be a supported least-privilege role")



@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
