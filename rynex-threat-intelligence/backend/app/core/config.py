"""Application configuration via environment variables. No secrets in code."""

from functools import lru_cache

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

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Collector HTTP behaviour
    COLLECTOR_TIMEOUT_SECONDS: float = 30.0
    COLLECTOR_MAX_RETRIES: int = 3
    COLLECTOR_BACKOFF_BASE: float = 2.0
    COLLECTOR_USER_AGENT: str = "RTIP/0.1 (+https://rynex.tech; threat-intel-platform)"

    # SSRF protection for user-configurable feeds
    ALLOW_PRIVATE_NETWORK_SOURCES: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
