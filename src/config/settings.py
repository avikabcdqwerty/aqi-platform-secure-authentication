import os
from typing import List

class Settings:
    """
    Centralized configuration for secrets, TLS, rate limits, and environment variables.
    Loads from environment variables for security and flexibility.
    """

    # Application
    HOST: str = os.getenv("AQI_API_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("AQI_API_PORT", "8000"))
    DEBUG: bool = os.getenv("AQI_API_DEBUG", "false").lower() == "true"

    # TLS/HTTPS
    ENFORCE_HTTPS: bool = os.getenv("AQI_API_ENFORCE_HTTPS", "true").lower() == "true"
    SSL_KEYFILE: str = os.getenv("AQI_API_SSL_KEYFILE", "")
    SSL_CERTFILE: str = os.getenv("AQI_API_SSL_CERTFILE", "")
    TLS_VERIFY: bool = os.getenv("AQI_API_TLS_VERIFY", "true").lower() == "true"

    # CORS
    ALLOWED_ORIGINS: List[str] = os.getenv("AQI_API_ALLOWED_ORIGINS", "https://research.example.com").split(",")

    # JWT
    JWT_ALGORITHMS: List[str] = os.getenv("AQI_JWT_ALGORITHMS", "RS256").split(",")
    JWT_AUDIENCE: str = os.getenv("AQI_JWT_AUDIENCE", "aqi-platform")
    JWT_PUBLIC_KEYS_ENV: str = os.getenv("AQI_JWT_PUBLIC_KEYS_ENV", "AQI_JWT_PUBLIC_KEYS")
    JWT_PRIVATE_KEY_ENV: str = os.getenv("AQI_JWT_PRIVATE_KEY_ENV", "AQI_JWT_PRIVATE_KEY")
    ALLOWED_ROLES: List[str] = os.getenv("AQI_ALLOWED_ROLES", "researcher,admin").split(",")

    # OAuth2
    OAUTH2_INTROSPECTION_URL: str = os.getenv("AQI_OAUTH2_INTROSPECTION_URL", "https://auth.example.com/introspect")
    OAUTH2_CLIENT_ID: str = os.getenv("AQI_OAUTH2_CLIENT_ID", "")
    OAUTH2_CLIENT_SECRET: str = os.getenv("AQI_OAUTH2_CLIENT_SECRET", "")

    # Vault/KMS
    VAULT_ENABLED: bool = os.getenv("AQI_VAULT_ENABLED", "false").lower() == "true"
    VAULT_ADDR: str = os.getenv("AQI_VAULT_ADDR", "")
    VAULT_TOKEN: str = os.getenv("AQI_VAULT_TOKEN", "")
    VAULT_JWT_PUBLIC_KEYS_PATH: str = os.getenv("AQI_VAULT_JWT_PUBLIC_KEYS_PATH", "secret/data/aqi/jwt/public")
    VAULT_JWT_PRIVATE_KEY_PATH: str = os.getenv("AQI_VAULT_JWT_PRIVATE_KEY_PATH", "secret/data/aqi/jwt/private")

    # Redis (rate limiting, lockout)
    REDIS_URL: str = os.getenv("AQI_REDIS_URL", "redis://localhost:6379/0")
    AUTH_FAILED_ATTEMPTS_LIMIT: int = int(os.getenv("AQI_AUTH_FAILED_ATTEMPTS_LIMIT", "5"))
    AUTH_LOCKOUT_TTL: int = int(os.getenv("AQI_AUTH_LOCKOUT_TTL", "900"))  # seconds
    AUTH_RATE_LIMIT_TTL: int = int(os.getenv("AQI_AUTH_RATE_LIMIT_TTL", "300"))  # seconds

def get_settings() -> Settings:
    """
    Returns a singleton Settings instance.
    """
    # Singleton pattern for settings
    global _settings_instance
    try:
        return _settings_instance
    except NameError:
        _settings_instance = Settings()
        return _settings_instance

__all__ = ["Settings", "get_settings"]