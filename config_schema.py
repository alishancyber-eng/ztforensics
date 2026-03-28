"""
config_schema.py – Pydantic v2 configuration model for ZTForensics.

Validates all environment variables with type checking, URL format
validation, conditional requirements, and sensible defaults.

Usage:
    from config_schema import Settings
    settings = Settings()           # reads from environment / .env
    print(settings.keycloak_realm)

Or from the command line (prints the resolved config as JSON):
    python config_schema.py
"""
from __future__ import annotations

import os
from typing import Literal, Optional

from pydantic import (
    AnyHttpUrl,
    Field,
    NonNegativeFloat,
    PositiveInt,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All ZTForensics runtime configuration settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ----------------------------------------------------------------
    # Keycloak
    # ----------------------------------------------------------------
    keycloak_server_url: AnyHttpUrl = Field(
        default="http://localhost:8080",
        description="Base URL of the Keycloak server.",
    )
    keycloak_realm: str = Field(
        default="forensics",
        min_length=1,
        description="Keycloak realm name.",
    )
    keycloak_client_id: str = Field(
        default="api-gateway",
        min_length=1,
        description="Keycloak client ID.",
    )
    keycloak_client_secret: str = Field(
        default="",
        description="Keycloak client secret (required for confidential clients).",
    )
    keycloak_admin_user: str = Field(
        default="admin",
        description="Keycloak admin username.",
    )
    keycloak_admin_password: str = Field(
        default="admin123",
        description="Keycloak admin password.",
    )

    # ----------------------------------------------------------------
    # API Gateway
    # ----------------------------------------------------------------
    api_gateway_host: str = Field(default="0.0.0.0", description="Bind host.")
    api_gateway_port: PositiveInt = Field(default=8000, description="Bind port.")
    api_gateway_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
    )
    jwt_algorithm: str = Field(default="RS256", description="JWT signing algorithm.")
    token_expiration: PositiveInt = Field(
        default=3600,
        description="JWT token expiration in seconds.",
    )

    # ----------------------------------------------------------------
    # Database
    # ----------------------------------------------------------------
    database_url: str = Field(
        default="postgresql://ztf:ztfpass@ztf-postgres:5432/ztfdb",
        description="SQLAlchemy database URL.",
    )
    database_pool_size: PositiveInt = Field(default=10)
    database_pool_recycle: PositiveInt = Field(default=3600)

    # ----------------------------------------------------------------
    # MinIO
    # ----------------------------------------------------------------
    minio_endpoint: str = Field(
        default="ztf-minio:9000",
        description="MinIO endpoint in host:port format.",
    )
    minio_access_key: str = Field(default="minioadmin")
    minio_secret_key: str = Field(default="minioadmin123")
    minio_bucket: str = Field(default="forensics-evidence")

    # ----------------------------------------------------------------
    # OPA
    # ----------------------------------------------------------------
    opa_url: AnyHttpUrl = Field(
        default="http://ztf-opa:8181",
        description="Open Policy Agent base URL.",
    )
    opa_policy_path: str = Field(default="/policies")

    # ----------------------------------------------------------------
    # Dashboard
    # ----------------------------------------------------------------
    dashboard_host: str = Field(default="0.0.0.0")
    dashboard_port: PositiveInt = Field(default=5000)
    api_gateway_url: AnyHttpUrl = Field(
        default="http://ztf-api:8000",
        description="Internal API Gateway URL used by the dashboard.",
    )
    keycloak_login_url: Optional[AnyHttpUrl] = Field(
        default=None,
        description="Keycloak authorization endpoint URL shown to users.",
    )

    # ----------------------------------------------------------------
    # Security
    # ----------------------------------------------------------------
    secret_key: str = Field(
        default="your-secret-key-change-in-production",
        min_length=8,
        description="Application secret key – must be changed in production.",
    )
    debug: bool = Field(default=False)
    cors_origins: str = Field(
        default="http://localhost:5000,http://localhost:8000",
        description="Comma-separated list of allowed CORS origins, or '*'.",
    )

    # ----------------------------------------------------------------
    # Logging
    # ----------------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
    )
    log_format: Literal["json", "text"] = Field(default="json")

    # ----------------------------------------------------------------
    # Validators
    # ----------------------------------------------------------------
    @field_validator("minio_endpoint")
    @classmethod
    def validate_minio_endpoint(cls, v: str) -> str:
        """Endpoint must be in host:port format."""
        if "://" in v:
            msg = "minio_endpoint should be host:port (without scheme), e.g. 'minio:9000'"
            raise ValueError(msg)
        parts = v.rsplit(":", 1)
        if len(parts) != 2:
            msg = "minio_endpoint must include a port, e.g. 'minio:9000'"
            raise ValueError(msg)
        port_str = parts[1]
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            msg = f"minio_endpoint port '{port_str}' is not a valid port number"
            raise ValueError(msg)
        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Must start with a known SQLAlchemy dialect."""
        known = ("postgresql", "sqlite", "mysql", "mssql")
        if not any(v.startswith(prefix) for prefix in known):
            msg = f"database_url must start with one of: {', '.join(known)}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def warn_insecure_defaults(self) -> "Settings":
        """Raise if production-unsafe defaults are used with DEBUG=False."""
        if not self.debug:
            insecure: list[str] = []
            if self.secret_key == "your-secret-key-change-in-production":
                insecure.append("SECRET_KEY is still the example value")
            if self.cors_origins.strip() == "*":
                insecure.append("CORS_ORIGINS=* is insecure for production")
            if insecure:
                import warnings
                for msg in insecure:
                    warnings.warn(
                        f"[config_schema] Security warning: {msg}",
                        UserWarning,
                        stacklevel=2,
                    )
        return self

    # ----------------------------------------------------------------
    # Convenience properties
    # ----------------------------------------------------------------
    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS_ORIGINS as a Python list."""
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def keycloak_realm_url(self) -> str:
        """Return the full Keycloak realm base URL."""
        return f"{self.keycloak_server_url}/realms/{self.keycloak_realm}"

    @property
    def keycloak_jwks_url(self) -> str:
        """Return the Keycloak JWKS endpoint URL."""
        return f"{self.keycloak_realm_url}/protocol/openid-connect/certs"


# Allow running as a script to inspect current settings
if __name__ == "__main__":
    import json

    s = Settings()
    print(json.dumps(s.model_dump(mode="json"), indent=2, default=str))
