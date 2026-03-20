from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"

    database_url: str = "postgresql://ztforensics:change_me@postgres:5432/forensics_db"
    opa_url: str = "http://opa:8181"

    jwt_issuer: str = "https://example-issuer.com/"
    jwt_audience: str = "ztforensics-api"
    jwt_jwks_url: str = "https://example-issuer.com/.well-known/jwks.json"
    jwt_algorithms: str = "RS256"


settings = Settings()