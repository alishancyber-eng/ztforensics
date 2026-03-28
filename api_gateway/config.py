from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    opa_url: str = "http://opa:8181"

    postgres_user: str = "ztforensics"
    postgres_password: str = "change_me_strong_password"
    postgres_db: str = "forensics_db"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def database_url(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()