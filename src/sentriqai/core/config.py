from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentriqAI"
    environment: Literal["development", "testing", "production"] = "development"
    debug: bool = True

    database_url: str

    jwt_secret_key: str
    jwt_algorithm: Literal["HS256"] = "HS256"
    access_token_expire_minutes: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
