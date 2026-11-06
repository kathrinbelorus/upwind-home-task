"""Runtime settings, read from environment variables (or a local .env file)."""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Shared secret between the add-on and the backend. Required: the app
    # refuses to start without it instead of running unauthenticated.
    api_key: SecretStr = Field(min_length=16)
    enable_docs: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
