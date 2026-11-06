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

    # Optional. Without a key the AI assessment is skipped and the rules run alone.
    gemini_api_key: SecretStr | None = None
    # A small, fast model is enough for a capped classification signal.
    gemini_model: str = "gemini-3.5-flash-lite"


@lru_cache
def get_settings() -> Settings:
    return Settings()
