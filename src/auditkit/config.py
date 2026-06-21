from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    opencode_api_key: str = ""
    opencode_base_url: str = "https://opencode.ai/zen/go/v1"
    opencode_model: str = "deepseek-v4-pro"
    opencode_model_light: str = "deepseek-v4-flash"


settings = Settings()
