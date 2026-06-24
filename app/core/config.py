from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "PhishSniffer"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    DATABASE_URL: str = "sqlite+aiosqlite:///./phishsniffer.db"

    VIRUSTOTAL_API_KEY: str
    ABUSEIPDB_API_KEY: str
    URLSCAN_API_KEY: str
    GOOGLE_SAFE_BROWSING_API_KEY: str
    GROQ_API_KEY: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()