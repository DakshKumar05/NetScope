from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NES_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./network_scanner.db"
    allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Scanner defaults. Deliberately conservative.
    default_timeout: float = 1.0
    default_concurrency: int = 100
    max_concurrency: int = 500
    max_ports_per_scan: int = 8000
    max_hosts_per_scan: int = 512
    # Ceiling on connection attempts per second across a whole scan.
    rate_limit_per_second: int = 400

    banner_read_bytes: int = 2048
    http_timeout: float = 4.0

    # Vulnerability providers.
    osv_api_url: str = "https://api.osv.dev/v1/query"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""
    vuln_cache_ttl_seconds: int = 21600
    vuln_lookups_enabled: bool = True

    # Guard rail: refuse targets outside private ranges unless explicitly allowed.
    allow_public_targets: bool = False

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
