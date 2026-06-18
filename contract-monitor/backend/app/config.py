from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ENV_FILE_PATH = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    rpc_url: str
    polling_interval_seconds: int = 30
    start_block: int | None = None

    # Scanner loop RPC retry/backoff behavior.
    rpc_backoff_base_seconds: float = 2.0
    rpc_backoff_max_seconds: float = 120.0
    rpc_backoff_jitter_seconds: float = 1.0
    rpc_log_every_n_errors: int = 10

    # Optional provider keys used to auto-build RPC URL when only base URL is provided.
    infura_api_key: str | None = None
    alchemy_api_key: str | None = None
    rpc_url_bnb_chain: str | None = None
    rpc_url_polygon: str | None = None
    rpc_url_arbitrum: str | None = None
    rpc_url_base: str | None = None
    rpc_url_optimism: str | None = None
    rpc_url_avalanche: str | None = None

    # Solana adapter settings.
    solana_rpc_url: str = "https://api.mainnet-beta.solana.com"
    solscan_token: str | None = None
    cargo_audit_cmd: str = "cargo-audit"

    # Tool locations can be plain command names if available in PATH.
    slither_cmd: str = "slither"
    mythril_cmd: str = "myth"
    echidna_cmd: str = "echidna"

    # Optional source fetch settings for Slither/Echidna runs.
    etherscan_api_key: str | None = None
    etherscan_base_url: str = "https://api.etherscan.io/api"
    etherscan_chain_id: str = "1"
    profile_cache_ttl_seconds: int = 900
    profile_refresh_backoff_seconds: int = 90
    protocol_scan_max_contracts: int = 50

    # CoinMarketCap discovery settings (protocol discovery helper API).
    cmc_api_key: str | None = None
    cmc_keyless_dex_search_url: str = "https://api.coinmarketcap.com/x402/v1/dex/search"
    cmc_timeout_seconds: int = 20

    # Telegram output.
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None

    # Optional generic webhook for downstream systems.
    alert_webhook_url: str | None = None

    # Persistence.
    sqlite_path: str = "./data/monitor.db"

    model_config = SettingsConfigDict(
        env_file=ENV_FILE_PATH,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("start_block", mode="before")
    @classmethod
    def _blank_start_block_as_none(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @model_validator(mode="after")
    def _normalize_rpc_url(self) -> "Settings":
        # Convenience: allow RPC_URL base and append provider key automatically.
        if self.rpc_url.endswith("/v2/") and self.alchemy_api_key:
            self.rpc_url = f"{self.rpc_url}{self.alchemy_api_key}"
        elif self.rpc_url.endswith("/v3/") and self.infura_api_key:
            self.rpc_url = f"{self.rpc_url}{self.infura_api_key}"
        elif self.rpc_url in {"", "https://eth-mainnet.g.alchemy.com/v2/"} and self.alchemy_api_key:
            self.rpc_url = f"https://eth-mainnet.g.alchemy.com/v2/{self.alchemy_api_key}"
        elif self.rpc_url in {"", "https://mainnet.infura.io/v3/"} and self.infura_api_key:
            self.rpc_url = f"https://mainnet.infura.io/v3/{self.infura_api_key}"
        return self
