from __future__ import annotations

from dataclasses import dataclass

from .models import DiscoveredContract, ScanResult
from .scanners import AnalysisRunner
from .solana_scanner import SolanaAnalysisRunner


@dataclass(frozen=True)
class ChainAdapterConfig:
    chain: str
    rpc_url: str | None
    explorer_chain_id: str


class BaseChainScannerAdapter:
    """Common interface all chain adapters must implement."""

    async def scan_contract(self, address: str, tx_hash: str, block_number: int = 0) -> ScanResult:
        raise NotImplementedError


class EvmChainScannerAdapter(BaseChainScannerAdapter):
    def __init__(self, config: ChainAdapterConfig, runner: AnalysisRunner):
        self.config = config
        self.runner = runner

    async def scan_contract(self, address: str, tx_hash: str, block_number: int = 0) -> ScanResult:
        contract = DiscoveredContract(
            chain=self.config.chain,
            address=address,
            tx_hash=tx_hash,
            block_number=block_number,
        )
        return await self.runner.analyze(
            contract,
            rpc_url=self.config.rpc_url,
            explorer_chain_id=self.config.explorer_chain_id,
        )


class SolanaChainScannerAdapter(BaseChainScannerAdapter):
    def __init__(self, rpc_url: str | None, solscan_token: str | None, cargo_audit_cmd: str):
        self._runner = SolanaAnalysisRunner(
            rpc_url=rpc_url,
            solscan_token=solscan_token,
            cargo_audit_cmd=cargo_audit_cmd,
        )

    async def scan_contract(self, address: str, tx_hash: str, block_number: int = 0) -> ScanResult:
        contract = DiscoveredContract(
            chain="solana",
            address=address,
            tx_hash=tx_hash,
            block_number=block_number,
        )
        return await self._runner.analyze(contract)


def build_all_chain_adapters(settings) -> dict[str, BaseChainScannerAdapter]:
    """Build the complete adapter registry: all configured EVM chains + Solana."""
    adapters: dict[str, BaseChainScannerAdapter] = {}

    runner = AnalysisRunner(settings)

    for chain, config in build_default_evm_chain_configs(settings).items():
        adapters[chain] = EvmChainScannerAdapter(config, runner)

    adapters["solana"] = SolanaChainScannerAdapter(
        rpc_url=settings.solana_rpc_url,
        solscan_token=settings.solscan_token,
        cargo_audit_cmd=settings.cargo_audit_cmd,
    )

    return adapters


def build_default_evm_chain_configs(settings) -> dict[str, ChainAdapterConfig]:
    chain_configs: dict[str, ChainAdapterConfig] = {
        "ethereum": ChainAdapterConfig(
            chain="ethereum",
            rpc_url=settings.rpc_url,
            explorer_chain_id="1",
        ),
        "bnb-chain": ChainAdapterConfig(
            chain="bnb-chain",
            rpc_url=settings.rpc_url_bnb_chain,
            explorer_chain_id="56",
        ),
        "polygon": ChainAdapterConfig(
            chain="polygon",
            rpc_url=settings.rpc_url_polygon,
            explorer_chain_id="137",
        ),
        "arbitrum": ChainAdapterConfig(
            chain="arbitrum",
            rpc_url=settings.rpc_url_arbitrum,
            explorer_chain_id="42161",
        ),
        "base": ChainAdapterConfig(
            chain="base",
            rpc_url=settings.rpc_url_base,
            explorer_chain_id="8453",
        ),
        "optimism": ChainAdapterConfig(
            chain="optimism",
            rpc_url=settings.rpc_url_optimism,
            explorer_chain_id="10",
        ),
        "avalanche": ChainAdapterConfig(
            chain="avalanche",
            rpc_url=settings.rpc_url_avalanche,
            explorer_chain_id="43114",
        ),
    }
    return chain_configs
