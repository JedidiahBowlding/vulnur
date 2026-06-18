from __future__ import annotations

import asyncio
import copy
import logging
import random
from contextlib import asynccontextmanager

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from web3 import Web3
from web3.exceptions import CannotHandleRequest, ProviderConnectionError, TooManyRequests, Web3Exception

from .chain_adapters import build_all_chain_adapters
from .config import Settings
from .etherscan_enrichment import EtherscanEnricher
from .models import DiscoveredContract
from .notifier import Notifier
from .protocol_discovery import CoinMarketCapDiscovery
from .providers import EthereumWatcher
from .scanners import AnalysisRunner
from .storage import Storage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("contract-monitor")

settings = Settings()
storage = Storage(settings.sqlite_path)
watcher = EthereumWatcher(settings.rpc_url)
runner = AnalysisRunner(settings)
notifier = Notifier(settings)
protocol_discovery = CoinMarketCapDiscovery(settings)
chain_adapters = build_all_chain_adapters(settings)
enricher = EtherscanEnricher(
    api_key=settings.etherscan_api_key,
    base_url=settings.etherscan_base_url,
    chain_id=settings.etherscan_chain_id,
)
stop_event = asyncio.Event()


class ProtocolContractsPayload(BaseModel):
    addresses: list[str] = Field(default_factory=list)


class ProtocolScanPayload(BaseModel):
    addresses: list[str] | None = None


def _validate_protocol_name(protocol_name: str) -> str:
    normalized = protocol_name.strip().lower()
    if not normalized:
        raise HTTPException(status_code=400, detail="protocol_name cannot be empty")
    if len(normalized) > 80:
        raise HTTPException(status_code=400, detail="protocol_name too long (max 80 chars)")
    return normalized


def _normalize_chain(chain: str | None) -> str:
    normalized = (chain or "ethereum").strip().lower()
    if normalized in {"", "any", "all"}:
        return "all"
    return normalized


def _chain_adapter_or_400(chain: str):
    adapter = chain_adapters.get(chain)
    if not adapter:
        supported = ", ".join(sorted(chain_adapters.keys()))
        raise HTTPException(
            status_code=400,
            detail=f"unsupported chain '{chain}'. supported chains: {supported}",
        )
    return adapter


def _normalize_addresses(addresses: list[str]) -> list[str]:
    normalized: list[str] = []
    invalid: list[str] = []

    for raw in addresses:
        value = (raw or "").strip()
        if not value:
            continue
        if not Web3.is_address(value):
            invalid.append(value)
            continue
        normalized.append(Web3.to_checksum_address(value).lower())

    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"invalid contract address(es): {', '.join(invalid[:5])}",
        )

    return sorted(set(normalized))


def _extract_defi_data_from_scan(scan: dict) -> dict[str, list[str]]:
    summary = scan.get("summary") or ""
    signals: list[str] = []
    for part in summary.split(" | "):
        if part.startswith("defi-signals: "):
            tail = part.replace("defi-signals: ", "", 1)
            signals = [item.strip() for item in tail.split(",") if item.strip()]
            break

    vuln_items = scan.get("vulnerabilities") or []
    risks = sorted(
        {
            item.split(":", 1)[1]
            for item in vuln_items
            if isinstance(item, str) and item.startswith("defi_risk:") and ":" in item
        }
    )

    return {
        "signals": signals,
        "risks": risks,
    }


_SOLANA_ADDRESS_RE = __import__('re').compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')


def _is_solana_address(value: str) -> bool:
    return bool(_SOLANA_ADDRESS_RE.match(value))


def _normalize_addresses_for_chain(addresses: list[str], chain: str) -> list[str]:
    """Validate and normalise addresses according to chain address format."""
    normalized: list[str] = []
    invalid: list[str] = []

    for raw in addresses:
        value = (raw or "").strip()
        if not value:
            continue
        if chain == "solana":
            if not _is_solana_address(value):
                invalid.append(value)
            else:
                normalized.append(value)
        else:
            if not Web3.is_address(value):
                invalid.append(value)
            else:
                normalized.append(Web3.to_checksum_address(value).lower())

    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"invalid address(es) for chain '{chain}': {', '.join(invalid[:5])}",
        )
    return sorted(set(normalized))


def _normalize_protocol_contract_inputs(
    addresses: list[str],
    chain: str,
) -> list[dict[str, str]]:
    normalized_addresses = _normalize_addresses_for_chain(addresses, chain)
    return [{"chain": chain, "address": address} for address in normalized_addresses]


def _is_retryable_rpc_error(exc: Exception) -> bool:
    if isinstance(exc, (ProviderConnectionError, CannotHandleRequest, TooManyRequests)):
        return True

    # Several provider-side Web3 failures are transient (rate limit/capacity/downstream node).
    # Keep these on backoff path to avoid noisy stack traces from the scanner loop.
    if isinstance(exc, Web3Exception):
        text = str(exc).lower()
        web3_retryable_markers = (
            "cannot fulfill request",
            "too many requests",
            "request limit",
            "rate limit",
            "temporarily unavailable",
            "try again",
            "-32005",
            "-32016",
            "-32046",
        )
        if any(marker in text for marker in web3_retryable_markers):
            return True

    if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return True

    if isinstance(exc, requests.exceptions.HTTPError):
        status_code = exc.response.status_code if exc.response is not None else None
        return status_code in {429, 500, 502, 503, 504}

    text = str(exc).lower()
    retryable_markers = (
        "429",
        "too many requests",
        "connection reset",
        "temporarily unavailable",
        "timed out",
        "connection aborted",
    )
    return any(marker in text for marker in retryable_markers)


def _short_error(exc: Exception, max_len: int = 240) -> str:
    text = f"{type(exc).__name__}: {exc}"
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


async def scanner_loop() -> None:
    logger.info("Scanner loop started")
    last_processed = storage.get_last_processed_block()
    consecutive_rpc_errors = 0
    suppressed_rpc_logs = 0

    if last_processed is None and settings.start_block is not None:
        last_processed = settings.start_block
        storage.set_last_processed_block(last_processed)

    while not stop_event.is_set():
        try:
            latest = await asyncio.to_thread(watcher.latest_block_number)

            if last_processed is None:
                last_processed = latest - 1
                storage.set_last_processed_block(last_processed)

            if latest <= last_processed:
                if consecutive_rpc_errors > 0:
                    logger.info(
                        "RPC recovered after %s transient errors (suppressed %s logs)",
                        consecutive_rpc_errors,
                        suppressed_rpc_logs,
                    )
                    consecutive_rpc_errors = 0
                    suppressed_rpc_logs = 0
                await asyncio.sleep(settings.polling_interval_seconds)
                continue

            created_contracts = await asyncio.to_thread(
                watcher.find_contract_creations,
                last_processed + 1,
                latest,
            )
            logger.info(
                "Scanning blocks %s-%s. New contracts found: %s",
                last_processed + 1,
                latest,
                len(created_contracts),
            )

            for contract in created_contracts:
                if storage.has_contract(contract.address):
                    continue

                storage.add_contract(contract)
                result = await runner.analyze(
                    contract,
                    rpc_url=settings.rpc_url,
                    explorer_chain_id=settings.etherscan_chain_id,
                )
                storage.upsert_scan(result)
                notifier.notify_scan(result)

            last_processed = latest
            storage.set_last_processed_block(last_processed)

            if consecutive_rpc_errors > 0:
                logger.info(
                    "RPC recovered after %s transient errors (suppressed %s logs)",
                    consecutive_rpc_errors,
                    suppressed_rpc_logs,
                )
                consecutive_rpc_errors = 0
                suppressed_rpc_logs = 0
        except Exception as exc:
            if _is_retryable_rpc_error(exc):
                consecutive_rpc_errors += 1

                exponential_delay = settings.rpc_backoff_base_seconds * (
                    2 ** (consecutive_rpc_errors - 1)
                )
                backoff_delay = min(settings.rpc_backoff_max_seconds, exponential_delay)
                jitter = random.uniform(0, settings.rpc_backoff_jitter_seconds)
                sleep_seconds = backoff_delay + jitter

                if (
                    consecutive_rpc_errors == 1
                    or consecutive_rpc_errors % max(1, settings.rpc_log_every_n_errors) == 0
                ):
                    logger.warning(
                        "Transient RPC error (%s consecutive). Backing off %.1fs. %s",
                        consecutive_rpc_errors,
                        sleep_seconds,
                        _short_error(exc),
                    )
                else:
                    suppressed_rpc_logs += 1

                await asyncio.sleep(sleep_seconds)
                continue

            logger.exception("Unexpected scanner loop error")

        await asyncio.sleep(settings.polling_interval_seconds)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(scanner_loop())
    try:
        yield
    finally:
        stop_event.set()
        await task


app = FastAPI(title="Contract Monitor", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/contracts")
def list_contracts(
    limit: int = 100,
    min_liquidity_eth: float | None = None,
    max_liquidity_eth: float | None = None,
    search: str | None = None,
) -> list[dict]:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    if min_liquidity_eth is not None and min_liquidity_eth < 0:
        raise HTTPException(status_code=400, detail="min_liquidity_eth must be >= 0")
    if max_liquidity_eth is not None and max_liquidity_eth < 0:
        raise HTTPException(status_code=400, detail="max_liquidity_eth must be >= 0")
    if (
        min_liquidity_eth is not None
        and max_liquidity_eth is not None
        and min_liquidity_eth > max_liquidity_eth
    ):
        raise HTTPException(
            status_code=400,
            detail="min_liquidity_eth must be less than or equal to max_liquidity_eth",
        )

    rows = storage.list_recent_scans(limit=limit)
    filtered: list[dict] = []

    for row in rows:
        # Apply search filter
        if search:
            search_lower = search.lower()
            address_match = search_lower in row["address"].lower()
            if not address_match:
                continue

        liquidity_wei = 0
        try:
            checksum = Web3.to_checksum_address(row["address"])
            liquidity_wei = int(watcher.w3.eth.get_balance(checksum))
        except Exception as exc:
            logger.warning("Failed to fetch liquidity for %s: %s", row["address"], _short_error(exc))

        liquidity_eth = float(Web3.from_wei(liquidity_wei, "ether"))
        row["liquidity_wei"] = liquidity_wei
        row["liquidity_eth"] = liquidity_eth

        if min_liquidity_eth is not None and liquidity_eth < min_liquidity_eth:
            continue
        if max_liquidity_eth is not None and liquidity_eth > max_liquidity_eth:
            continue

        filtered.append(row)

    return filtered


@app.post("/api/rescan/{address}")
async def rescan_address(address: str) -> dict[str, str]:
    # For manual rescans we don't know the creation tx hash/block, so we store placeholders.
    contract = DiscoveredContract(
        chain="ethereum",
        address=address,
        tx_hash="manual-rescan",
        block_number=0,
    )
    storage.add_contract(contract)
    result = await runner.analyze(
        contract,
        rpc_url=settings.rpc_url,
        explorer_chain_id=settings.etherscan_chain_id,
    )
    storage.upsert_scan(result)
    notifier.notify_scan(result)
    return {"status": "queued", "address": address}


@app.get("/api/protocols")
def list_protocols() -> list[dict]:
    return storage.list_protocols()


@app.get("/api/protocols/discover")
def discover_protocols(query: str, limit: int = 25, chain: str = "all") -> dict:
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")

    try:
        protocols = protocol_discovery.search_defi_protocols(
            query=query,
            limit=limit,
            chain=_normalize_chain(chain),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "provider": "coinmarketcap",
        "query": query,
        "chain_filter": chain,
        "count": len(protocols),
        "protocols": protocols,
    }


@app.post("/api/protocols/{protocol_name}/contracts/import-coinmarketcap")
def import_protocol_contracts_from_coinmarketcap(
    protocol_name: str,
    query: str,
    limit: int = 25,
    chain: str = "all",
) -> dict:
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")

    normalized_name = _validate_protocol_name(protocol_name)
    normalized_chain = _normalize_chain(chain)

    try:
        protocols = protocol_discovery.search_defi_protocols(
            query=query,
            limit=limit,
            chain=normalized_chain,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    discovered_entries: list[dict[str, str]] = []
    for protocol in protocols:
        by_chain = protocol.get("evm_addresses_by_chain", {})
        if isinstance(by_chain, dict) and by_chain:
            for chain_name, addresses in by_chain.items():
                chain_key = _normalize_chain(str(chain_name))
                if chain_key == "all" or chain_key == "unknown":
                    continue
                for address in addresses or []:
                    if isinstance(address, str) and Web3.is_address(address):
                        discovered_entries.append(
                            {
                                "chain": chain_key,
                                "address": Web3.to_checksum_address(address).lower(),
                            }
                        )
        else:
            for address in protocol.get("evm_contract_addresses", []):
                if isinstance(address, str) and Web3.is_address(address):
                    fallback_chain = normalized_chain if normalized_chain != "all" else "ethereum"
                    discovered_entries.append(
                        {
                            "chain": fallback_chain,
                            "address": Web3.to_checksum_address(address).lower(),
                        }
                    )

    deduped_entries = sorted(
        {(item["chain"], item["address"]) for item in discovered_entries if item.get("chain")},
        key=lambda x: (x[0], x[1]),
    )
    discovered_addresses = [{"chain": chain_name, "address": address} for chain_name, address in deduped_entries]

    if not discovered_addresses:
        raise HTTPException(
            status_code=400,
            detail="no contract addresses discovered from CoinMarketCap search",
        )

    if len(discovered_addresses) > settings.protocol_scan_max_contracts:
        raise HTTPException(
            status_code=400,
            detail=(
                "too many discovered addresses for one import; "
                f"max is {settings.protocol_scan_max_contracts}"
            ),
        )

    inserted = 0
    for item in discovered_addresses:
        inserted += storage.add_protocol_contracts(
            normalized_name,
            [item["address"]],
            chain=item["chain"],
        )
    tracked = storage.list_protocol_contracts(normalized_name, chain=normalized_chain)

    return {
        "provider": "coinmarketcap",
        "protocol_name": normalized_name,
        "query": query,
        "chain_filter": normalized_chain,
        "discovered_addresses": discovered_addresses,
        "note": "scan/import supports configured EVM chain adapters; non-EVM discovery remains visible in /api/protocols/discover",
        "added_now": inserted,
        "total_tracked_contracts": len(tracked),
        "contracts": tracked,
    }


@app.post("/api/protocols/{protocol_name}/contracts")
def register_protocol_contracts(
    protocol_name: str,
    payload: ProtocolContractsPayload,
    chain: str = "ethereum",
) -> dict:
    normalized_name = _validate_protocol_name(protocol_name)
    normalized_chain = _normalize_chain(chain)
    if normalized_chain == "all":
        raise HTTPException(status_code=400, detail="chain must be specific for manual registration")
    _chain_adapter_or_400(normalized_chain)

    entries = _normalize_protocol_contract_inputs(payload.addresses, chain=normalized_chain)
    addresses = [entry["address"] for entry in entries]
    if not entries:
        raise HTTPException(status_code=400, detail="at least one valid address is required")
    if len(addresses) > settings.protocol_scan_max_contracts:
        raise HTTPException(
            status_code=400,
            detail=(
                "too many addresses in a single request; "
                f"max is {settings.protocol_scan_max_contracts}"
            ),
        )

    inserted = storage.add_protocol_contracts(normalized_name, addresses, chain=normalized_chain)
    current = storage.list_protocol_contracts(normalized_name, chain=normalized_chain)
    return {
        "protocol_name": normalized_name,
        "chain": normalized_chain,
        "added_now": inserted,
        "total_tracked_contracts": len(current),
        "contracts": current,
    }


@app.post("/api/protocols/{protocol_name}/scan")
async def scan_protocol_contracts(
    protocol_name: str,
    payload: ProtocolScanPayload,
    chain: str = "all",
) -> dict:
    normalized_name = _validate_protocol_name(protocol_name)
    normalized_chain = _normalize_chain(chain)

    if payload.addresses is None:
        targets = storage.list_protocol_contracts(normalized_name, chain=normalized_chain)
    else:
        if normalized_chain == "all":
            raise HTTPException(
                status_code=400,
                detail="chain must be provided when scanning ad-hoc addresses",
            )
        _chain_adapter_or_400(normalized_chain)
        targets = _normalize_protocol_contract_inputs(payload.addresses, chain=normalized_chain)

    if not targets:
        raise HTTPException(
            status_code=400,
            detail="no addresses to scan; register protocol contracts or pass addresses in payload",
        )
    if len(targets) > settings.protocol_scan_max_contracts:
        raise HTTPException(
            status_code=400,
            detail=(
                "too many protocol contracts in one scan; "
                f"max is {settings.protocol_scan_max_contracts}"
            ),
        )

    results: list[dict] = []
    skipped: list[dict[str, str]] = []
    for target in targets:
        chain_name = target["chain"]
        address = target["address"]
        adapter = chain_adapters.get(chain_name)
        if not adapter:
            skipped.append(
                {
                    "chain": chain_name,
                    "address": address,
                    "reason": "no configured adapter for chain",
                }
            )
            continue

        contract = DiscoveredContract(
            chain=chain_name,
            address=address,
            tx_hash=f"manual-protocol-scan:{normalized_name}:{chain_name}",
            block_number=0,
        )
        storage.add_contract(contract)
        result = await adapter.scan_contract(
            address=address,
            tx_hash=contract.tx_hash,
            block_number=0,
        )
        storage.upsert_scan(result)
        notifier.notify_scan(result)

        row = result.to_dict()
        row["protocol_name"] = normalized_name
        row["defi"] = _extract_defi_data_from_scan(row)
        results.append(row)

    unique_vulns = sorted(
        {
            vuln
            for item in results
            for vuln in item.get("vulnerabilities", [])
            if isinstance(vuln, str)
        }
    )

    return {
        "protocol_name": normalized_name,
        "chain_filter": normalized_chain,
        "scanned_contracts": len(results),
        "skipped_contracts": skipped,
        "max_allowed": settings.protocol_scan_max_contracts,
        "aggregate": {
            "unique_vulnerabilities": unique_vulns,
            "vulnerability_count": len(unique_vulns),
        },
        "results": results,
    }


@app.get("/api/contracts/{address}/profile")
def contract_profile(address: str, refresh: bool = False) -> dict:
    cached = storage.get_contract_profile(address)
    cached_at = cached.get("cached_at") if cached else None
    last_attempt = cached.get("last_refresh_attempt_at") if cached else None
    age = storage.age_seconds(cached_at)
    attempt_age = storage.age_seconds(last_attempt)

    within_ttl = age is not None and age <= settings.profile_cache_ttl_seconds
    within_backoff = (
        attempt_age is not None
        and attempt_age <= settings.profile_refresh_backoff_seconds
    )

    should_refresh = refresh or cached is None or not within_ttl
    if should_refresh and cached is not None and within_backoff:
        should_refresh = False

    if should_refresh:
        try:
            profile = enricher.enrich(address)
            storage.upsert_contract_profile(address, profile)
            cached = storage.get_contract_profile(address)
        except Exception as exc:
            storage.mark_profile_refresh_error(address, _short_error(exc))
            cached = storage.get_contract_profile(address)

    if cached is None:
        # Should be uncommon, but keep contract with API expectations.
        return {
            "address": address.lower(),
            "generated_at": None,
            "contract_source_metadata": {},
            "creator_deployment_context": {},
            "abi_inventory": {},
            "token_profile": {},
            "transfer_activity_metrics": {},
            "balance_value_flow": {},
            "labels_and_tags": {},
            "proxy_upgrade_intelligence": {},
            "clone_relationships": {},
            "verification_audit_breadcrumbs": {},
            "coverage_notes": ["profile_unavailable"],
            "_meta": {
                "from_cache": False,
                "cache_ttl_seconds": settings.profile_cache_ttl_seconds,
                "refresh_backoff_seconds": settings.profile_refresh_backoff_seconds,
                "cached_at": None,
                "cache_age_seconds": None,
                "rate_limited": False,
                "last_refresh_error": None,
            },
            "_diff": {
                "changed_count": 0,
                "from_snapshot_at": None,
                "to_snapshot_at": None,
                "changes": [],
            },
            "_snapshots": [],
        }

    response = copy.deepcopy(cached)
    response.pop("cached_at", None)
    response.pop("last_refresh_attempt_at", None)
    response.pop("last_refresh_error", None)

    latest_diff = storage.latest_profile_diff(address)
    snapshot_rows = storage.list_profile_snapshots(address, limit=5)

    response["_meta"] = {
        "from_cache": True,
        "cache_ttl_seconds": settings.profile_cache_ttl_seconds,
        "refresh_backoff_seconds": settings.profile_refresh_backoff_seconds,
        "cached_at": cached_at,
        "cache_age_seconds": age,
        "rate_limited": should_refresh is False and refresh and within_backoff,
        "last_refresh_error": cached.get("last_refresh_error"),
    }
    response["_diff"] = latest_diff
    response["_snapshots"] = [
        {
            "id": row["id"],
            "created_at": row["created_at"],
        }
        for row in snapshot_rows
    ]

    return response


@app.post("/webhooks/scan")
def inbound_scan_webhook(payload: dict) -> dict[str, str]:
    # Allows external systems to send a scan event that will be forwarded to Telegram.
    from .models import ScanResult

    required = {"address", "tx_hash", "block_number", "status", "vulnerabilities", "summary", "scanned_at"}
    if not required.issubset(payload.keys()):
        raise HTTPException(status_code=400, detail="invalid payload")

    result = ScanResult(
        chain=payload.get("chain", "ethereum"),
        address=payload["address"],
        tx_hash=payload["tx_hash"],
        block_number=int(payload["block_number"]),
        status=payload["status"],
        vulnerabilities=list(payload["vulnerabilities"]),
        summary=payload["summary"],
        scanned_at=payload["scanned_at"],
    )
    notifier.notify_scan(result)
    return {"status": "forwarded"}
