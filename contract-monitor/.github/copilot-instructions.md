# Contract Monitor — Agent Instructions

## Project Overview

Continuous smart contract security monitoring platform with:
- **Backend**: FastAPI (Python 3.11+) in `backend/app/`
- **Frontend**: React + Vite in `frontend/src/`
- **Database**: SQLite at `backend/data/monitor.db`
- **Analysis tools**: Mythril (`myth`), Slither (`slither`), Echidna (`echidna`) — all best-effort, missing tools produce summary notes not errors
- **Non-EVM scanner**: Solana via Anchor IDL + SolScan + optional `cargo-audit`

## Architecture

```
backend/app/
  main.py              # FastAPI app, all HTTP routes, scanner loop
  config.py            # Pydantic settings loaded from backend/.env
  models.py            # DiscoveredContract(chain, address, tx_hash, block_number) + ScanResult
  storage.py           # SQLite — contracts, scans, protocol_contracts (all keyed by chain+address)
  scanners.py          # EVM analysis runner (Mythril RPC + Slither + Echidna + DeFi signals)
  solana_scanner.py    # Solana analysis runner (IDL + pattern scan + cargo-audit)
  solana_sources.py    # Anchor IDL registry → SolScan → Solana RPC fetch pipeline
  chain_adapters.py    # EvmChainScannerAdapter, SolanaChainScannerAdapter, build_all_chain_adapters()
  providers.py         # EthereumWatcher — block polling, contract creation detection
  sources.py           # fetch_source_code() — Etherscan V1/V2 with chain_id support
  protocol_discovery.py # CoinMarketCapDiscovery — multi-chain DEX search, chain signal extraction
  etherscan_enrichment.py # EtherscanEnricher — full contract profile (ABI, token, txs, proxy)
  notifier.py          # Telegram + webhook alerts (includes chain in message)
  vulnerability_details.py # Human-readable labels for vulnerability keys
```

## Key Conventions

**Models carry `chain`**: `DiscoveredContract` and `ScanResult` both have a `chain: str` field. Always populate it. Never omit chain when constructing these.

**Storage is keyed by `(chain, address)`**: The primary key for `contracts`, `scans`, and `protocol_contracts` is composite. Use `has_contract_on_chain(chain, address)` not `has_contract(address)` for cross-chain lookups. The migration helpers in `_ensure_multichain_*` run automatically on startup.

**Chain adapter dispatch**: All protocol scans route through `chain_adapters` dict built by `build_all_chain_adapters(settings)`. Adding a new chain = add a new adapter class + register it there + add RPC settings to `config.py` + add env vars to `.env.example`.

**Address validation is chain-specific**: Use `_normalize_addresses_for_chain(addresses, chain)` in `main.py` for user input. EVM = `Web3.is_address()`. Solana = base58 32–44 char regex. Never mix them.

**Analysis is always best-effort**: Every scanner tool (Mythril, Slither, Echidna, cargo-audit) appends to `summaries` if missing/skipped, never raises. `vulnerabilities` list is always returned even if empty.

**DeFi signal extraction runs on source**: `_extract_defi_signals(source_code)` in `scanners.py` runs whenever source is available. Adds `defi-signals:` and `defi-risks:` entries to `summary`. Solana equivalent is in `solana_scanner.py`.

**Source fetch is chain-aware**: `fetch_source_code(address, api_key, base_url, chain_id=...)` in `sources.py`. The chain_id must match the Etherscan V2 `chainid` param. Always pass `explorer_chain_id` from the adapter config.

## Build & Run

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # then fill in values
./run.sh              # or: RUN_RELOAD=1 ./run.sh for hot-reload

# Frontend
cd frontend
npm install && npm run dev   # http://localhost:5173
```

Backend runs on port 8000. Always start from `backend/` dir.

## API Routes (all in main.py)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness check |
| GET | `/api/contracts` | List scanned contracts with liquidity + filters |
| GET | `/api/contracts/{address}/profile` | Etherscan enriched profile (cached) |
| POST | `/api/rescan/{address}` | Force re-scan a single EVM address |
| GET | `/api/protocols` | List tracked protocol groups |
| GET | `/api/protocols/discover` | CMC DEX search (`?query=&chain=`) |
| POST | `/api/protocols/{name}/contracts` | Register addresses (`?chain=ethereum\|solana\|...`) |
| POST | `/api/protocols/{name}/contracts/import-coinmarketcap` | Discover + auto-import from CMC |
| POST | `/api/protocols/{name}/scan` | Run analysis across all contracts (`?chain=all\|specific`) |
| POST | `/webhooks/scan` | Forward external scan payload to Telegram |

## Environment Keys

**Required:**
- `RPC_URL` — Ethereum mainnet RPC (Infura/Alchemy)

**Strongly recommended:**
- `ETHERSCAN_API_KEY` — source code fetch for Slither/Echidna; use V2 base URL
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` — alerts

**Per-chain EVM (optional, enables non-Ethereum protocol scans):**
- `RPC_URL_BNB_CHAIN`, `RPC_URL_POLYGON`, `RPC_URL_ARBITRUM`, `RPC_URL_BASE`, `RPC_URL_OPTIMISM`, `RPC_URL_AVALANCHE`

**Solana (optional):**
- `SOLANA_RPC_URL` — defaults to public mainnet; use private endpoint for reliability
- `SOLSCAN_TOKEN` — richer program metadata
- `CARGO_AUDIT_CMD` — defaults to `cargo-audit`; must be installed separately

**Protocol discovery (optional):**
- `CMC_API_KEY` — CoinMarketCap; falls back to keyless x402 endpoint without it

## Common Gotchas

- `START_BLOCK` must be blank on first run or set to a recent block — never genesis, will trigger full backfill.
- `ETHERSCAN_BASE_URL` should be `https://api.etherscan.io/v2/api` (V2), not V1.
- `has_contract()` in storage only checks `ethereum` chain. Use `has_contract_on_chain()` for any other chain.
- React hooks in the frontend must be declared before any conditional early returns (hooks order is fixed).
- `AnalysisRunner` is stateless — instantiating a new one per adapter is fine and intentional.
- Non-EVM chains discovered by CMC (Solana addresses from discovery) will be in `non_evm_address_samples`; only EVM `0x` addresses land in `evm_contract_addresses` / `evm_addresses_by_chain`.
