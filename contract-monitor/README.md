# Contract Monitor

Continuous smart contract monitoring system that:

- Polls an Infura/Alchemy RPC endpoint for newly deployed contracts.
- Filters duplicates with persistent SQLite storage.
- Automatically runs Mythril, Slither, and Echidna (best-effort based on source availability).
- Sends Telegram alerts and optional webhook events after each scan.
- Exposes a React dashboard to review scan history and findings.

## Architecture

- `backend/app/providers.py`: block polling + contract creation detection.
- `backend/app/storage.py`: duplicate filtering + result persistence.
- `backend/app/scanners.py`: Mythril/Slither/Echidna orchestration.
- `backend/app/notifier.py`: Telegram + webhook alert dispatch.
- `backend/app/main.py`: FastAPI API and background scanner loop.
- `frontend/`: dashboard UI.

## Prerequisites

- Python 3.11+
- Node.js 18+
- Installed analyzers in `PATH`:
  - `myth` (Mythril)
  - `slither`
  - `echidna`

## Backend setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Update `.env` with your credentials:

- `RPC_URL`: Infura or Alchemy HTTPS endpoint
- optional per-chain RPCs: `RPC_URL_BNB_CHAIN`, `RPC_URL_POLYGON`, `RPC_URL_ARBITRUM`, `RPC_URL_BASE`, `RPC_URL_OPTIMISM`, `RPC_URL_AVALANCHE`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- optional: `ETHERSCAN_API_KEY`
- optional: `ALERT_WEBHOOK_URL`

Run backend:

```bash
./run.sh
```

## Frontend setup

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:5173`.

## API endpoints

- `GET /health`
- `GET /api/contracts?limit=100`
- `POST /api/rescan/{address}`
- `POST /webhooks/scan` (for forwarding external scan payloads to Telegram)
- `GET /api/protocols`
- `GET /api/protocols/discover?query=...&limit=25&chain=all`
- `POST /api/protocols/{protocol_name}/contracts`
- `POST /api/protocols/{protocol_name}/contracts/import-coinmarketcap?query=...&limit=25&chain=all`
- `POST /api/protocols/{protocol_name}/scan`

### DeFi protocol scan workflow

1. Register protocol contracts once:

```bash
curl -X POST "http://localhost:8000/api/protocols/aave/contracts?chain=ethereum" \
  -H "Content-Type: application/json" \
  -d '{"addresses": ["0x7d2768de32b0b80b7a3454c06bdac7f4a6a3f4f2", "0x...another"]}'
```

2. Trigger a protocol-wide scan:

```bash
curl -X POST "http://localhost:8000/api/protocols/aave/scan?chain=all" \
  -H "Content-Type: application/json" \
  -d '{}'
```

3. Optional: scan ad-hoc addresses without registering:

```bash
curl -X POST "http://localhost:8000/api/protocols/uniswap-v2/scan?chain=polygon" \
  -H "Content-Type: application/json" \
  -d '{"addresses": ["0x..."]}'
```

Protocol scan responses include:

- Per-contract findings from Mythril/Slither/Echidna.
- DeFi-oriented source-code signals (example: `amm`, `lending`, `oracle`).
- DeFi risk tags (example: upgradeability/admin/oracle dependency signals).
- Chain-aware results (for configured EVM adapters).

### CoinMarketCap-assisted protocol discovery

You can use CoinMarketCap DEX search as a discovery source before scanning:

1. Discover likely protocol matches from CoinMarketCap:

```bash
curl "http://localhost:8000/api/protocols/discover?query=uniswap&limit=20&chain=all"
```

Example chain-specific filtering:

```bash
curl "http://localhost:8000/api/protocols/discover?query=jupiter&limit=20&chain=solana"
```

2. Import discovered contract addresses into tracked protocol contracts:

```bash
curl -X POST "http://localhost:8000/api/protocols/uniswap/contracts/import-coinmarketcap?query=uniswap&limit=20&chain=all"
```

3. Run protocol scan as usual:

```bash
curl -X POST "http://localhost:8000/api/protocols/uniswap/scan?chain=all" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Notes:

- The CMC endpoint used by default is keyless `x402` DEX search.
- If CMC responds with HTTP 402, you may need wallet payment or a paid plan/API key.
- Discovery is chain-aware and supports `chain=all` (default) or specific chains (for example `ethereum`, `solana`, `bnb-chain`, `base`, `arbitrum`).
- Import + scan support configured EVM chain adapters (`ethereum`, `bnb-chain`, `polygon`, `arbitrum`, `base`, `optimism`, `avalanche`).
- Non-EVM discovery data is still returned for visibility but requires non-EVM scanner adapters to analyze.

## Notes

- New contract detection scans transactions where `to == null`.
- Duplicate filtering uses unique contract address keys in SQLite.
- Slither and Echidna scans require verified source code retrieval. If source is unavailable, those tools are skipped while Mythril still runs against the address.
