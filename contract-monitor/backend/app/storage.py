import json
import math
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import DiscoveredContract, ScanResult
from .vulnerability_details import build_vulnerability_details


class Storage:
    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._initialize()

    def _initialize(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS contracts (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    address TEXT PRIMARY KEY,
                    tx_hash TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    address TEXT PRIMARY KEY,
                    tx_hash TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    vulnerabilities_json TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    scanned_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS contract_profiles (
                    address TEXT PRIMARY KEY,
                    profile_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_refresh_attempt_at TEXT,
                    last_refresh_error TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS contract_profile_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    profile_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS protocol_contracts (
                    protocol_name TEXT NOT NULL,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    address TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (protocol_name, chain, address)
                )
                """
            )
            self._ensure_profile_columns()
            self._ensure_multichain_contracts_table()
            self._ensure_multichain_scans_table()
            self._ensure_multichain_protocol_contracts_table()

    def _ensure_multichain_contracts_table(self) -> None:
        info = self._conn.execute("PRAGMA table_info(contracts)").fetchall()
        columns = {row["name"] for row in info}
        pk = [row["name"] for row in info if row["pk"] > 0]

        if "chain" in columns and pk == ["chain", "address"]:
            return

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS contracts_v2 (
                chain TEXT NOT NULL,
                address TEXT NOT NULL,
                tx_hash TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (chain, address)
            )
            """
        )
        self._conn.execute(
            """
            INSERT OR IGNORE INTO contracts_v2 (chain, address, tx_hash, block_number, discovered_at)
            SELECT 'ethereum', address, tx_hash, block_number, discovered_at
            FROM contracts
            """
        )
        self._conn.execute("DROP TABLE contracts")
        self._conn.execute("ALTER TABLE contracts_v2 RENAME TO contracts")

    def _ensure_multichain_scans_table(self) -> None:
        info = self._conn.execute("PRAGMA table_info(scans)").fetchall()
        columns = {row["name"] for row in info}
        pk = [row["name"] for row in info if row["pk"] > 0]

        if "chain" in columns and pk == ["chain", "address"]:
            return

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans_v2 (
                chain TEXT NOT NULL,
                address TEXT NOT NULL,
                tx_hash TEXT NOT NULL,
                block_number INTEGER NOT NULL,
                status TEXT NOT NULL,
                vulnerabilities_json TEXT NOT NULL,
                summary TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (chain, address)
            )
            """
        )
        self._conn.execute(
            """
            INSERT OR IGNORE INTO scans_v2 (
                chain, address, tx_hash, block_number, status,
                vulnerabilities_json, summary, scanned_at
            )
            SELECT 'ethereum', address, tx_hash, block_number, status,
                   vulnerabilities_json, summary, scanned_at
            FROM scans
            """
        )
        self._conn.execute("DROP TABLE scans")
        self._conn.execute("ALTER TABLE scans_v2 RENAME TO scans")

    def _ensure_multichain_protocol_contracts_table(self) -> None:
        info = self._conn.execute("PRAGMA table_info(protocol_contracts)").fetchall()
        columns = {row["name"] for row in info}
        pk = [row["name"] for row in info if row["pk"] > 0]

        if "chain" in columns and pk == ["protocol_name", "chain", "address"]:
            return

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS protocol_contracts_v2 (
                protocol_name TEXT NOT NULL,
                chain TEXT NOT NULL,
                address TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (protocol_name, chain, address)
            )
            """
        )
        self._conn.execute(
            """
            INSERT OR IGNORE INTO protocol_contracts_v2 (protocol_name, chain, address, created_at)
            SELECT protocol_name, 'ethereum', address, created_at
            FROM protocol_contracts
            """
        )
        self._conn.execute("DROP TABLE protocol_contracts")
        self._conn.execute("ALTER TABLE protocol_contracts_v2 RENAME TO protocol_contracts")

    def _ensure_profile_columns(self) -> None:
        existing = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(contract_profiles)").fetchall()
        }
        if "last_refresh_attempt_at" not in existing:
            self._conn.execute(
                "ALTER TABLE contract_profiles ADD COLUMN last_refresh_attempt_at TEXT"
            )
        if "last_refresh_error" not in existing:
            self._conn.execute(
                "ALTER TABLE contract_profiles ADD COLUMN last_refresh_error TEXT"
            )

    def has_contract(self, address: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM contracts WHERE chain = ? AND address = ?",
                ("ethereum", address.lower()),
            ).fetchone()
            return row is not None

    def has_contract_on_chain(self, chain: str, address: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM contracts WHERE chain = ? AND address = ?",
                (chain.strip().lower(), address.lower()),
            ).fetchone()
            return row is not None

    def add_contract(self, contract: DiscoveredContract) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO contracts (chain, address, tx_hash, block_number)
                VALUES (?, ?, ?, ?)
                """,
                (
                    contract.chain.lower(),
                    contract.address.lower(),
                    contract.tx_hash,
                    contract.block_number,
                ),
            )

    def upsert_scan(self, result: ScanResult) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO scans (
                    chain, address, tx_hash, block_number, status,
                    vulnerabilities_json, summary, scanned_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, address) DO UPDATE SET
                    tx_hash = excluded.tx_hash,
                    block_number = excluded.block_number,
                    status = excluded.status,
                    vulnerabilities_json = excluded.vulnerabilities_json,
                    summary = excluded.summary,
                    scanned_at = excluded.scanned_at
                """,
                (
                    result.chain.lower(),
                    result.address.lower(),
                    result.tx_hash,
                    result.block_number,
                    result.status,
                    json.dumps(result.vulnerabilities),
                    result.summary,
                    result.scanned_at,
                ),
            )

    def set_last_processed_block(self, block_number: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO metadata (key, value)
                VALUES ('last_processed_block', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(block_number),),
            )

    def get_last_processed_block(self) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM metadata WHERE key = 'last_processed_block'"
            ).fetchone()
            if not row:
                return None
            return int(row["value"])

    def list_recent_scans(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT s.address, s.tx_hash, s.block_number, s.status,
                      s.chain,
                       s.vulnerabilities_json, s.summary, s.scanned_at,
                       c.discovered_at,
                       cp.profile_json AS profile_json
                FROM scans s
                  JOIN contracts c ON c.address = s.address AND c.chain = s.chain
                LEFT JOIN contract_profiles cp ON cp.address = s.address
                ORDER BY s.scanned_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        output: list[dict[str, Any]] = []
        for row in rows:
            creator_address = None
            is_proxy = None
            activity_score = None

            try:
                if row["profile_json"]:
                    profile = json.loads(row["profile_json"])
                    creator_address = (
                        profile.get("creator_deployment_context", {}).get("creator_address")
                    )
                    is_proxy = (
                        profile.get("proxy_upgrade_intelligence", {}).get("is_proxy")
                    )

                    metrics = profile.get("transfer_activity_metrics", {})
                    normal = int(metrics.get("normal_tx_count") or 0)
                    internal = int(metrics.get("internal_tx_count") or 0)
                    token = int(metrics.get("token_transfer_count") or 0)
                    raw_activity = normal + token + (0.5 * internal)
                    activity_score = round(min(100.0, math.log10(1 + raw_activity) * 25), 1)
            except Exception:
                creator_address = None
                is_proxy = None
                activity_score = None

            output.append(
                {
                    "address": row["address"],
                    "chain": row["chain"],
                    "tx_hash": row["tx_hash"],
                    "block_number": row["block_number"],
                    "status": row["status"],
                    "vulnerabilities": json.loads(row["vulnerabilities_json"]),
                    "vulnerability_details": build_vulnerability_details(
                        json.loads(row["vulnerabilities_json"])
                    ),
                    "summary": row["summary"],
                    "scanned_at": row["scanned_at"],
                    "discovered_at": row["discovered_at"],
                    "creator_address": creator_address,
                    "is_proxy": is_proxy,
                    "activity_score": activity_score,
                }
            )
        return output

    def get_contract_profile(self, address: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT profile_json, updated_at, last_refresh_attempt_at, last_refresh_error
                FROM contract_profiles
                WHERE address = ?
                """,
                (address.lower(),),
            ).fetchone()
            if not row:
                return None

            try:
                payload = json.loads(row["profile_json"])
            except Exception:
                return None

            payload["cached_at"] = row["updated_at"]
            payload["last_refresh_attempt_at"] = row["last_refresh_attempt_at"]
            payload["last_refresh_error"] = row["last_refresh_error"]
            return payload

    def upsert_contract_profile(self, address: str, profile: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO contract_profiles (address, profile_json, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(address) DO UPDATE SET
                    profile_json = excluded.profile_json,
                    updated_at = CURRENT_TIMESTAMP,
                    last_refresh_attempt_at = CURRENT_TIMESTAMP,
                    last_refresh_error = NULL
                """,
                (address.lower(), json.dumps(profile)),
            )
            self._conn.execute(
                """
                INSERT INTO contract_profile_snapshots (address, profile_json)
                VALUES (?, ?)
                """,
                (address.lower(), json.dumps(profile)),
            )

    def mark_profile_refresh_error(self, address: str, message: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO contract_profiles (
                    address, profile_json, updated_at, last_refresh_attempt_at, last_refresh_error
                )
                VALUES (?, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
                ON CONFLICT(address) DO UPDATE SET
                    last_refresh_attempt_at = CURRENT_TIMESTAMP,
                    last_refresh_error = excluded.last_refresh_error
                """,
                (address.lower(), message),
            )

    def add_protocol_contracts(self, protocol_name: str, addresses: list[str], chain: str) -> int:
        protocol_key = protocol_name.strip().lower()
        chain_key = chain.strip().lower()
        normalized_addresses = sorted({addr.lower() for addr in addresses if addr})
        if not protocol_key or not chain_key or not normalized_addresses:
            return 0

        inserted = 0
        with self._lock, self._conn:
            for address in normalized_addresses:
                cursor = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO protocol_contracts (protocol_name, chain, address)
                    VALUES (?, ?, ?)
                    """,
                    (protocol_key, chain_key, address),
                )
                inserted += int(cursor.rowcount > 0)
        return inserted

    def list_protocol_contracts(
        self, protocol_name: str, chain: str | None = None
    ) -> list[dict[str, str]]:
        protocol_key = protocol_name.strip().lower()
        chain_key = chain.strip().lower() if chain else None
        with self._lock:
            if chain_key and chain_key not in {"all", "any"}:
                rows = self._conn.execute(
                    """
                    SELECT chain, address
                    FROM protocol_contracts
                    WHERE protocol_name = ? AND chain = ?
                    ORDER BY created_at ASC
                    """,
                    (protocol_key, chain_key),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT chain, address
                    FROM protocol_contracts
                    WHERE protocol_name = ?
                    ORDER BY created_at ASC
                    """,
                    (protocol_key,),
                ).fetchall()
        return [{"chain": row["chain"], "address": row["address"]} for row in rows]

    def list_protocols(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                  SELECT protocol_name, COUNT(*) AS contract_count,
                      COUNT(DISTINCT chain) AS chain_count,
                      MAX(created_at) AS last_updated_at
                FROM protocol_contracts
                GROUP BY protocol_name
                ORDER BY protocol_name ASC
                """
            ).fetchall()

        return [
            {
                "protocol_name": row["protocol_name"],
                "contract_count": row["contract_count"],
                "chain_count": row["chain_count"],
                "last_updated_at": row["last_updated_at"],
            }
            for row in rows
        ]

    def list_profile_snapshots(self, address: str, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, created_at, profile_json
                FROM contract_profile_snapshots
                WHERE address = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (address.lower(), limit),
            ).fetchall()

        output: list[dict[str, Any]] = []
        for row in rows:
            output.append(
                {
                    "id": row["id"],
                    "created_at": row["created_at"],
                    "profile": json.loads(row["profile_json"]),
                }
            )
        return output

    @staticmethod
    def _flatten_json(obj: Any, prefix: str = "") -> dict[str, str]:
        flat: dict[str, str] = {}
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_prefix = f"{prefix}.{key}" if prefix else str(key)
                flat.update(Storage._flatten_json(value, key_prefix))
            return flat
        if isinstance(obj, list):
            for idx, value in enumerate(obj):
                key_prefix = f"{prefix}[{idx}]"
                flat.update(Storage._flatten_json(value, key_prefix))
            return flat

        flat[prefix] = "" if obj is None else str(obj)
        return flat

    def latest_profile_diff(self, address: str, max_changes: int = 25) -> dict[str, Any]:
        snapshots = self.list_profile_snapshots(address, limit=2)
        if len(snapshots) < 2:
            return {
                "changed_count": 0,
                "from_snapshot_at": None,
                "to_snapshot_at": snapshots[0]["created_at"] if snapshots else None,
                "changes": [],
            }

        newest = snapshots[0]
        previous = snapshots[1]
        flat_new = self._flatten_json(newest["profile"])
        flat_old = self._flatten_json(previous["profile"])

        all_keys = sorted(set(flat_new.keys()) | set(flat_old.keys()))
        changes: list[dict[str, str]] = []
        for key in all_keys:
            old = flat_old.get(key, "")
            new = flat_new.get(key, "")
            if old != new:
                changes.append(
                    {
                        "field": key,
                        "old": old,
                        "new": new,
                    }
                )

        return {
            "changed_count": len(changes),
            "from_snapshot_at": previous["created_at"],
            "to_snapshot_at": newest["created_at"],
            "changes": changes[:max_changes],
        }

    @staticmethod
    def age_seconds(iso_timestamp: str | None) -> float | None:
        if not iso_timestamp:
            return None
        try:
            normalized = iso_timestamp.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return max(0.0, (datetime.now(tz=UTC) - dt).total_seconds())
        except Exception:
            try:
                # SQLite CURRENT_TIMESTAMP default format: YYYY-MM-DD HH:MM:SS
                dt = datetime.strptime(iso_timestamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
                return max(0.0, (datetime.now(tz=UTC) - dt).total_seconds())
            except Exception:
                return None
