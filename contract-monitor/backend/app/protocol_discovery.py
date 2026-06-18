from __future__ import annotations

import re
from typing import Any

import requests

from .config import Settings


class CoinMarketCapDiscovery:
    def __init__(self, settings: Settings):
        self.settings = settings

    def search_defi_protocols(
        self,
        query: str,
        limit: int = 25,
        chain: str | None = None,
    ) -> list[dict[str, Any]]:
        query_text = (query or "").strip()
        if len(query_text) < 2:
            raise RuntimeError("query must be at least 2 characters")

        limit_value = max(1, min(limit, 100))

        headers: dict[str, str] = {}
        if self.settings.cmc_api_key:
            headers["X-CMC_PRO_API_KEY"] = self.settings.cmc_api_key

        response = requests.get(
            self.settings.cmc_keyless_dex_search_url,
            params={"q": query_text, "limit": limit_value},
            headers=headers,
            timeout=self.settings.cmc_timeout_seconds,
        )

        if response.status_code == 402:
            raise RuntimeError(
                "CoinMarketCap keyless endpoint returned 402 Payment Required; "
                "you may need x402 wallet payment or a paid API plan"
            )
        if response.status_code == 401:
            raise RuntimeError("CoinMarketCap authentication failed; check CMC_API_KEY")
        if response.status_code >= 400:
            raise RuntimeError(f"CoinMarketCap request failed with status {response.status_code}")

        payload = response.json()
        raw_data = payload.get("data", payload)
        objects = self._collect_objects(raw_data)

        chain_filter = (chain or "").strip().lower()
        if chain_filter in {"", "all", "any"}:
            chain_filter = ""

        aggregated: dict[str, dict[str, Any]] = {}
        query_lower = query_text.lower()

        for obj in objects:
            protocol_name = self._extract_name(obj)
            if not protocol_name:
                continue

            addresses_by_type = self._extract_address_candidates(obj)
            chain_signals = self._extract_chain_signals(obj)
            if chain_filter and chain_filter not in chain_signals:
                continue

            evm_addresses = addresses_by_type.get("evm", set())
            non_evm_addresses = sorted(
                {
                    address
                    for chain_name, chain_addresses in addresses_by_type.items()
                    if chain_name != "evm"
                    for address in chain_addresses
                }
            )
            tags = self._extract_tags(obj)
            searchable = self._flatten_to_text(obj)
            if query_lower not in searchable and not any(query_lower in tag for tag in tags):
                continue

            is_defi_like = any(
                marker in searchable
                for marker in (
                    "defi",
                    "dex",
                    "liquidity",
                    "lending",
                    "amm",
                    "vault",
                    "staking",
                    "yield",
                    "swap",
                    "perp",
                )
            )
            if not is_defi_like:
                continue

            key = protocol_name.lower()
            if key not in aggregated:
                aggregated[key] = {
                    "protocol_name": protocol_name,
                    "evm_contract_addresses": set(),
                    "non_evm_address_samples": set(),
                    "evm_addresses_by_chain": {},
                    "chains": set(),
                    "tags": set(),
                    "hits": 0,
                }

            aggregated[key]["evm_contract_addresses"].update(evm_addresses)
            aggregated[key]["non_evm_address_samples"].update(non_evm_addresses[:20])
            aggregated[key]["chains"].update(chain_signals)
            for chain_name in chain_signals:
                if chain_name == "unknown":
                    continue
                chain_bucket = aggregated[key]["evm_addresses_by_chain"].setdefault(chain_name, set())
                chain_bucket.update(evm_addresses)
            aggregated[key]["tags"].update(tags)
            aggregated[key]["hits"] += 1

        results: list[dict[str, Any]] = []
        for item in aggregated.values():
            contract_addresses = sorted(item["evm_contract_addresses"])
            chains = sorted(item["chains"])
            non_evm_samples = sorted(item["non_evm_address_samples"])
            evm_by_chain = {
                chain_name: sorted(addresses)
                for chain_name, addresses in sorted(item["evm_addresses_by_chain"].items())
            }
            tags = sorted(item["tags"])
            hits = int(item["hits"])
            score = hits + min(len(contract_addresses), 5) + min(len(chains), 3)

            results.append(
                {
                    "protocol_name": item["protocol_name"],
                    "chains": chains,
                    "contract_addresses": contract_addresses,
                    "evm_contract_addresses": contract_addresses,
                    "evm_addresses_by_chain": evm_by_chain,
                    "non_evm_address_samples": non_evm_samples,
                    "tag_signals": tags,
                    "source_hits": hits,
                    "confidence_score": score,
                }
            )

        results.sort(key=lambda row: (row["confidence_score"], row["source_hits"]), reverse=True)
        return results[:limit_value]

    @staticmethod
    def _collect_objects(value: Any) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                results.append(node)
                for nested in node.values():
                    walk(nested)
                return
            if isinstance(node, list):
                for nested in node:
                    walk(nested)

        walk(value)
        return results

    @staticmethod
    def _extract_name(obj: dict[str, Any]) -> str | None:
        candidates = (
            "protocol_name",
            "dex_name",
            "exchange_name",
            "project_name",
            "name",
            "slug",
        )
        for key in candidates:
            value = obj.get(key)
            if isinstance(value, str) and value.strip():
                text = value.strip()
                if len(text) >= 2:
                    return text
        return None

    @staticmethod
    def _extract_address_candidates(obj: dict[str, Any]) -> dict[str, set[str]]:
        addresses: dict[str, set[str]] = {
            "evm": set(),
            "solana": set(),
            "tron": set(),
        }

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, nested in node.items():
                    key_lower = str(key).lower()
                    if "address" in key_lower and isinstance(nested, str):
                        for addr in re.findall(r"0x[a-fA-F0-9]{40}", nested):
                            addresses["evm"].add(addr.lower())
                        for addr in re.findall(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", nested):
                            addresses["tron"].add(addr)
                        for addr in re.findall(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", nested):
                            addresses["solana"].add(addr)
                    walk(nested)
                return
            if isinstance(node, list):
                for nested in node:
                    walk(nested)
                return
            if isinstance(node, str):
                for addr in re.findall(r"0x[a-fA-F0-9]{40}", node):
                    addresses["evm"].add(addr.lower())
                for addr in re.findall(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b", node):
                    addresses["tron"].add(addr)
                for addr in re.findall(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b", node):
                    addresses["solana"].add(addr)

        walk(obj)
        return addresses

    @staticmethod
    def _extract_chain_signals(obj: dict[str, Any]) -> set[str]:
        flattened = CoinMarketCapDiscovery._flatten_to_text(obj)

        mapping: dict[str, tuple[str, ...]] = {
            "ethereum": ("ethereum", "eth", "erc20"),
            "solana": ("solana", "spl"),
            "bnb-chain": ("bnb", "bsc", "binance smart chain"),
            "base": ("base",),
            "arbitrum": ("arbitrum",),
            "optimism": ("optimism",),
            "polygon": ("polygon", "matic"),
            "avalanche": ("avalanche", "avax"),
            "tron": ("tron", "trc20"),
            "sui": ("sui",),
            "aptos": ("aptos",),
        }

        chains: set[str] = set()
        for chain_name, needles in mapping.items():
            if any(needle in flattened for needle in needles):
                chains.add(chain_name)

        if not chains:
            chains.add("unknown")

        return chains

    @staticmethod
    def _extract_tags(obj: dict[str, Any]) -> set[str]:
        tags: set[str] = set()
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key_lower not in {"tags", "category", "categories", "labels"}:
                continue
            if isinstance(value, str) and value.strip():
                tags.add(value.strip().lower())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        tags.add(item.strip().lower())
        return tags

    @staticmethod
    def _flatten_to_text(obj: dict[str, Any]) -> str:
        parts: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, nested in node.items():
                    parts.append(str(key))
                    walk(nested)
                return
            if isinstance(node, list):
                for nested in node:
                    walk(nested)
                return
            parts.append(str(node))

        walk(obj)
        return " ".join(parts).lower()
