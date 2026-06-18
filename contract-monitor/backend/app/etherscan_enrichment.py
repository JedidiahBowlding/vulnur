from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import requests


class EtherscanEnricher:
    def __init__(self, api_key: str | None, base_url: str, chain_id: str = "1", timeout: int = 20):
        self.api_key = api_key
        self.base_url = base_url
        self.chain_id = chain_id
        self.timeout = timeout

    def _call(self, module: str, action: str, **params: Any) -> Any:
        if not self.api_key:
            return None

        query: dict[str, Any] = {
            "module": module,
            "action": action,
            "apikey": self.api_key,
        }
        query.update(params)

        if "/v2/" in self.base_url:
            query["chainid"] = self.chain_id

        response = requests.get(self.base_url, params=query, timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        result = payload.get("result")

        if str(payload.get("status")) == "0":
            text = str(result).lower()
            no_data_markers = (
                "no transactions found",
                "no records found",
                "no data found",
                "contract source code not verified",
                "invalid address format",
            )
            if any(marker in text for marker in no_data_markers):
                return None

        return result

    @staticmethod
    def _as_int(value: Any) -> int | None:
        try:
            if value is None or value == "":
                return None
            return int(str(value))
        except Exception:
            return None

    @staticmethod
    def _as_bool(value: Any) -> bool | None:
        if value is None:
            return None
        lowered = str(value).strip().lower()
        if lowered in {"1", "true", "yes"}:
            return True
        if lowered in {"0", "false", "no"}:
            return False
        return None

    @staticmethod
    def _iso_from_unix(ts: Any) -> str | None:
        try:
            return datetime.fromtimestamp(int(ts), tz=UTC).isoformat()
        except Exception:
            return None

    def enrich(self, address: str) -> dict[str, Any]:
        now = datetime.now(tz=UTC).isoformat()

        profile: dict[str, Any] = {
            "address": address.lower(),
            "generated_at": now,
            "data_sources": {
                "etherscan": self.base_url,
            },
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
            "coverage_notes": [],
        }

        if not self.api_key:
            profile["coverage_notes"].append("etherscan_api_key_missing")
            return profile

        source_rows = self._call("contract", "getsourcecode", address=address)
        source = source_rows[0] if isinstance(source_rows, list) and source_rows else None

        if isinstance(source, dict):
            source_code = source.get("SourceCode")
            abi_raw = source.get("ABI")
            contract_name = source.get("ContractName")
            compiler_version = source.get("CompilerVersion")
            optimization_used = self._as_bool(source.get("OptimizationUsed"))
            optimization_runs = self._as_int(source.get("Runs"))
            evm_version = source.get("EVMVersion")
            license_type = source.get("LicenseType")
            proxy_flag = self._as_bool(source.get("Proxy"))
            implementation = source.get("Implementation")
            swarm_source = source.get("SwarmSource")
            constructor_arguments = source.get("ConstructorArguments")
            similar_match = source.get("SimilarMatch")

            profile["contract_source_metadata"] = {
                "verified": bool(source_code),
                "contract_name": contract_name,
                "compiler_version": compiler_version,
                "optimization_used": optimization_used,
                "optimization_runs": optimization_runs,
                "evm_version": evm_version,
                "license_type": license_type,
                "proxy": proxy_flag,
                "implementation_address": implementation or None,
                "constructor_arguments": constructor_arguments or None,
                "swarm_source": swarm_source or None,
            }

            if isinstance(abi_raw, str) and abi_raw and abi_raw not in {"Contract source code not verified", "[]"}:
                payable_functions = 0
                admin_like_functions = 0
                public_or_external_functions = 0
                events_count = 0
                parsed_ok = False

                try:
                    import json

                    abi_items = json.loads(abi_raw)
                    if isinstance(abi_items, list):
                        parsed_ok = True
                        for item in abi_items:
                            if not isinstance(item, dict):
                                continue
                            item_type = item.get("type")
                            if item_type == "event":
                                events_count += 1
                            if item_type != "function":
                                continue

                            visibility = item.get("stateMutability")
                            if visibility in {"view", "pure", "nonpayable", "payable"}:
                                public_or_external_functions += 1
                            if visibility == "payable":
                                payable_functions += 1

                            name = str(item.get("name") or "").lower()
                            if any(
                                keyword in name
                                for keyword in (
                                    "owner",
                                    "admin",
                                    "upgrade",
                                    "pause",
                                    "mint",
                                    "burn",
                                )
                            ):
                                admin_like_functions += 1
                except Exception:
                    parsed_ok = False

                profile["abi_inventory"] = {
                    "abi_available": parsed_ok,
                    "public_or_external_functions": public_or_external_functions,
                    "payable_functions": payable_functions,
                    "events": events_count,
                    "admin_like_functions": admin_like_functions,
                }
            else:
                profile["abi_inventory"] = {
                    "abi_available": False,
                }

            profile["proxy_upgrade_intelligence"] = {
                "is_proxy": proxy_flag,
                "implementation_address": implementation or None,
                "upgradeability_signal": "proxy" if proxy_flag else "non_proxy_or_unknown",
            }

            profile["clone_relationships"] = {
                "similar_match_address": similar_match or None,
                "is_potential_clone": bool(similar_match),
            }

            profile["verification_audit_breadcrumbs"] = {
                "verified": bool(source_code),
                "verification_source": "etherscan_getsourcecode",
                "contract_name": contract_name,
                "compiler_version": compiler_version,
                "license_type": license_type,
            }

            profile["labels_and_tags"] = {
                "contract_name_label": contract_name,
                "license_label": license_type,
            }

        creation_rows = self._call(
            "contract",
            "getcontractcreation",
            contractaddresses=address,
        )
        creation = creation_rows[0] if isinstance(creation_rows, list) and creation_rows else None

        deploy_tx_hash = None
        if isinstance(creation, dict):
            deploy_tx_hash = creation.get("txHash")
            profile["creator_deployment_context"] = {
                "creator_address": creation.get("contractCreator") or None,
                "deploy_tx_hash": deploy_tx_hash,
            }

        normal_txs = self._call(
            "account",
            "txlist",
            address=address,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=200,
            sort="asc",
        )
        normal_list = normal_txs if isinstance(normal_txs, list) else []

        internal_txs = self._call(
            "account",
            "txlistinternal",
            address=address,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=200,
            sort="asc",
        )
        internal_list = internal_txs if isinstance(internal_txs, list) else []

        token_txs = self._call(
            "account",
            "tokentx",
            address=address,
            startblock=0,
            endblock=99999999,
            page=1,
            offset=200,
            sort="asc",
        )
        token_list = token_txs if isinstance(token_txs, list) else []

        deploy_block = None
        deploy_time = None
        if deploy_tx_hash and normal_list:
            for tx in normal_list:
                if str(tx.get("hash", "")).lower() == str(deploy_tx_hash).lower():
                    deploy_block = self._as_int(tx.get("blockNumber"))
                    deploy_time = self._iso_from_unix(tx.get("timeStamp"))
                    break

        if profile["creator_deployment_context"]:
            profile["creator_deployment_context"].update(
                {
                    "deploy_block": deploy_block,
                    "deploy_time": deploy_time,
                    "first_funding_tx_hash": normal_list[0].get("hash") if normal_list else None,
                }
            )

        token_name = None
        token_symbol = None
        token_decimals = None
        if token_list:
            token_name = token_list[0].get("tokenName")
            token_symbol = token_list[0].get("tokenSymbol")
            token_decimals = self._as_int(token_list[0].get("tokenDecimal"))

        total_supply = self._call("stats", "tokensupply", contractaddress=address)
        total_supply_int = self._as_int(total_supply)

        profile["token_profile"] = {
            "token_name": token_name,
            "token_symbol": token_symbol,
            "token_decimals": token_decimals,
            "total_supply_raw": total_supply_int,
            "holder_count": None,
        }

        first_seen = self._iso_from_unix(normal_list[0].get("timeStamp")) if normal_list else None
        last_seen = self._iso_from_unix(normal_list[-1].get("timeStamp")) if normal_list else None

        profile["transfer_activity_metrics"] = {
            "normal_tx_count": len(normal_list),
            "internal_tx_count": len(internal_list),
            "token_transfer_count": len(token_list),
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
        }

        eth_balance_wei = self._as_int(self._call("account", "balance", address=address, tag="latest"))
        total_incoming_wei = 0
        total_outgoing_wei = 0
        for tx in normal_list:
            value = self._as_int(tx.get("value")) or 0
            to_addr = str(tx.get("to") or "").lower()
            from_addr = str(tx.get("from") or "").lower()
            addr = address.lower()
            if to_addr == addr:
                total_incoming_wei += value
            if from_addr == addr:
                total_outgoing_wei += value

        profile["balance_value_flow"] = {
            "current_eth_balance_wei": eth_balance_wei,
            "total_incoming_wei": total_incoming_wei,
            "total_outgoing_wei": total_outgoing_wei,
            "net_flow_wei": total_incoming_wei - total_outgoing_wei,
            "flow_sample_size": len(normal_list),
        }

        profile["coverage_notes"].extend(
            [
                "holder_count_not_available_from_standard_etherscan_endpoints",
                "address_name_tag_requires_specialized_or_paid_sources",
                "upgrade_history_requires_event-level_or_archive_analysis",
            ]
        )

        return profile
