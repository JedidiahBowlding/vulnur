"""
Solana source and metadata fetcher.

Tries three sources in priority order:
  1. Anchor IDL from the anchor-lang verification registry (anchorlang.com public API).
  2. SolScan public API – program info and verified source metadata.
  3. Solana JSON-RPC getProgramAccounts / getAccountInfo for raw bytecode confirmation.

All calls are best-effort; failures return None rather than raising.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import requests

logger = logging.getLogger("contract-monitor.solana-sources")

_ANCHOR_IDL_URL = "https://api.anchorlang.com/idl/{program_id}"
_SOLSCAN_PROGRAM_URL = "https://public-api.solscan.io/account/{program_id}"
_SOLANA_RPC_MAINNET = "https://api.mainnet-beta.solana.com"

TIMEOUT = 15


def fetch_solana_program_info(
    program_id: str,
    rpc_url: str | None = None,
    solscan_token: str | None = None,
    timeout: int = TIMEOUT,
) -> dict[str, Any]:
    """Return a dict with keys: idl, program_name, is_verified, source_notes."""
    result: dict[str, Any] = {
        "program_id": program_id,
        "idl": None,
        "program_name": None,
        "is_verified": False,
        "source_notes": [],
    }

    # --- 1. Anchor IDL registry ---
    try:
        resp = requests.get(
            _ANCHOR_IDL_URL.format(program_id=program_id),
            timeout=timeout,
        )
        if resp.status_code == 200:
            idl = resp.json()
            if isinstance(idl, dict) and idl.get("name"):
                result["idl"] = idl
                result["program_name"] = idl.get("name")
                result["is_verified"] = True
                result["source_notes"].append("anchor_idl_registry")
        elif resp.status_code == 404:
            result["source_notes"].append("anchor_idl_not_found")
        else:
            result["source_notes"].append(f"anchor_idl_status_{resp.status_code}")
    except Exception as exc:
        result["source_notes"].append(f"anchor_idl_error:{type(exc).__name__}")

    # --- 2. SolScan public account info ---
    try:
        headers: dict[str, str] = {}
        if solscan_token:
            headers["token"] = solscan_token
        resp = requests.get(
            _SOLSCAN_PROGRAM_URL.format(program_id=program_id),
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                result["source_notes"].append("solscan_ok")
                if not result["program_name"]:
                    result["program_name"] = (
                        data.get("account", {}).get("data", {}).get("parsed", {}).get("info", {}).get("programId")
                        or data.get("metadata", {}).get("name")
                    )
                result["solscan_data"] = {
                    "executable": data.get("executable"),
                    "lamports": data.get("lamports"),
                    "owner": data.get("owner"),
                    "data_len": data.get("dataLength"),
                }
        elif resp.status_code == 404:
            result["source_notes"].append("solscan_not_found")
        else:
            result["source_notes"].append(f"solscan_status_{resp.status_code}")
    except Exception as exc:
        result["source_notes"].append(f"solscan_error:{type(exc).__name__}")

    # --- 3. Solana RPC – getAccountInfo for basic existence/executable check ---
    try:
        rpc = rpc_url or _SOLANA_RPC_MAINNET
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [program_id, {"encoding": "base64", "commitment": "confirmed"}],
        }
        resp = requests.post(rpc, json=payload, timeout=timeout)
        resp.raise_for_status()
        account = resp.json().get("result", {}).get("value")
        if account:
            result["source_notes"].append("rpc_account_found")
            result.setdefault("solscan_data", {})["executable"] = account.get("executable")
            result.setdefault("solscan_data", {})["owner"] = account.get("owner")
        else:
            result["source_notes"].append("rpc_account_not_found")
    except Exception as exc:
        result["source_notes"].append(f"rpc_error:{type(exc).__name__}")

    return result


def idl_to_pseudo_source(idl: dict[str, Any]) -> str | None:
    """
    Convert an Anchor IDL JSON to a compact pseudo-source string that the
    static pattern scanner can analyse for DeFi signals and risk patterns.
    """
    if not isinstance(idl, dict):
        return None

    lines: list[str] = []
    program_name = idl.get("name", "UnknownProgram")
    lines.append(f"// Program: {program_name}")

    for instruction in idl.get("instructions", []):
        name = instruction.get("name", "unknown")
        accounts = [a.get("name", "") for a in instruction.get("accounts", [])]
        args = [a.get("name", "") for a in instruction.get("args", [])]
        is_mutable = any(a.get("isMut") for a in instruction.get("accounts", []))
        is_signer = any(a.get("isSigner") for a in instruction.get("accounts", []))
        lines.append(
            f"pub fn {name}({', '.join(args)}) {{ "
            f"// accounts: {', '.join(accounts)}"
            f"{' // mutable' if is_mutable else ''}"
            f"{' // signer' if is_signer else ''}"
            f" }}"
        )

    for acc_type in idl.get("accounts", []):
        fields = [f.get("name", "") for f in acc_type.get("type", {}).get("fields", [])]
        lines.append(f"struct {acc_type.get('name', 'Unknown')} {{ {', '.join(fields)} }}")

    for event in idl.get("events", []):
        lines.append(f"event {event.get('name', 'Unknown')} {{}}")

    for error in idl.get("errors", []):
        lines.append(f"// error {error.get('code')}: {error.get('msg', '')}")

    return "\n".join(lines) if lines else None
