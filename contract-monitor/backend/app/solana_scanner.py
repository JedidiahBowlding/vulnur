"""
Solana program scanner.

Analysis pipeline:
  1. Fetch IDL and program metadata via solana_sources.
  2. Convert the IDL to pseudo-source and run the same DeFi signal/risk
     keyword patterns used for EVM.
  3. Run `cargo audit` subprocess if the program source directory is
     available (best-effort; skipped when not installed or source absent).
  4. Run a Solana-specific instruction pattern analysis on the IDL directly.

All tools are best-effort: a missing tool produces a summary note, not an error.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .models import DiscoveredContract, ScanResult
from .solana_sources import fetch_solana_program_info, idl_to_pseudo_source

logger = logging.getLogger("contract-monitor.solana-scanner")

# ---------------------------------------------------------------------------
# Solana-specific DeFi signal and risk patterns (maps IDL instruction names
# and account field names to well-known DeFi patterns).
# ---------------------------------------------------------------------------
_SOLANA_SIGNAL_PATTERNS: dict[str, tuple[str, ...]] = {
    "amm": ("swap", "add_liquidity", "remove_liquidity", "deposit", "withdraw", "initialize_pool"),
    "lending": ("borrow", "repay", "liquidate", "deposit_collateral", "withdraw_collateral"),
    "staking": ("stake", "unstake", "claim_reward", "delegate", "withdraw_stake"),
    "vault": ("vault", "deposit", "withdraw", "rebalance"),
    "oracle": ("update_price", "set_price", "oracle", "pyth", "switchboard", "price_feed"),
    "governance": ("propose", "vote", "execute_proposal", "cancel_proposal"),
    "bridge": ("lock", "unlock", "wrap", "unwrap", "relay"),
}

_SOLANA_RISK_PATTERNS: dict[str, tuple[str, ...]] = {
    "unchecked_account_ownership": ("owner", "is_writable", "is_signer"),
    "arbitrary_cpi": ("invoke", "invoke_signed", "cpi", "cross_program_invocation"),
    "pda_seed_collision": ("pda", "find_program_address", "create_program_address"),
    "missing_signer_check": ("is_signer",),
    "admin_upgrade_authority": ("upgrade_authority", "set_upgrade_authority", "upgrade"),
    "oracle_staleness": ("oracle", "pyth", "switchboard", "staleness", "price_feed"),
    "flash_loan_pattern": ("flash", "flash_loan", "flash_borrow"),
    "large_mutable_accounts": ("is_writable",),
}


class SolanaAnalysisRunner:
    def __init__(
        self,
        rpc_url: str | None = None,
        solscan_token: str | None = None,
        cargo_audit_cmd: str = "cargo-audit",
    ):
        self.rpc_url = rpc_url
        self.solscan_token = solscan_token
        self.cargo_audit_cmd = cargo_audit_cmd

    async def analyze(self, contract: DiscoveredContract) -> ScanResult:
        program_id = contract.address
        vulnerabilities: list[str] = []
        summaries: list[str] = []

        # --- fetch program info + IDL ---
        program_info = await asyncio.to_thread(
            fetch_solana_program_info,
            program_id,
            self.rpc_url,
            self.solscan_token,
        )
        summaries.append("solana-sources: " + ", ".join(program_info.get("source_notes", ["none"])))

        idl = program_info.get("idl")
        pseudo_source = idl_to_pseudo_source(idl) if idl else None

        # --- IDL static analysis ---
        if idl:
            idl_findings, idl_risks = self._analyse_idl(idl)
            vulnerabilities.extend([f"solana_idl:{f}" for f in idl_findings])
            if idl_risks:
                summaries.append(f"idl-risks: {len(idl_risks)} patterns detected")
        else:
            summaries.append("idl-analysis: skipped (no IDL available)")

        # --- DeFi signal/risk keyword scan on pseudo-source ---
        if pseudo_source:
            signals, risks = self._extract_defi_signals(pseudo_source)
            if signals:
                summaries.append("defi-signals: " + ",".join(signals))
            if risks:
                vulnerabilities.extend([f"defi_risk:{r}" for r in risks])
                summaries.append("defi-risks: " + ",".join(risks))
        else:
            summaries.append("defi-signals: skipped (no pseudo-source)")

        # --- cargo-audit (optional; only if source directory available) ---
        cargo_findings, cargo_summary = await self._run_cargo_audit()
        if cargo_findings:
            vulnerabilities.extend(cargo_findings)
        summaries.append(cargo_summary)

        vulnerabilities = sorted(set(vulnerabilities))
        status = "vulnerabilities_detected" if vulnerabilities else "ok"

        return ScanResult.build(
            chain="solana",
            address=program_id,
            tx_hash=contract.tx_hash,
            block_number=0,
            status=status,
            vulnerabilities=vulnerabilities,
            summary=" | ".join(summaries),
        )

    def _analyse_idl(self, idl: dict[str, Any]) -> tuple[list[str], list[str]]:
        findings: list[str] = []
        risks: list[str] = []

        instructions = idl.get("instructions", [])
        all_instruction_names = " ".join(i.get("name", "").lower() for i in instructions)
        all_account_names = " ".join(
            a.get("name", "").lower()
            for i in instructions
            for a in i.get("accounts", [])
        )
        combined = f"{all_instruction_names} {all_account_names}"

        for signal, needles in _SOLANA_SIGNAL_PATTERNS.items():
            if any(n in combined for n in needles):
                findings.append(signal)

        for risk, needles in _SOLANA_RISK_PATTERNS.items():
            if any(n in combined for n in needles):
                risks.append(risk)

        # Flag instructions with no signer accounts as potentially unsafe.
        for instruction in instructions:
            accounts = instruction.get("accounts", [])
            if accounts and not any(a.get("isSigner") for a in accounts):
                findings.append(f"no_signer_in_ix:{instruction.get('name', 'unknown')}")

        return sorted(set(findings)), sorted(set(risks))

    def _extract_defi_signals(self, text: str) -> tuple[list[str], list[str]]:
        lowered = text.lower()
        signal_map: dict[str, tuple[str, ...]] = {
            **{k: v for k, v in _SOLANA_SIGNAL_PATTERNS.items()},
            "flashloan": ("flash", "flash_loan"),
        }
        risk_map: dict[str, tuple[str, ...]] = {
            "arbitrary_cpi": ("invoke", "invoke_signed"),
            "upgrade_authority": ("upgrade_authority", "set_upgrade_authority"),
            "oracle_dependency": ("oracle", "pyth", "switchboard", "price_feed"),
            "admin_control": ("admin", "authority", "owner"),
            "large_mutable_surface": ("is_writable",),
        }

        signals = sorted({k for k, needles in signal_map.items() if any(n in lowered for n in needles)})
        risks = sorted({k for k, needles in risk_map.items() if any(n in lowered for n in needles)})
        return signals, risks

    async def _run_cargo_audit(self) -> tuple[list[str], str]:
        if shutil.which(self.cargo_audit_cmd) is None:
            return [], f"cargo-audit: skipped (not installed)"

        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                [self.cargo_audit_cmd, "--json"],
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [f"cargo_audit_timeout"], "cargo-audit: timed out"
        except Exception as exc:
            return [], f"cargo-audit: error ({exc})"

        output = completed.stdout or ""
        findings: list[str] = []
        try:
            report = json.loads(output)
            vulnerabilities = (
                report.get("vulnerabilities", {}).get("list", [])
            )
            for vuln in vulnerabilities:
                advisory = vuln.get("advisory", {})
                crate_name = advisory.get("package") or vuln.get("package", {}).get("name", "unknown")
                adv_id = advisory.get("id", "")
                findings.append(f"cargo_audit:{crate_name}:{adv_id}")
        except Exception:
            if "error" in output.lower() or "vulnerability" in output.lower():
                findings.append("cargo_audit:parse_error")

        if findings:
            return findings, f"cargo-audit: {len(findings)} advisories"
        return [], "cargo-audit: no advisories"
