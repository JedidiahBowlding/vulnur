from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import Settings
from .models import DiscoveredContract, ScanResult
from .sources import fetch_source_code


class AnalysisRunner:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def analyze(
        self,
        contract: DiscoveredContract,
        rpc_url: str | None = None,
        explorer_chain_id: str | None = None,
    ) -> ScanResult:
        vulnerabilities: list[str] = []
        summaries: list[str] = []
        status = "ok"

        if rpc_url:
            myth_findings, myth_summary = await self._run_mythril(contract.address, rpc_url)
            vulnerabilities.extend(myth_findings)
            summaries.append(myth_summary)
        else:
            summaries.append("mythril: skipped (rpc unavailable for chain)")

        source_code = None
        try:
            source_code = fetch_source_code(
                contract.address,
                self.settings.etherscan_api_key,
                self.settings.etherscan_base_url,
                chain_id=explorer_chain_id or self.settings.etherscan_chain_id,
            )
        except Exception as exc:
            summaries.append(f"source-fetch: failed ({exc})")

        if source_code:
            slither_findings, slither_summary = await self._run_slither(source_code)
            vulnerabilities.extend(slither_findings)
            summaries.append(slither_summary)

            echidna_findings, echidna_summary = await self._run_echidna(source_code)
            vulnerabilities.extend(echidna_findings)
            summaries.append(echidna_summary)

            defi_signals, defi_risks = self._extract_defi_signals(source_code)
            if defi_signals:
                summaries.append("defi-signals: " + ",".join(defi_signals))
            if defi_risks:
                vulnerabilities.extend([f"defi_risk:{risk}" for risk in defi_risks])
                summaries.append("defi-risks: " + ",".join(defi_risks))
        else:
            summaries.append("slither: skipped (source unavailable)")
            summaries.append("echidna: skipped (source unavailable)")

        vulnerabilities = sorted(set(vulnerabilities))
        if vulnerabilities:
            status = "vulnerabilities_detected"

        return ScanResult.build(
            chain=contract.chain,
            address=contract.address,
            tx_hash=contract.tx_hash,
            block_number=contract.block_number,
            status=status,
            vulnerabilities=vulnerabilities,
            summary=" | ".join(summaries),
        )

    async def _run_mythril(self, address: str, rpc_url: str) -> tuple[list[str], str]:
        cmd = [
            self.settings.mythril_cmd,
            "analyze",
            "-a",
            address,
            "--rpc",
            rpc_url,
            "--execution-timeout",
            "60",
            "--max-depth",
            "32",
        ]
        return await self._run_tool("mythril", cmd)

    async def _run_slither(self, source_code: str) -> tuple[list[str], str]:
        with tempfile.TemporaryDirectory(prefix="monitor-slither-") as temp_dir:
            source_path = Path(temp_dir) / "ScannedContract.sol"
            source_path.write_text(source_code, encoding="utf-8")
            cmd = [self.settings.slither_cmd, str(source_path), "--json", "-"]
            return await self._run_tool("slither", cmd)

    async def _run_echidna(self, source_code: str) -> tuple[list[str], str]:
        with tempfile.TemporaryDirectory(prefix="monitor-echidna-") as temp_dir:
            source_path = Path(temp_dir) / "ScannedContract.sol"
            source_path.write_text(source_code, encoding="utf-8")
            cmd = [
                self.settings.echidna_cmd,
                str(source_path),
                "--test-limit",
                "500",
                "--format",
                "json",
            ]
            return await self._run_tool("echidna", cmd)

    async def _run_tool(self, name: str, cmd: list[str]) -> tuple[list[str], str]:
        executable = cmd[0]
        if shutil.which(executable) is None:
            return [f"{name}_unavailable"], f"{name}: command not found ({executable})"

        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [f"{name}_timeout"], f"{name}: timed out"
        except Exception as exc:
            return [f"{name}_error"], f"{name}: failed to run ({exc})"

        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        findings = self._extract_findings(name, output)
        failure_summary = self._summarize_tool_failure(name, output)

        if completed.returncode != 0 and not findings:
            if failure_summary:
                return [], failure_summary
            findings.append(f"{name}_nonzero_exit")

        if findings:
            return findings, f"{name}: {len(findings)} findings"
        return [], f"{name}: no findings"

    def _summarize_tool_failure(self, tool: str, output: str) -> str | None:
        lowered = output.lower()

        if "no such file or directory: 'solc'" in lowered:
            return f"{tool}: compiler unavailable (solc not installed)"

        if tool == "slither":
            if "cryticcompile" in lowered and "error" in lowered:
                return "slither: compilation failed"
            return None

        if tool == "echidna":
            if "abi is empty" in lowered:
                return "echidna: skipped (no testable ABI/functions found)"
            if "doesn't support versions of solc before" in lowered:
                return "echidna: skipped (unsupported compiler version)"
            if "constructor arguments are required" in lowered:
                return "echidna: skipped (constructor arguments required)"
            if "couldn't compile given file" in lowered:
                return "echidna: compilation failed"

        return None

    def _extract_findings(self, tool: str, output: str) -> list[str]:
        findings: set[str] = set()

        # Try JSON parsing first when possible.
        try:
            parsed = json.loads(output)
            if tool == "slither":
                for detector in parsed.get("results", {}).get("detectors", []):
                    check = detector.get("check")
                    impact = detector.get("impact")
                    if check and impact:
                        findings.add(f"slither:{check}:{impact}")
            elif tool == "echidna":
                if isinstance(parsed, list):
                    for entry in parsed:
                        if isinstance(entry, dict) and entry.get("status") == "solved":
                            name = entry.get("name", "echidna_property")
                            findings.add(f"echidna:{name}:violated")
        except Exception:
            pass

        # Fallback keyword scan for plain text outputs.
        lowered = output.lower()
        keyword_map = {
            "reentrancy": "reentrancy",
            "integer overflow": "integer_overflow",
            "underflow": "integer_underflow",
            "tx.origin": "tx_origin_auth",
            "uninitialized": "uninitialized_state",
            "delegatecall": "unsafe_delegatecall",
            "selfdestruct": "dangerous_selfdestruct",
            "suicidal": "dangerous_selfdestruct",
            "unchecked call": "unchecked_call",
            "assertion failed": "property_violation",
        }
        for needle, label in keyword_map.items():
            if needle in lowered:
                findings.add(f"{tool}:{label}")

        return sorted(findings)

    def _extract_defi_signals(self, source_code: str) -> tuple[list[str], list[str]]:
        lowered = source_code.lower()

        signal_keywords: dict[str, tuple[str, ...]] = {
            "amm": (
                "swap",
                "addliquidity",
                "removeliquidity",
                "getamountout",
                "pair",
            ),
            "lending": (
                "borrow",
                "repay",
                "liquidat",
                "collateral",
                "interest",
            ),
            "flashloan": (
                "flashloan",
                "flash loan",
                "onflashloan",
            ),
            "oracle": (
                "oracle",
                "latestanswer",
                "pricefeed",
                "aggregatorv3interface",
            ),
            "staking": (
                "stake",
                "unstake",
                "reward",
                "claimreward",
            ),
            "vault": (
                "vault",
                "deposit",
                "withdraw",
                "shares",
            ),
        }

        risk_keywords: dict[str, tuple[str, ...]] = {
            "upgradeable_logic": ("delegatecall", "upgrade", "implementation"),
            "admin_pause_control": ("onlyowner", "onlyadmin", "pause", "unpause"),
            "external_call_surface": ("call(", "staticcall", "callcode", "delegatecall"),
            "oracle_dependency": ("oracle", "latestanswer", "getprice", "pricefeed"),
        }

        signals: list[str] = []
        for signal, needles in signal_keywords.items():
            if any(needle in lowered for needle in needles):
                signals.append(signal)

        risks: list[str] = []
        for risk, needles in risk_keywords.items():
            if any(needle in lowered for needle in needles):
                risks.append(risk)

        return sorted(set(signals)), sorted(set(risks))
