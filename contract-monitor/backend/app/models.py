from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class DiscoveredContract:
    chain: str
    address: str
    tx_hash: str
    block_number: int


@dataclass
class ScanResult:
    chain: str
    address: str
    tx_hash: str
    block_number: int
    status: str
    vulnerabilities: list[str]
    summary: str
    scanned_at: str

    @classmethod
    def build(
        cls,
        chain: str,
        address: str,
        tx_hash: str,
        block_number: int,
        status: str,
        vulnerabilities: list[str],
        summary: str,
    ) -> "ScanResult":
        return cls(
            chain=chain,
            address=address,
            tx_hash=tx_hash,
            block_number=block_number,
            status=status,
            vulnerabilities=vulnerabilities,
            summary=summary,
            scanned_at=datetime.now(tz=timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
