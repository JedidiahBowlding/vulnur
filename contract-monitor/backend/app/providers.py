from web3 import Web3

from .models import DiscoveredContract


class EthereumWatcher:
    def __init__(self, rpc_url: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

    def latest_block_number(self) -> int:
        return int(self.w3.eth.block_number)

    def find_contract_creations(
        self, start_block: int, end_block: int
    ) -> list[DiscoveredContract]:
        found: list[DiscoveredContract] = []
        for block_number in range(start_block, end_block + 1):
            block = self.w3.eth.get_block(block_number, full_transactions=True)
            for tx in block.transactions:
                # A contract creation transaction has no recipient address.
                if tx["to"] is not None:
                    continue

                receipt = self.w3.eth.get_transaction_receipt(tx["hash"])
                contract_address = receipt.get("contractAddress")
                if not contract_address:
                    continue

                found.append(
                    DiscoveredContract(
                        chain="ethereum",
                        address=Web3.to_checksum_address(contract_address),
                        tx_hash=tx["hash"].hex(),
                        block_number=block_number,
                    )
                )
        return found
