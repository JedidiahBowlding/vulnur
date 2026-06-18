from __future__ import annotations

import requests


def fetch_source_code(
    address: str,
    api_key: str | None,
    base_url: str,
    chain_id: str = "1",
    timeout: int = 20,
) -> str | None:
    if not api_key:
        return None

    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    if "/v2/" in base_url:
        params["chainid"] = chain_id

    response = requests.get(base_url, params=params, timeout=timeout)
    response.raise_for_status()
    data = response.json()

    # Etherscan has deprecated V1 for some accounts/keys; retry on V2 automatically.
    if (
        str(data.get("status")) == "0"
        and isinstance(data.get("result"), str)
        and "deprecated v1 endpoint" in data["result"].lower()
    ):
        v2_url = "https://api.etherscan.io/v2/api"
        v2_params = {
            "chainid": chain_id,
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
        response = requests.get(v2_url, params=v2_params, timeout=timeout)
        response.raise_for_status()
        data = response.json()

    results = data.get("result")
    if not isinstance(results, list) or not results:
        return None

    source = results[0].get("SourceCode")
    if not source:
        return None

    if source.startswith("{{") and source.endswith("}}"):
        source = source[1:-1]
    return source
