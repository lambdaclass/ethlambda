#!/usr/bin/env bash
#
# Send demo transactions to the EL while the engine-api demo is running.
# ethrex includes them in the next payload it builds for ethlambda, so they
# show up inside the Lean block's execution payload one slot later.
#
# Usage:
#   scripts/engine-api-demo/send-txs.sh [count]      # default 5
#
# Env overrides:
#   RPC_URL  (http://127.0.0.1:8545)   EL HTTP-RPC endpoint
#   KEY      (hardhat/anvil dev key #0, prefunded in genesis-el.json)
#
# Requires `uv` (signs with an ephemeral eth-account; no permanent install).

COUNT="${1:-5}"
RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
# Hardhat/Anvil dev account #0 (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266),
# prefunded with 10k ETH in genesis-el.json. Local-dev key, never use on a
# real network.
KEY="${KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

if ! command -v uv >/dev/null 2>&1; then
    echo "ERROR: uv not found — install it or send transactions with your own tooling (cast, web3)." >&2
    exit 1
fi

COUNT="$COUNT" RPC_URL="$RPC_URL" KEY="$KEY" uv run --quiet --with eth-account python3 - <<'PY'
import json
import os
import urllib.request

from eth_account import Account

rpc_url = os.environ["RPC_URL"]
count = int(os.environ["COUNT"])
acct = Account.from_key(os.environ["KEY"])


def rpc(method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = urllib.request.Request(
        rpc_url, data=body, headers={"content-type": "application/json"}
    )
    resp = json.load(urllib.request.urlopen(req, timeout=10))
    if "error" in resp:
        raise RuntimeError(f"{method}: {resp['error']}")
    return resp["result"]


chain_id = int(rpc("eth_chainId", []), 16)
nonce = int(rpc("eth_getTransactionCount", [acct.address, "pending"]), 16)
print(f"sender {acct.address} | chainId {chain_id} | starting nonce {nonce}")

for i in range(count):
    tx = {
        "chainId": chain_id,
        "nonce": nonce + i,
        # Self-transfers: no recipient setup needed, still real transactions.
        "to": acct.address,
        "value": 10**15,  # 0.001 ETH
        "gas": 21_000,
        "maxFeePerGas": 10 * 10**9,
        "maxPriorityFeePerGas": 10**9,
        "type": 2,
    }
    raw = Account.sign_transaction(tx, acct.key).raw_transaction
    tx_hash = rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
    print(f"  sent tx {nonce + i}: {tx_hash}")

print(f"{count} transactions in the EL mempool — watch the next slot's block.")
PY
