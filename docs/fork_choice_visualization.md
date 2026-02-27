# Fork Choice Visualization

A browser-based real-time visualization of the LMD GHOST fork choice tree, served from the existing RPC server with no additional dependencies.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /lean/v0/fork_choice/ui` | Interactive D3.js visualization page |
| `GET /lean/v0/fork_choice` | JSON snapshot of the fork choice tree |

Both endpoints are served on the metrics port (`--metrics-port`, default `5054`).

## Quick Start

### Local devnet

```bash
make run-devnet
```

The local devnet runs 3 ethlambda nodes with metrics ports 8085, 8086, and 8087. Open any of them:

- http://localhost:8085/lean/v0/fork_choice/ui
- http://localhost:8086/lean/v0/fork_choice/ui
- http://localhost:8087/lean/v0/fork_choice/ui

### Standalone node

```bash
cargo run --release -- \
  --custom-network-config-dir ./config \
  --node-key ./keys/node.key \
  --node-id 0 \
  --metrics-port 5054
```

Then open http://localhost:5054/lean/v0/fork_choice/ui.

## Visualization Guide

### Color coding

| Color | Meaning |
|-------|---------|
| Green | Finalized block |
| Blue | Justified block |
| Yellow | Safe target block |
| Orange | Current head |
| Gray | Default (no special status) |

### Layout

- **Y axis**: slot number (time flows downward)
- **X axis**: fork spreading — branches appear when competing chains exist
- **Circle size**: scaled by `weight / validator_count` — larger circles have more attestation support

### Interactive features

- **Tooltips**: hover any block to see root hash, slot, proposer index, and weight
- **Auto-polling**: the page fetches fresh data every 2 seconds
- **Auto-scroll**: the view follows the head as the chain progresses

### What to look for

- **Single vertical chain**: healthy consensus, no forks
- **Horizontal branching**: competing chains — check attestation weights to see which branch validators prefer
- **Color transitions**: blocks turning green as finalization advances
- **Stalled finalization**: if justified/finalized slots stop advancing, check validator attestation activity

## JSON API

```bash
curl -s http://localhost:5054/lean/v0/fork_choice | jq .
```

Response schema:

```json
{
  "nodes": [
    {
      "root": "0x...",
      "slot": 42,
      "parent_root": "0x...",
      "proposer_index": 3,
      "weight": 5
    }
  ],
  "head": "0x...",
  "justified": { "root": "0x...", "slot": 10 },
  "finalized": { "root": "0x...", "slot": 5 },
  "safe_target": "0x...",
  "validator_count": 8
}
```

| Field | Description |
|-------|-------------|
| `nodes` | All blocks in the live chain (from finalized slot onward) |
| `nodes[].weight` | Number of latest-message attestations whose target is this block or a descendant |
| `head` | Current fork choice head root |
| `justified` | Latest justified checkpoint |
| `finalized` | Latest finalized checkpoint |
| `safe_target` | Block root selected with a 2/3 validator threshold |
| `validator_count` | Total validators in the head state |
