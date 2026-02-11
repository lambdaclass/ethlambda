# Checkpoint Sync

## Overview

Checkpoint sync allows a new consensus node to skip replaying the entire chain from genesis. Instead, it downloads a recent finalized state from a running peer and starts from there.

This is useful for quickly joining an already-running network, and mitigates long-range attacks by starting from a recent trusted checkpoint.

## Usage

Checkpoint sync still requires a full network config directory (`--custom-network-config-dir`). The genesis config is needed to verify the downloaded state — checkpoint sync only replaces the starting state, not node configuration.

Pass the `--checkpoint-sync-url` flag when starting ethlambda:

```bash
# Sync from a running ethlambda peer
ethlambda \
  --checkpoint-sync-url http://peer:5054 \
  --custom-network-config-dir ./network-config \
  --node-key ./node.key \
  --node-id ethlambda_0

# Sync from a leanpoint provider
ethlambda \
  --checkpoint-sync-url http://leanpoint:5555 \
  --custom-network-config-dir ./network-config \
  --node-key ./node.key \
  --node-id ethlambda_0
```

When `--checkpoint-sync-url` is omitted, the node initializes from genesis.

## Checkpoint Sources

### Direct peer

Any running ethlambda node serves its finalized state over HTTP. Point `--checkpoint-sync-url` at the node's RPC address (default port `5054`):

```
--checkpoint-sync-url http://peer:5054
```

This is the simplest option — no additional infrastructure needed. The trade-off is that you trust a single peer to provide a correct finalized state. Any lean consensus client that serves the `/lean/v0/states/finalized` endpoint can be used as a checkpoint source, not just ethlambda.

### Leanpoint

[Leanpoint](https://github.com/blockblaz/leanpoint) is a dedicated checkpoint sync provider. It polls multiple nodes and only serves state when 50%+ agree on finality, adding a layer of consensus validation.

```
--checkpoint-sync-url http://leanpoint:5555
```

This is the recommended option for production deployments since it reduces trust in any single peer.

## How It Works

```
                  ┌──────────┐
                  │ Starting │
                  │   Node   │
                  └────┬─────┘
                       │
          1. HTTP GET {url}/lean/v0/states/finalized
                       │
                       ▼
              ┌────────────────┐
              │ Checkpoint     │     SSZ-encoded State
              │ Source         │◄── (peer or leanpoint)
              └────────┬───────┘
                       │
          2. SSZ decode → State
                       │
                       ▼
              ┌────────────────┐
              │ Verify against │     Genesis config provides
              │ local genesis  │◄── expected validators,
              │ config         │    genesis time
              └────────┬───────┘
                       │
          3. Store::from_anchor_state
                       │
                       ▼
              ┌────────────────┐
              │ Store          │     Header + state stored
              │ initialized    │     (no block body)
              └────────────────┘
```

1. **Fetch**: HTTP GET to `{url}/lean/v0/states/finalized` with `Accept: application/octet-stream`. The response body is an SSZ-encoded `State`.

   Timeouts:
   - **Connect**: 15 seconds (fail fast if peer is unreachable)
   - **Read**: 15 seconds of inactivity — resets on each successful read, so large states can download as long as data keeps flowing

2. **Verify**: `verify_checkpoint_state` checks the downloaded state against the local genesis config. See [Verification Checks](#verification-checks) below.

3. **Initialize**: `Store::from_anchor_state` stores the block header (extracted from `state.latest_block_header`) and the full state. No block body is stored since it isn't available from the checkpoint (the node does not need the block body to participate from this point forward).

### Failure and success

If any step fails (network error, verification failure, SSZ decode error), the node logs the error and exits. There is no automatic retry — restart the node to try again. The database is not modified until verification succeeds, so a failed checkpoint sync leaves the data directory clean.

After successful initialization, the node starts normally — it spawns the blockchain actor, connects to the P2P network, and begins participating from the checkpoint slot.

If the data directory (`./data`) already contains state from a previous run, checkpoint sync writes the new anchor state on top without clearing existing data. For a clean checkpoint sync, remove the data directory first.

## Verification Checks

All checks are performed by `verify_checkpoint_state` before the state is accepted:

| Check | Error | What it catches |
|-------|-------|----------------|
| Slot > 0 | `SlotIsZero` | Checkpoint state cannot be genesis (slot 0) |
| Validators non-empty | `NoValidators` | State must contain validators |
| Genesis time matches | `GenesisTimeMismatch` | Wrong network or misconfigured peer |
| Validator count matches | `ValidatorCountMismatch` | Validator set size differs from genesis config |
| Sequential validator indices | `NonSequentialValidatorIndex` | Indices must be 0, 1, 2, ... in order |
| Validator pubkeys match | `ValidatorPubkeyMismatch` | Validator identity differs from genesis config |
| Finalized slot <= state slot | `FinalizedExceedsStateSlot` | Finalized checkpoint cannot be in the future |
| Justified slot >= finalized slot | `JustifiedPrecedesFinalized` | Justified must be at or after finalized |
| Same-slot checkpoints have matching roots | `JustifiedFinalizedRootMismatch` | If justified and finalized are at the same slot, they must agree on the root |
| Block header slot <= state slot | `BlockHeaderSlotExceedsState` | Block header cannot be ahead of the state |
| Block header root matches finalized | `BlockHeaderFinalizedRootMismatch` | If header is at finalized slot, its root must match the finalized root |
| Block header root matches justified | `BlockHeaderJustifiedRootMismatch` | If header is at justified slot, its root must match the justified root |

Additionally, HTTP errors and SSZ decoding failures are caught as `Http` and `SszDecode` errors before verification runs.

## Security Considerations

### Trust model

Checkpoint sync operates under a [**weak subjectivity**](https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity) assumption. In proof of work, any node can objectively determine the canonical chain by verifying the most cumulative work. Proof of stake doesn't have this property — validators can costlessly sign multiple forks, so a node that wasn't online to observe the chain in real time cannot distinguish the real chain from a fabricated one using protocol rules alone.

Weak subjectivity resolves this: a new node obtains a recent trusted state through a social channel (a peer, a checkpoint provider, a block explorer) and starts from there. Nodes that are always online are unaffected — they continuously track the chain and don't need external trust.

What you **are** trusting:
- The checkpoint source is honest about which state is finalized
- The state hasn't been crafted to put you on a fork that diverged within the weak subjectivity period

What verification **does** protect against:
- Wrong network (genesis time mismatch)
- Wrong validator set (pubkey or count mismatch)
- Structurally invalid states (impossible slot orderings, inconsistent checkpoints)
- Corrupted data (SSZ decode failures)

What verification **does not** protect against:
- A checkpoint source that serves a structurally valid state on a minority fork — it will pass all checks but put you on the wrong chain. This is why the choice of checkpoint source matters (see [Reducing trust with leanpoint](#reducing-trust-with-leanpoint)).

### Reducing trust with leanpoint

Using [leanpoint](https://github.com/blockblaz/leanpoint) reduces the trust requirement from a single peer to a majority of polled nodes. It only serves a finalized state when 50%+ of nodes agree, making it harder for a single malicious node to serve a crafted state.

### Recommendations

- For **devnets and testing**: syncing from any peer is fine
- For **production networks**: prefer leanpoint or verify the checkpoint against multiple independent sources
