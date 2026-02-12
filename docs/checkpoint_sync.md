# Checkpoint Sync

## Overview

Checkpoint sync allows a new consensus node to skip replaying the entire chain from genesis. Instead, it downloads a recent finalized state from a running peer and starts from there. This mitigates long-range attacks by starting from a recent trusted checkpoint.

## Usage

Checkpoint sync still requires a full network config directory (`--custom-network-config-dir`). The genesis config is needed to verify the downloaded state: checkpoint sync only replaces the starting state, not node configuration.

Pass the `--checkpoint-sync-url` flag when starting ethlambda:

```bash
ethlambda \
  --checkpoint-sync-url <URL> \
  --custom-network-config-dir ./network-config \
  --node-key ./node.key \
  --node-id ethlambda_0
```

Where `<URL>` is the address of a checkpoint source (see [Checkpoint Sources](#checkpoint-sources) below).

When `--checkpoint-sync-url` is omitted, the node initializes from genesis.

## Checkpoint Sources

### Direct peer

Any running node that serves the `/lean/v0/states/finalized` endpoint can be used as a checkpoint source, not just ethlambda. Point `--checkpoint-sync-url` at the node's RPC address (default port `5054`):

```bash
--checkpoint-sync-url http://peer:5054
```

This is the simplest option, with no additional infrastructure needed. The trade-off is that you trust a single peer to provide a correct finalized state.

### Leanpoint

[Leanpoint](https://github.com/blockblaz/leanpoint) is a dedicated checkpoint sync provider. It polls multiple nodes and only serves state when 50%+ agree on finality, adding a layer of consensus validation.

```bash
--checkpoint-sync-url http://leanpoint:5555
```

This is the recommended option for production deployments since it reduces trust in any single peer.

## How It Works

1. **Fetch and verify**: The node sends an HTTP GET to `{url}/lean/v0/states/finalized` requesting the SSZ-encoded finalized state. Once downloaded, the state is decoded and verified against the local genesis config (see [Verification Checks](#verification-checks) below).

   Timeouts:
   - **Connect**: 15 seconds (fail fast if peer is unreachable)
   - **Read**: 15 seconds of inactivity that resets on each successful read, so large states can download as long as data keeps flowing

2. **Initialize**: The node stores the block header and the full state from the checkpoint. No block body is stored since it isn't available from the checkpoint. The node does not need the anchor block body to participate from this point forward.

### Failure and success

If any step fails (network error, decoding error, verification failure), the node logs the error and exits. There is no automatic retry; restart the node to try again. The database is not modified until verification succeeds, so a failed checkpoint sync leaves the data directory clean.

After successful initialization, the node starts normally: it connects to the P2P network and begins participating from the checkpoint slot.

If the data directory (`./data`) already contains state from a previous run, checkpoint sync writes the new anchor state on top without clearing existing data. For a clean checkpoint sync, remove the data directory first.

## Verification Checks

All checks are performed before the state is accepted:

| Check | What it catches |
| ------- | ----------------- |
| Slot > 0 | Checkpoint state cannot be genesis (slot 0) |
| Validators non-empty | State must contain validators |
| Genesis time matches | Wrong network or misconfigured peer |
| Validator count matches | Validator set size differs from genesis config |
| Sequential validator indices | Indices must be 0, 1, 2, ... in order |
| Validator pubkeys match | Validator identity differs from genesis config |
| Finalized slot <= state slot | Finalized checkpoint cannot be in the future |
| Justified slot >= finalized slot | Justified must be at or after finalized |
| Same-slot checkpoints have matching roots | If justified and finalized are at the same slot, they must agree on the root |
| Block header slot <= state slot | Block header cannot be ahead of the state |
| Block header root matches finalized | If header is at finalized slot, its root must match the finalized root |
| Block header root matches justified | If header is at justified slot, its root must match the justified root |

HTTP errors and SSZ decoding failures are caught before verification runs.

## Security Considerations

### Trust model

Checkpoint sync operates under a [**weak subjectivity**](https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity) assumption. In proof of work, any node can objectively determine the canonical chain by verifying the most cumulative work. Proof of stake doesn't have this property: validators can costlessly sign multiple forks, so a node that wasn't online to observe the chain in real time cannot distinguish the real chain from a fabricated one using protocol rules alone.

Weak subjectivity resolves this: a new node obtains a recent trusted state through a social channel (a peer, a checkpoint provider, a block explorer) and starts from there. Nodes that are always online are unaffected because they continuously track the chain and don't need external trust.

What you **are** trusting:

- The checkpoint source is honest about which state is finalized
- The state hasn't been crafted to put you on a fork that diverged within the weak subjectivity period

What verification **does** protect against:

- Wrong network (genesis time mismatch)
- Wrong validator set (pubkey or count mismatch)
- Structurally invalid states (impossible slot orderings, inconsistent checkpoints)
- Corrupted data (SSZ decode failures)

What verification **does not** protect against:

- A checkpoint source that serves a structurally valid state on a minority fork. It will pass all checks but put you on the wrong chain. This is why the choice of checkpoint source matters.
