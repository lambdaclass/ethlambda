# Checkpoint Sync

## Overview

Checkpoint sync allows a new consensus node to skip replaying the entire chain from genesis. Instead, it downloads a recent finalized state from a running peer and starts from there. This mitigates long-range attacks by starting from a recent trusted checkpoint.

## Usage

Checkpoint sync still requires the network config files (genesis, validators, bootnodes, etc.). The genesis config is needed to verify the downloaded state: checkpoint sync only replaces the starting state, not node configuration.

Pass the `--checkpoint-sync-url` flag when starting ethlambda:

```bash
ethlambda \
  --checkpoint-sync-url <URL> \
  --genesis ./network-config/config.yaml \
  --validators ./network-config/annotated_validators.yaml \
  --bootnodes ./network-config/nodes.yaml \
  --validator-config ./network-config/validator-config.yaml \
  --hash-sig-keys-dir ./network-config/hash-sig-keys \
  --node-key ./node.key \
  --node-id ethlambda_0
```

Where `<URL>` is the address of a checkpoint source (see [Checkpoint Sources](#checkpoint-sources) below).

State already on disk takes precedence over both checkpoint sync and genesis: if the data directory holds a previous run's chain state for this network, the node resumes from it. `--checkpoint-sync-url` is the fallback for when there is nothing resumable on disk, or when what is there has fallen too far behind (see [Restarts and Existing State](#restarts-and-existing-state)). With no resumable state and no URL, the node initializes from genesis.

## Checkpoint Sources

### Direct peer

Any running node that serves the finalized state as SSZ can be used as a checkpoint source, not just ethlambda. For ethlambda nodes, the endpoint is `/lean/v0/states/finalized`.

This is the simplest option, with no additional infrastructure needed. The trade-off is that you trust a single peer to provide a correct finalized state.

### Leanpoint

[Leanpoint](https://github.com/blockblaz/leanpoint) is a dedicated checkpoint sync provider. It polls multiple nodes and only serves state when 50%+ agree on finality, adding a layer of consensus validation.

This is the recommended option for production deployments since it reduces trust in any single peer.

## How It Works

1. **Fetch and verify**: The node sends an HTTP GET to the provided URL requesting the SSZ-encoded finalized state. Once downloaded, the state is decoded and verified against the local genesis config (see [Verification Checks](#verification-checks) below).

   Timeouts:
   - **Connect**: 15 seconds (fail fast if peer is unreachable)
   - **Read**: 15 seconds of inactivity that resets on each successful read, so large states can download as long as data keeps flowing

2. **Initialize**: The node stores the block header and the full state from the checkpoint. No block body is stored since it isn't available from the checkpoint. The node does not need the anchor block body to participate from this point forward.

### Failure and success

If any step fails (network error, decoding error, verification failure), the node logs the error and exits. There is no automatic retry; restart the node to try again. The database is not modified until verification succeeds, so a failed checkpoint sync leaves the data directory clean.

After successful initialization, the node starts normally: it connects to the P2P network and begins participating from the checkpoint slot.

## Restarts and Existing State

A node restarted against a populated data directory resumes from disk rather than re-initializing, so no flag is needed to preserve the chain across a redeploy. The decision is made before any download:

| State in data directory | `--checkpoint-sync-url` | Result |
| ------------------------- | ------------------------- | -------- |
| None | omitted | Initialize from genesis |
| None | set | Checkpoint sync |
| Present, head within the resume window | either | Resume from disk (no download) |
| Present, head beyond the resume window | set | Checkpoint sync |
| Present, head beyond the resume window | omitted | Resume from disk anyway, with a warning |
| **From another network** | either | **Startup aborts** (see [Foreign State](#foreign-state)) |

The resume window is `MAX_RESUMABLE_DB_STATE_AGE` (450 slots, ~30 minutes at 4-second slots) measured as `current_slot - head_slot`. Staleness is measured against the head, not the finalized checkpoint, so a node whose head is current still resumes during a finality stall.

Beyond that window the node prefers a checkpoint when one is offered, since catching up over P2P costs more than downloading a recent state. With no URL configured there is no anchor to switch to, so the node simply runs against the data directory it was given: that is the setup that was asked for. The warning is there because range sync may not be able to close a gap this large. Peers prune block signatures past `SIGNATURE_PRUNING_RANGE` (21600 slots, ~1 day), so beyond that horizon they cannot serve the history the node is missing and it needs a checkpoint URL to catch up at all. The warning logs the gap so this is visible in the boot log.

When a checkpoint URL *is* set and every URL fails, the node exits rather than falling back to the stale state on disk. This is intentional: configuring the flag asks for a specific anchor, so an unreachable source is a misconfiguration worth surfacing at boot instead of quietly starting a node that is hours behind. Omitting the flag is how you ask for "resume whatever is on disk"; that path never exits.

To deliberately discard existing state and start over from genesis or from a checkpoint, remove the data directory first. Checkpoint sync itself writes its anchor state on top without clearing existing data.

### Foreign State

Persisted state is accepted only after it is verified against the local genesis config: same `GENESIS_TIME` and the same validator registry (count, sequential indices, and both pubkeys per validator). The validator set is fixed at genesis, so any state of this chain must carry exactly that registry. These are the same identity checks checkpoint sync applies to a downloaded state, sharing one implementation.

If the data directory belongs to a different network, startup **aborts** with `persisted state does not match the configured genesis: …`. It is not treated as an empty directory, because initializing a new anchor on top would leave the foreign chain's rows in place, and the slot-indexed reads behind `BlocksByRange` would then serve those blocks to peers. Point `--data-dir` at the right directory, or remove it.

Note that a genesis time comparison alone would not catch a network that was regenerated with the same `GENESIS_TIME` but a different validator set, which is why the whole registry is compared.

## Verification Checks

All checks are performed before a downloaded checkpoint state is accepted. The genesis-identity subset (marked below) is shared with the resume-from-disk path:

| Check | What it catches |
| ------- | ----------------- |
| Slot > 0 | Checkpoint state cannot be genesis (slot 0) |
| Validators non-empty | State must contain validators |
| Genesis time matches *(shared)* | Wrong network or misconfigured peer |
| Validator count matches *(shared)* | Validator set size differs from genesis config |
| Sequential validator indices *(shared)* | Indices must be 0, 1, 2, ... in order |
| Validator pubkeys match *(shared)* | Validator identity differs from genesis config |
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
