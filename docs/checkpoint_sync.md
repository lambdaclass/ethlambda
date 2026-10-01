# Checkpoint Sync

## Overview

Checkpoint sync allows a new consensus node to skip replaying the entire chain from genesis. Instead, it downloads a recent finalized state from a running peer and starts from there. This mitigates long-range attacks by starting from a recent trusted checkpoint.

Both `ethlambda node` (the lean consensus chain) and `ethlambda beacon` (an Ethereum Beacon Chain gossip follower, mainnet by default, or another network via `--network`) use it. The two paths share the retry loop and the URL fan-out, and now share the same fetch order, but talk to different endpoints and verify a different container shape; where they differ, this document says so.

## Usage

### `ethlambda node`

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

### `ethlambda beacon`

`beacon` takes no genesis config, validator registry, or bootnode file of its own: it takes `--network` instead, naming a built-in network or a directory of published network files (see [`cli.md`](cli.md)). `genesis_time`, `genesis_validators_root`, and the bootnode list all come from whichever network `--network` resolves to; for the built-in networks (`mainnet`, the default, plus `sepolia`, `hoodi` and `plataberget`), they are built into the binary (see `CLAUDE.md`'s "Built-in networks").

```bash
ethlambda beacon --network <network> --checkpoint-sync-url <URL>
```

The anchor precedence is, in order: a resumable data directory, then `--checkpoint-sync-url`, then, for a loaded network only, that directory's own `genesis.ssz`, then abort. The URL is therefore **required** on a fresh data directory only for a built-in network, unlike on `node`: this follower imports nothing past its anchor, so anchoring a built-in network at genesis would leave it parked at slot 0 while claiming to follow a live chain. A loaded network's own genesis state is a legitimate anchor instead, since a freshly started devnet has no checkpoint provider at slot 0 and this is the only way to join one. With neither a resumable DB, a URL, nor (for a loaded network) a genesis fallback, startup aborts with `CheckpointSyncError::BeaconGenesisSync`. A data directory already anchored from a previous run resumes exactly as `node`'s does, without a URL, subject to the same resume window (see [Restarts and Existing State](#restarts-and-existing-state)).

## Checkpoint Sources

### Direct peer (lean)

Any running node that serves the finalized state as SSZ can be used as a checkpoint source, not just ethlambda. For ethlambda nodes, the endpoint is `/lean/v0/states/finalized`.

This is the simplest option, with no additional infrastructure needed. The trade-off is that you trust a single peer to provide a correct finalized state.

### Leanpoint (lean)

[Leanpoint](https://github.com/blockblaz/leanpoint) is a dedicated checkpoint sync provider. It polls multiple nodes and only serves state when 50%+ agree on finality, adding a layer of consensus validation.

This is the recommended option for production deployments since it reduces trust in any single peer.

### Any standard Beacon API provider (beacon)

`ethlambda beacon` speaks the standard Beacon API against `--checkpoint-sync-url`, so any conforming server works as a source: a public checkpoint-sync provider, an infrastructure endpoint, or another beacon client's own API port. Nothing ethlambda-specific is required of the peer; it only has to answer the two endpoints in [How It Works](#how-it-works) below the way the spec describes them.

## How It Works

1. **Fetch, sequentially**: the node downloads the finalized state first, decodes and verifies it, then downloads the anchor block. State before block, on both chains, because the block is addressed by a slot that only the state carries; the two fetches used to run concurrently on lean (`tokio::try_join!`), but the beacon path cannot do that (it cannot address its block request until it has read the anchor block's slot off the state), so both now run sequentially. This is lighthouse's order.

   | | `node` (lean) | `beacon` |
   | --- | --- | --- |
   | Finalized state | `GET /lean/v0/states/finalized` | `GET /eth/v2/debug/beacon/states/finalized` |
   | Anchor block | `GET /lean/v0/blocks/finalized` | `GET /eth/v2/beacon/blocks/{slot}`, where `slot` is read off `state.latest_block_header.slot` |

   Both endpoints on both chains mean "whatever is finalized right now", so the peer can advance finalization between the state and block requests; a mismatched pair is retried rather than treated as a hard failure (see [Anchor Pairing](#anchor-pairing) below).

   Timeouts, shared by both chains:
   - **Connect**: 15 seconds (fail fast if peer is unreachable)
   - **Read**: 15 seconds of inactivity that resets on each successful read, so large states can download as long as data keeps flowing

2. **Fork resolution (beacon only)**: SSZ carries no type tag, so decoding the downloaded state first requires knowing which fork's container shape to decode it as. `BeaconState::slot_from_ssz` reads the slot straight off its fixed byte offset, without decoding the rest of the container; the configured fork schedule then names the fork at that slot. The `Eth-Consensus-Version` response header is not consulted at all. This matches lighthouse's checkpoint-sync client, and removes any dependence on the peer setting that header correctly: a self-describing slot cannot lie about its own fork the way a header can. The anchor block is decoded the same way, reusing the gossip path's own slot-peeking decoder.

3. **Initialize**: the node stores the anchor block's header, its body (present unless the fetched block's own body happens to be empty, same as any other block), and the full state from the checkpoint. On `node`, persisting the block itself also means it can be served over `BlocksByRoot`; without that, peers requesting the anchor by root would get a synthetic block whose hash differs from `latest_finalized.root` and would score-penalize this node. `beacon`'s req/resp protocol has no `BlocksByRoot` handler yet, so that benefit doesn't apply there today; the block is stored anyway, since the pairing check above needs it.

#### Gloas anchor: the payload envelope (beacon only)

A gloas block's execution payload is not in the block, so a node anchored on
one holds the block and state but not the payload its children may build on.
Once the chain actor is running, a node that anchored on a gloas block with no
stored envelope asks the checkpoint URLs for it, in order:
`GET /eth/v1/beacon/execution_payload_envelopes/{anchor_root}` as SSZ. A
success is handed to the chain actor as `new_execution_payload_envelope`, the
same entry a gossiped envelope takes, so the bid check, the column check and
the verification all apply. The fetch runs in the background and never delays
startup.

It is a fast path and nothing depends on it. A `404` means the peer does not
know the payload, **not** that the payload is empty, so the node concludes
nothing from it; any failure (network, decoding, an envelope naming another
block) is logged at `info` and ignored. Without the envelope, the by-root
request that fires when a FULL child arrives recovers it.

### Failure and success

If any step fails (network error, decoding error, verification failure), the node logs the error and exits. There is no automatic retry; restart the node to try again. The database is not modified until verification succeeds, so a failed checkpoint sync leaves the data directory clean.

After successful initialization, the node starts normally: `node` connects to the P2P network and begins participating from the checkpoint slot; `beacon` joins the resolved network's gossip and follows the chain from the anchor, importing blocks (a gloas anchor starts EMPTY, see [the envelope](#gloas-anchor-the-payload-envelope-beacon-only)).

## Restarts and Existing State

A node restarted against a populated data directory resumes from disk rather than re-initializing, so no flag is needed to preserve the chain across a redeploy. The decision is made before any download, and is the same shape on both chains except for one row:

| State in data directory | `--checkpoint-sync-url` | `node` | `beacon` |
| --- | --- | --- | --- |
| None | omitted | Initialize from genesis | Built-in network: abort, `CheckpointSyncError::BeaconGenesisSync` (no genesis-sync path). Loaded network: initialize from the directory's own `genesis.ssz` |
| None | set | Checkpoint sync | Checkpoint sync |
| Present, head within the resume window | either | Resume from disk (no download) | Resume from disk (no download) |
| Present, head beyond the resume window | set | Checkpoint sync | Checkpoint sync |
| Present, head beyond the resume window | omitted | Resume from disk anyway, with a warning | Resume from disk anyway, with a warning |
| **Wrong network, or the other chain** | either | **Startup aborts** (see [Foreign State](#foreign-state)) | **Startup aborts** (see [Foreign State](#foreign-state)) |

The resume window is `MAX_RESUMABLE_DB_STATE_AGE` (450 slots) measured as `current_slot - head_slot`. Staleness is measured against the head, not the finalized checkpoint, so a node whose head is current still resumes during a finality stall. The same 450-slot window means a different wall-clock budget on each chain: ~30 minutes at lean's four-second slots, ~90 minutes at beacon's twelve-second ones.

Beyond that window, `node` prefers a checkpoint when one is offered, since catching up over P2P costs more than downloading a recent state. With no URL configured there is no anchor to switch to, so the node simply runs against the data directory it was given: that is the setup that was asked for. The warning is there because range sync may not be able to close a gap this large. Peers prune block signatures past `SIGNATURE_PRUNING_RANGE` (21600 slots, ~1 day), so beyond that horizon they cannot serve the history the node is missing and it needs a checkpoint URL to catch up at all. The warning logs the gap so this is visible in the boot log. `beacon` follows the same preference, though it imports nothing past its anchor today, so there is no backfill cost yet to weigh against a fresh download.

When a checkpoint URL *is* set and every URL fails, the node exits rather than falling back to the stale state on disk. This is intentional, on either chain: configuring the flag asks for a specific anchor, so an unreachable source is a misconfiguration worth surfacing at boot instead of quietly starting a node that is hours behind. Omitting the flag is how you ask for "resume whatever is on disk"; that path never exits.

To deliberately discard existing state and start over, remove the data directory first. `node` then starts over from genesis or from a checkpoint, whichever `--checkpoint-sync-url` says; `beacon` does the same, except that a built-in-network run still needs the URL, since the built-in networks alone have no genesis-sync path. Checkpoint sync itself writes its anchor state on top without clearing existing data.

### Foreign State

Persisted state is accepted only after its genesis identity is verified against the network the node is configured for: the pair `(genesis_time, genesis_validators_root)`. Lean has no `genesis_validators_root` field of its own, but its validator registry is fixed at genesis and never mutates afterward, so the root of the registry a lean state carries today is the root it had at genesis; that is the value the `Lean` variant's `genesis_validators_root()` accessor answers with. Both fields are compared by one function, `verify_state_genesis`, shared by the resume path on either chain and by both checkpoint-sync paths. The slot duration is compared separately, against the persisted `config` row rather than the state: a lean network sets it in its config file and no state carries it, so a data directory built at another cadence is caught there.

`Store::from_db_state` no longer runs this check itself: it loads whatever chain a data directory holds and hands back a `Store`, without judging whether that is the chain or the network the operator configured. The caller (`fetch_initial_state` for `node`, `fetch_initial_beacon_state` for `beacon`) checks `Store::chain()` against the sub-command it is running under, then runs `verify_state_genesis` against the loaded finalized state. Either check failing aborts startup: a chain mismatch as `CheckpointSyncError::WrongChain`, a genesis mismatch as `CheckpointSyncError::Genesis` (wrapping `GenesisMismatch::GenesisTime` or `GenesisMismatch::GenesisValidatorsRoot`). Both used to be raised from inside `from_db_state` itself, as `ethlambda_storage::Error::GenesisMismatch`/`::WrongChain`; those two variants have been removed from the storage crate now that the check runs one layer up, in the caller that actually knows which network and which chain it wants.

Either failure is not treated as an empty directory, because initializing a new anchor on top would leave the foreign chain's rows in place, and the slot-indexed reads behind `BlocksByRange` would then serve those rows to peers. Point `--data-dir` at the right directory, or remove it.

Note that a genesis-time-only comparison still would not catch a network that was regenerated with the same `genesis_time` but a different validator set, which is why the registry root is compared too; that reasoning is unchanged; only its mechanism is, since a list's root already commits to the count, each validator's index, and both pubkeys, where this used to be four separate comparisons.

## Verification Checks

All checks are performed before a downloaded checkpoint anchor is accepted. The genesis-identity checks (marked *(shared)*) are the ones the resume-from-disk path also runs, on either chain, through the same `verify_state_genesis` function described in [Foreign State](#foreign-state) above.

### Lean

| Check | What it catches |
| --- | --- |
| Slot > 0 | Checkpoint state cannot be genesis (slot 0) |
| Validators non-empty | State must contain validators |
| Genesis time matches *(shared)* | Wrong network or misconfigured peer |
| Genesis validators root matches *(shared)* | Wrong validator set: the root commits to the count, each validator's index, and both pubkeys, so this one comparison subsumes what used to be four |
| Finalized slot <= state slot | Finalized checkpoint cannot be in the future |
| Justified slot >= finalized slot | Justified must be at or after finalized |
| Same-slot checkpoints have matching roots | If justified and finalized are at the same slot, they must agree on the root |
| Block header slot <= state slot | Block header cannot be ahead of the state |
| Block header root matches finalized | If header is at finalized slot, its root must match the finalized root |
| Block header root matches justified | If header is at justified slot, its root must match the justified root |

### Beacon

| Check | What it catches |
| --- | --- |
| Slot > 0 | Checkpoint state cannot be genesis (slot 0) |
| Validators non-empty | State must contain validators |
| Genesis time matches *(shared)* | Wrong network or misconfigured peer |
| Genesis validators root matches *(shared)* | Wrong validator set |
| Finalized epoch <= current epoch | Finalized checkpoint cannot be in the future |
| Justified epoch >= finalized epoch | Justified must be at or after finalized |
| Block header slot <= state slot | Block header cannot be ahead of the state |
| Block's fork matches state's fork | The fetched block must decode as the same fork the state resolved to |
| Anchor's fork is followed (`refuse_unfollowable_fork`) | A fork the node cannot follow is refused with `UnsupportedFork` before any store is built. Every fork is followed today, gloas included, so this refuses nothing; a gloas anchor starts with no payload known, so its head is EMPTY and its first FULL child is held until the parent's envelope is fetched. Runs on both anchor sources, the checkpoint provider's state and a loaded network's own genesis state |
| Anchor pairing | See [Anchor Pairing](#anchor-pairing) below |

Beacon has no same-slot-checkpoints-matching-roots check: nothing here computes two separate checkpoint roots to compare, since a trusted checkpoint-synced anchor is finalized by fiat, and the beacon spec's own construction applies that single checkpoint to all four of the store's justified/finalized slots at once.

HTTP errors and SSZ decoding failures are caught before verification runs, on both chains.

## Anchor Pairing

### Beacon: paired on the header root, not the state root

The consensus specification's `get_forkchoice_store` asserts `anchor_block.state_root == hash_tree_root(anchor_state)`: the anchor state is meant to be the anchor block's own post-state. A checkpoint-synced anchor is not, in general: the Beacon API's `states/finalized` endpoint resolves to the state at `finalized_checkpoint.epoch.start_slot()`, and when that boundary slot was empty (no block was proposed there), the state has advanced past its own `latest_block_header` by one or more empty slots, so its own root no longer matches what the header committed to. This is routine on mainnet, not a transient race: an empty slot at an epoch boundary is a normal outcome, not a fault to work around.

Both `get_forkchoice_store` (`ethlambda_state_transition::beacon::fork_choice`, the specification's own construction rules) and the checkpoint-sync path's own pairing check instead verify that the state's `latest_block_header` hashes to the anchor block's own root, substituting the state's own root for the header's `state_root` field when that field still holds its zero placeholder. (That field is left zero only for the duration of the header's own slot; `process_slot` fills it in with the real value the moment the slot moves past it, so once the slot has advanced the header already carries the real value and is trusted as-is.) The header root pins the pair just as precisely as the specification's check does, since it names exactly one block, and unlike the state's own root it is unaffected by the state having advanced past that block.

This is a **documented deviation from the consensus specification**, not an oversight: lighthouse's checkpoint-sync client (`beacon_node/beacon_chain/src/builder.rs`, `weak_subjectivity_state`) makes the same one, for the same reason.

Lean's own anchor pairing (`anchor_pair_is_consistent`) needs no such deviation: lean's finalized-state endpoint always names the state at the same slot as the anchor block itself, so there is no epoch-boundary snapping and no empty-slot gap between them to account for.

## Security Considerations

### Trust model

Checkpoint sync operates under a [**weak subjectivity**](https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity) assumption. In proof of work, any node can objectively determine the canonical chain by verifying the most cumulative work. Proof of stake doesn't have this property: validators can costlessly sign multiple forks, so a node that wasn't online to observe the chain in real time cannot distinguish the real chain from a fabricated one using protocol rules alone.

Weak subjectivity resolves this: a new node obtains a recent trusted state through a social channel (a peer, a checkpoint provider, a block explorer) and starts from there. Nodes that are always online are unaffected because they continuously track the chain and don't need external trust.

What you **are** trusting:

- The checkpoint source is honest about which state is finalized
- The state hasn't been crafted to put you on a fork that diverged within the weak subjectivity period

What verification **does** protect against:

- Wrong network (genesis time or genesis validators root mismatch)
- Structurally invalid states (impossible slot or epoch orderings, inconsistent checkpoints, a block that does not pair with its state)
- Corrupted data (SSZ decode failures)

What verification **does not** protect against:

- A checkpoint source that serves a structurally valid state on a minority fork. It will pass all checks but put you on the wrong chain. This is why the choice of checkpoint source matters.
