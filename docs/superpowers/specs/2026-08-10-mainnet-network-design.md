# `ethlambda beacon`: following the Ethereum Beacon Chain

Design for an `ethlambda beacon` subcommand that turns ethlambda into a
follower of the Ethereum Beacon Chain, reusing the spec-verified
`ethlambda-beacon` crate for consensus and the existing DB-backed `Store` for
persistence. `ethlambda lean` keeps today's behavior and stays the default.

Branch: `feat/mainnet-network`, off `feat/discv5-discovery`, with
`feat/beacon-chain-stf` merged in.

## 1. Scope

This document covers sub-projects **A1** (mainnet wire and typed decode) and
**A2** (anchor, fork choice, persistence) of the decomposition in §12.

**In scope**

- `lean` and `beacon` subcommands, with `lean` as the default so existing
  invocations keep working. Lean behavior is unchanged.
- Beacon-chain gossip topics, req/resp protocol ids, ENR entries, discv5
  admission, and a built-in mainnet bootnode list.
- Fork digest computed from the fork schedule and the anchor state.
- Fork-aware SSZ decoding of every subscribed gossip topic into
  `ethlambda-beacon` containers.
- Checkpoint sync of a finalized `BeaconState` and block from a Beacon API.
- Forward sync from the anchor to the head over `beacon_blocks_by_range/2`.
- Driving `on_tick` / `on_block` / `on_attestation` / `on_attester_slashing`
  against the DB-backed `Store`.
- Beacon state persistence: finalized anchors plus forward replay.
- Head and finalized checkpoint exposed through metrics and the RPC layer.

**Out of scope**, with the sub-project that owns each in §12: publishing any
message, serving req/resp beyond the handshake, backfill sync, PeerDAS custody,
execution-layer validation, and validator duties.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Consensus implementation | Reuse `ethlambda-beacon` unchanged | phase0 through fulu, 5705 mainnet fixture cases green, 150 of them `fork_choice` |
| Type location | Move `ethlambda-beacon`'s containers into `ethlambda-types` | Lets `BeaconState` gain a `Lean` variant without `ethlambda-beacon` depending on lean crates |
| CLI shape | `lean` and `beacon` subcommands, `lean` default | Each subcommand declares its own required flags, instead of `Option<T>` plus hand-rolled validation |
| Chain dispatch | One `BlockChainServer`, single `match` on the state variant at the top of each handler | No traits, no generics through the actor system |
| State storage | The existing DB-backed `Store`, extended | Beacon's in-memory `HashMap` store cannot hold mainnet states |
| Fork digest | Computed from `Config::mainnet()`'s schedule and the anchor state's `genesis_validators_root` | No hardcoded constants, and correct across BPO forks |
| Transport | QUIC only | Reuses the existing transport; the cost is a smaller peer pool |
| Gossip breadth | The 7 global topics, no subnet families | Subscribe only to what is consumed; each subnet family arrives with the sub-project that reads it |
| Bootnodes | Built-in list, discovery forced on | `ethlambda beacon` must work without extra flags |
| Publishing | Suppressed | Nothing this node can produce today would be signature-valid |

## 3. Type layout

`ethlambda-beacon`'s containers, `primitives`, `fork`, `preset`, `config`, and
`constants` move to `ethlambda-types`. `ethlambda-beacon` keeps `helpers`,
`stf`, `genesis`, `upgrade`, `fork_choice`, `bls`, and `kzg`, and depends on
`ethlambda-types`.

`BeaconState` gains a `Lean(LeanState)` variant, and `ForkName` gains `Lean`.

**`ForkName::Lean` sorts last**, after `Gloas` and `Heze`, not immediately after
`Fulu`. Three reasons:

1. `fork >= ForkName::X` gating throughout the STF reads as true for lean, which
   is the intent of "lean is the next fork".
2. `gloas` genuinely occupies the position after fulu. The crate already names it
   in `UNMODELED_FORKS`, and `fixture_forks/every_directory_is_accounted_for`
   fails if a fixture fork directory is neither parseable nor listed. Sorting
   `Lean` last leaves gloas's real slot free.
3. `ForkName::ALL` drives the fixture harness's test-list construction. `Lean`
   must be excluded from that walk: the beacon fixture release ships no `lean`
   tree, and a suite matching no case is designed to fail loudly.

`ForkName::Fulu.next()` stops returning `None`, so
`neighbours_terminate_at_the_ends` needs updating to assert against the new last
variant.

### `unreachable!()` in beacon accessors

Beacon accessors get `BeaconState::Lean => unreachable!(...)` arms. That is sound
only if no lean state ever reaches them, and `BeaconState::Lean` is constructible
anywhere, so the guarantee is structural rather than type-level. The boundary is
therefore **exactly one `match` per `BlockChainServer` handler**, at the top,
with no beacon accessor called above it. Each `unreachable!` carries a message
naming the handler that should have dispatched, so a violation is diagnosable
from the panic alone.

## 4. Chain dispatch

```
                         BlockChainServer  (one actor)
                                 |
   handler entry ────────► match state.fork_name()
                                 |
              ┌──────────────────┴──────────────────┐
        ForkName::Lean                     every beacon fork
              │                                     │
   existing lean body                    beacon body: calls
   (3SF, XMSS, intervals)                ethlambda_beacon::fork_choice::*
```

Nothing is shared below the match. The head-selection descent is *not* extracted
into a common helper, by decision: lean's weight is one vote per validator over
an unfiltered tree, beacon's is summed effective balances with proposer boost and
equivocation exclusion over an FFG-filtered tree, and only the descent loop
itself coincides.

`ethlambda-network-api` gains beacon message variants so `P2PServer` can hand
decoded beacon objects to the same actor ref.

## 5. `Store` with beacon support

The existing `Store` already provides what the beacon handlers need:

| Beacon `fork_choice::Store` field | Existing `Store` |
|---|---|
| anchor construction | `from_anchor_state`, `from_db_state`, `get_forkchoice_store` |
| `blocks` | `BlockHeaders` + `BlockBodies` via `get_signed_block` / `insert_signed_block` |
| `block_states` | `States` + `StateDiffs` + LRU via `get_state` / `insert_state` / `has_state` |
| `time`, `genesis_time` | `time()`, `set_time()`, `config()` |
| `justified_checkpoint`, `finalized_checkpoint` | `latest_justified()`, `latest_finalized()`, `update_checkpoints()` |
| pruning at finalization | `prune_old_data`, `prune_live_chain` |

**Fields to add.** Persisted: `unrealized_justified_checkpoint`,
`unrealized_finalized_checkpoint`, `unrealized_justifications`,
`checkpoint_states`. In-memory only, being per-slot or per-epoch scratch:
`proposer_boost_root`, `block_timeliness`, `equivocating_indices`,
`latest_messages`, `pow_blocks`.

The beacon handlers change signature from `&mut fork_choice::Store` to
`&mut ethlambda_storage::Store`. `fork_choice::Store` is deleted; the fixture
runners construct an `ethlambda-storage` `Store` on the in-memory backend
instead, so all 150 `fork_choice` cases keep gating the handlers.

This adds a dependency edge `ethlambda-beacon` to `ethlambda-storage`, which
already depends on `ethlambda-types`. No cycle, but it ends the property that
`ethlambda-beacon` depends on no other workspace crate, so `docs/beacon_stf.md`
needs updating to say what replaced it.

### Beacon states do not use the diff path

Lean's `StateDiff` stores `justified_slots`, `justifications_roots`, and
`justifications_validators` in full, regenerates `historical_block_hashes` from
`base_root` plus the slot gap, and omits `validators` on the documented
assumption that they never mutate. A beacon registry mutates every epoch, so
routing a beacon state through that path corrupts every reconstruction silently.

Beacon states therefore use **anchors plus forward replay**, with no diffs:

- `States` holds the latest finalized anchor and the one before it. Older anchors
  are pruned.
- Any state above finalization is reconstructed by replaying blocks forward from
  the latest anchor.
- The LRU is sized per network: 32 entries on lean (unchanged), 3 on beacon.

```
mainnet BeaconState  ~350 MB  (registry 254 MB, balances 17 MB,
                               inactivity 17 MB, participation 2x2.1 MB,
                               ring buffers)

disk        ~700 MB steady state, two anchors
memory      anchor + head + 1 spare  ~=  1 GB
cold miss   replay <= ~64 slots, two epochs of finalization lag
```

Both existing storage constants are lean-tuned and must become per-network:
`STATE_CACHE_CAPACITY` (32 would be ~11 GB of mainnet states) and
`SNAPSHOT_ANCHOR_INTERVAL` (1024 would mean 1024 state transitions per cold
reconstruction). Per-epoch beacon diffs, storing changed validator indices plus
full `balances` and participation at roughly 40 MB per epoch, would cut replay
cost later; they are not needed here.

### Storage format break

`States` values gain a one-byte fork selector ahead of the variant's SSZ, and
`get_state` returns `Result<Option<BeaconState>>` rather than the lean `State`,
which touches every caller in `blockchain` and `rpc`.

Existing databases become unreadable. A `db_version` key joins the existing
`Metadata["config"]` genesis fingerprint; a version mismatch aborts startup with
a message telling the operator to wipe the data directory. There is no migration:
lean devnets resync in minutes.

## 6. Startup order and the fork digest

Checkpoint sync runs **before** the swarm is built, so every network parameter is
derived from the anchor rather than hardcoded:

```
fetch anchor state + block (Beacon API)
  └─► genesis_validators_root, genesis_time   (both read off the anchor state)
      └─► epoch = (now - genesis_time) / (seconds_per_slot * SLOTS_PER_EPOCH)
          └─► fork_version = Config::mainnet() schedule at epoch
              └─► base = compute_fork_data_root(fork_version, gvr)
                  └─► epoch <  fulu_fork_epoch:  base[..4]
                      epoch >= fulu_fork_epoch:  xor(base, sha256(
                            le_u64(bp.epoch) ++ le_u64(bp.max_blobs_per_block)
                          ))[..4]
                      where bp = latest BLOB_SCHEDULE entry with entry.epoch <= epoch,
                                 else (electra_fork_epoch, max_blobs_per_block_electra)
                      └─► gossip topics, ENR `eth2` entry, discv5 admission
```

This is fulu's `compute_fork_digest` verbatim (EIP-7892). `ethlambda beacon`
therefore requires `--checkpoint-sync-url`, which matches every production
client and removes both constants that would otherwise need maintaining.

`Config::mainnet()` in the beacon crate matches upstream `configs/mainnet.yaml`
as of spec commit `fe2aab7` (2026-08-09), including `FULU_FORK_EPOCH` 411392 and
the two BPO entries at epochs 412672 and 419072. Gloas and heze are far-future.

The digest is computed once at startup. A fork or BPO boundary crossed while
running strands the node on stale topics, so startup logs the next boundary's
epoch and wall-clock time, and a warning fires when the clock passes it.
Re-subscribing across a boundary is sub-project E.

## 7. Wire

| Piece | Value |
|---|---|
| Transport | QUIC only. Only peers whose ENR advertises `quic` are dialable |
| Message id | Unchanged. The existing `compute_message_id` is already the altair form, `SHA256(domain ++ le_u64(len(topic)) ++ topic ++ data)[..20]` |
| `seen_ttl` | 385s (`SLOTS_PER_EPOCH * SECONDS_PER_SLOT * 2`) on mainnet, versus lean's 24s |
| Mesh params | `mesh_n` 8, low 6, high 12, heartbeat 700ms, history 6/3 already match the beacon spec and are unchanged |
| ENR | `eth2` = computed mainnet `ENRForkID`, `attnets` fixed 64-wide, `cgc` = `CUSTODY_REQUIREMENT` (4), `quic`, no `tcp` |
| Admission | Compares against the mainnet fork id rather than `EnrForkId::local()`, and clamps `attnets` to 64 |
| Bootnodes | Built-in `eth-clients/mainnet` ENRs; `--bootnodes` overrides |

**Gossip topics**, fulu-era, 7 subscriptions:

| Topic | Count |
|---|---|
| `beacon_block` | 1 |
| `beacon_aggregate_and_proof` | 1 |
| `voluntary_exit`, `proposer_slashing`, `attester_slashing` | 3 |
| `bls_to_execution_change` | 1 |
| `sync_committee_contribution_and_proof` | 1 |

Every subnet family is deliberately excluded. The rule is that this node
subscribes only to what it consumes, and adds a family when the sub-project that
consumes it lands:

| Excluded | Carries | Consumer, and when |
|---|---|---|
| `beacon_attestation_{0..63}` | unaggregated attestations | Validator duties, sub-project C. Fork choice reads the same `AttestationData` off `beacon_aggregate_and_proof`, with more attesters behind it |
| `sync_committee_{0..3}` | unaggregated sync committee messages | Validator duties, sub-project C |
| `data_column_sidecar_{0..127}` | PeerDAS column sidecars | Data availability, sub-project D. Nothing checks availability today |
| `blob_sidecar_{subnet_id}` | deneb and electra blobs | Nothing. Deprecated in fulu |

That leaves 7 topics rather than 203, drops roughly 30k BLS verifications per
epoch, and removes the column bandwidth entirely.

Two ENR entries now advertise less than the spec's shape suggests, both
deliberately:

- `attnets` is 64 bits all unset, which is exactly what a node subscribing to no
  attestation subnet serves. It costs only that subnet-gap-filling peers rank us
  lower.
- `cgc` still advertises `CUSTODY_REQUIREMENT`, because peers may reject a lower
  value outright and that would defeat the mode, while this node custodies and
  serves nothing until sub-project D. This is the widest gap between what we
  advertise and what we serve, so it is logged at startup alongside the
  `DataAvailability` and `ExecutionEngine` stubs.

The absence of `tcp` means beacon clients cannot discover us: lighthouse's
discovery predicate requires `enr.tcp4().is_some() || enr.tcp6().is_some()` and
applies it as a discv5 query filter. We discover them, which is what a follower
needs. `docs/discovery.md` already records this.

**Req/resp protocol ids**, registered by direction, following the same
subscribe-only-what-you-consume rule as the topics:

| Protocol | Direction | Why |
|---|---|---|
| `status/1`, `status/2` | both | Handshake on connect, in both directions |
| `ping/1`, `metadata/1,2,3` | both | Liveness and peer metadata |
| `goodbye/1` | inbound | Log the reason code; we never send one |
| `beacon_blocks_by_range/2` | outbound | Fill the anchor-to-head gap, §9 |
| `beacon_blocks_by_root/2` | outbound | Fetch a gossiped block's missing parent |

`blob_sidecars_by_{range,root}/1` and `data_column_sidecars_by_{range,root}/1`
are **not** registered: nothing consumes sidecars until sub-project D, and an
unregistered protocol is refused at stream negotiation rather than answered with
a lie. Inbound block serving arrives with sub-project E. Gloas and heze protocols
are excluded, being far-future on mainnet.

**Inbound responder.** The node answers only what keeps a connection alive:

| Protocol | Response |
|---|---|
| `status/1,2` | A real `Status` built from `Store`: our digest, finalized and head checkpoints |
| `ping/1` | Our metadata sequence number |
| `metadata/1,2,3` | A synthesized `MetaData` of the requested version |
| `goodbye/1` | None; log the reason code and let the peer close |

Nothing else is answered, because nothing else is registered. Peers asking for
blocks or sidecars get a stream-negotiation refusal, and that costs peer score:
the accepted price of following before serving. Sub-project E turns the two block
protocols bidirectional and adds the sidecar ones.

## 8. Decode

The SSZ type of a payload depends on the fork, which depends on the slot, which
is inside the payload. Decoding reads the slot from its fixed offset, maps slot
to epoch to `ForkName` via `Config::mainnet()`, then decodes the matching
variant. A decode failure is counted, logged at debug, and dropped.

## 9. Driving the handlers

```
slot clock (12s)    ──► on_tick(store, unix_seconds, config)
beacon_block        ──► decode ──► on_block(store, block, config, DataAvailability)
                              └──► on_attestation(.., is_from_block=true) per
                                   attestation carried in the block body
aggregate_and_proof ──► decode ──► on_attestation(store, att, is_from_block=false, config)
attester_slashing   ──► decode ──► on_attester_slashing(store, slashing)
                                      └─► get_head(store, config) ──► metrics, RPC
```

Two deliberate simplifications, both mirroring stubs the beacon crate already
carries:

| Simplification | Consequence | Resolved by |
|---|---|---|
| `ExecutionEngine::valid()` | Optimistic import, no execution validation | Sub-project B |
| `DataAvailability::NotRequired`, unconditionally: no column subnet is subscribed, so no evidence exists to pass | Post-fulu DA is not enforced | Sub-project D |

Both are logged once at startup so a running node never implies more validation
than it performs.

### Anchor to head

Checkpoint sync anchors at a **finalized** state, roughly two epochs behind the
head, and `on_block` rejects a block whose parent is not in the store. The first
gossiped block therefore lands on an unknown parent chain, so the gap has to be
fetched before gossip can be applied at all:

```
anchor (finalized)                                    head (wall clock)
   |<----------------- ~64 slots to fetch ----------------->|
   |                                                        |
   └─ beacon_blocks_by_range/2 from the highest-head peer ───┘
      then apply buffered gossip blocks in slot order
```

Blocks arriving on gossip while the gap is being filled are buffered by parent
root and applied once their parent imports; a gossiped block whose parent is
still missing after the range fetch completes is fetched individually with
`beacon_blocks_by_root/2`. This is the same shape as the existing lean
`RangeSyncState` and `pending_root_requests` in `crates/net/p2p/src/lib.rs`, and
that machinery is reused rather than rewritten.

This is forward sync only, from the anchor to the head. Backfill below the
anchor, which a node needs to serve historical requests, is sub-project E.

## 10. CLI: two subcommands, `lean` by default

```
ethlambda [lean]   <common> <lean-only>      today's client, unchanged
ethlambda  beacon  <common> <beacon-only>    the mainnet follower
```

Each subcommand declares its own required flags, so nothing is `Option<T>` for
the sole purpose of being validated by hand afterwards.

| Group | Flags |
|---|---|
| Common | `--node-key`, `--node-id`, `--data-dir`, `--gossipsub-port`, `--bootnodes`, `--http-address`, `--api-port`, `--metrics-port`, `--discovery.*` |
| `lean` only | `--genesis`, `--validators`, `--validator-config`, `--hash-sig-keys-dir` (all required), `--is-aggregator`, `--aggregate-subnet-ids`, `--attestation-committee-count`, `--enable-proposer-aggregation`, `--max-attestations-per-block`, `--disable-duty-sync-gate`, `--checkpoint-sync-url` |
| `beacon` only | `--checkpoint-sync-url` (required) |

`--checkpoint-sync-url` is declared per subcommand rather than shared, because
its meaning differs: on lean it is an optional fallback used only when there is
no resumable state on disk, and on beacon it is the mandatory source of the
anchor state, the `genesis_validators_root`, and therefore the fork digest.

Defaults that differ per subcommand fall out of the split instead of needing
resolution logic:

| Flag | `lean` | `beacon` |
|---|---|---|
| `--discovery.enable` | `false` | `true`, not overridable |
| `--discovery.port` | `9000` | `--gossipsub-port + 1` |

`--discovery.enable` is forced on for `beacon` because mainnet peering is
impossible without a crawl: published mainnet bootnode ENRs carry no `quic`
entry, so none of them is statically dialable. The differing `--discovery.port`
default keeps the discv5 socket from colliding with the QUIC port, which the
existing `validate_discovery` check would otherwise reject out of the box.

### Making `lean` the default subcommand

`Dockerfile`'s `ENTRYPOINT ["/usr/local/bin/ethlambda"]` takes flags appended by
the caller, and every devnet script, `lean-quickstart` profile, Hive client
wrapper, and `shadow/build.sh` invocation passes bare flags with no subcommand.
All of them must keep working untouched.

clap has no native default subcommand, so `main` preprocesses argv: if the first
argument is neither a known subcommand nor a help or version flag, `lean` is
inserted ahead of it. This is one small function with its own tests, and it keeps
`--help` output free of the duplicated argument groups that clap's
`args_conflicts_with_subcommands` pattern would produce.

```
ethlambda --genesis c.yaml ...   ->  ethlambda lean --genesis c.yaml ...
ethlambda lean --genesis c.yaml  ->  unchanged
ethlambda beacon --checkpoint-sync-url ...  ->  unchanged
ethlambda --help / --version / -h / -V      ->  unchanged, no injection
```

`HIVE_LEAN_TEST_DRIVER` is unaffected: it is an environment variable checked
after parsing and before any file is read, and the Hive shim passes bare flags
that now resolve to `lean`.

## 11. Testing

| Level | Test |
|---|---|
| Fork digest | Against three digests recorded from live crawls in `docs/discovery.md`: `8c9f62fe` (fulu with BPO 419072), `ad532ceb` (electra), `b5303f2a` (phase0). Covers both branches of `compute_fork_digest` |
| Topics and protocols | Construction of all 7 topic names and every protocol id, and that no `beacon_attestation_*`, `sync_committee_{id}`, `blob_sidecar_*` or `data_column_sidecar_*` topic is among them |
| Decode | Fork-aware decode driven by the `ssz_static` fixtures already in the tree |
| `Store` | All 150 mainnet `fork_choice` fixture cases pass against the DB-backed `Store` on the in-memory backend, and all 5705 mainnet plus 40009 minimal cases stay green after the type move |
| Anchor and replay | Reconstruct a state above finalization by replay and compare against the directly computed post-state |
| Anchor to head | Gossip blocks buffered while a range fetch is in flight are applied in slot order once their parent imports, and a block still orphaned afterwards triggers a by-root fetch |
| CLI | Argv injection: bare flags resolve to `lean`, explicit subcommands pass through, help and version are never rewritten. Each subcommand rejects the other's required flags |
| Lean regression | The full existing lean suite, unchanged, plus a devnet run driven by the current scripts with no subcommand added, proving the Docker entrypoint contract still holds |
| Live | Against mainnet: peers connect, a `beacon_block` decodes within ~30s, and head tracks within one slot of wall clock |

## 12. Sub-projects

```
A1 + A2 (this spec) ──┬──► B  execution layer, Engine API
                      ├──► C  validator duties, publishing, slashing protection
                      ├──► D  PeerDAS custody and data availability
                      └──► E  serving req/resp, backfill sync, fork-boundary resubscribe
```

`crates/net/ethrex-client` on `engine-api-integration` is a head start on B.
Publishing real blocks and attestations, which is what prompted this work, lands
in C and depends on B.

## 13. Risks

| Risk | Mitigation |
|---|---|
| Beacon state memory and disk (§5) | Anchors plus replay, per-network LRU. Measure resident size against a live node before building the rest of A2 |
| `unreachable!()` reached through an unforeseen path | Single dispatch point per handler, panic message naming the expected dispatcher |
| Type move churns the whole workspace | Mechanical move, no logic change; the beacon fixture suites gate it before anything else lands |
| QUIC-only leaves too few mainnet peers | Measured during A1. TCP plus noise plus yamux is the known fallback, and libp2p is already pulled in with `features = ["full"]` |
| Merging `feat/beacon-chain-stf` conflicts in the root `Cargo.toml` | Both branches carry local path overrides marked DO NOT COMMIT; resolve to the union and keep both notes |
| Deleting `fork_choice::Store` regresses a fixture-green crate | The fixture runners move to the new store in the same commit, so the suites gate the change itself |
