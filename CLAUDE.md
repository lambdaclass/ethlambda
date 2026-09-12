# ethlambda Development Guide

Development reference for ethlambda - minimalist Lean Ethereum consensus client.
Not to be confused with Ethereum consensus clients AKA Beacon Chain clients AKA Eth2 clients.

## Quick Reference

**Main branch:** `main`
**Rust version:** 1.97.1 (edition 2024)
**Test fixtures release:** Download latest production fixtures from leanSpec releases

## Codebase Structure (12 workspace crates)

```
bin/ethlambda/              # Entry point, CLI, orchestration
  ├─ src/main.rs            # run_node: one entry point for both chains (see below)
  ├─ src/cli.rs             # Options { common, network: Lean | Mainnet }
  ├─ src/command.rs         # Sub-command dispatch + default-subcommand injection
  ├─ src/beacon.rs          # Mainnet wire params: built-in genesis, fork digest
  ├─ src/checkpoint_sync.rs # Checkpoint sync for both chains (lean's `/lean/v0/...`, beacon's Beacon API)
  ├─ assets/mainnet/genesis.ssz  # Mainnet genesis BeaconState (eth-clients/mainnet's file)
  └─ src/version.rs         # Build-time version info (vergen-git2)
crates/
  blockchain/               # State machine actor (GenServer pattern)
    ├─ src/lib.rs           # BlockChain actor, tick events, validator duties
    ├─ src/store.rs         # Fork choice store, block/attestation processing
    ├─ src/block_builder.rs # Block assembly (pre-built at previous slot's interval 4)
    ├─ src/aggregation.rs   # Interval-2 signature aggregation worker
    ├─ src/reaggregate.rs   # Re-aggregation of block-borne votes on import
    ├─ src/sync_status.rs   # Sync-gate tracker (suppresses duties while syncing)
    ├─ src/key_manager.rs   # Validator key management and signing
    ├─ src/metrics.rs       # Blockchain-level Prometheus metrics
    ├─ fork_choice/         # [crate] LMD GHOST implementation (3SF-mini)
    └─ state_transition/    # [crate] STF: process_slots, process_block, attestations
        ├─ src/justified_slots_ops.rs  # Relative-index helpers for justified_slots
        └─ src/metrics.rs   # State transition timing + counters
  common/
    ├─ types/               # Core types (State, Block, Attestation, Checkpoint)
    ├─ crypto/              # XMSS aggregation (leansig wrapper)
    ├─ metrics/             # Prometheus re-exports, TimingGuard, gather utilities
    └─ test-fixtures/       # Spec-fixture loading (prod dep of rpc's Hive test driver)
  net/
    ├─ api/                 # Actor protocol traits wiring BlockChain ↔ P2P
    ├─ p2p/                 # libp2p: gossipsub + req-resp (Status, BlocksByRoot, BlocksByRange)
    │   ├─ src/gossipsub/   # Topic encoding, message handling
    │   ├─ src/req_resp/    # Request/response codec and handlers
    │   └─ src/metrics.rs   # Peer connection/disconnection tracking
    └─ rpc/                 # Axum HTTP: API server + metrics server (independent ports)
  storage/                  # RocksDB backend, in-memory for tests
    └─ src/api/             # StorageBackend trait + Table enum
```

## Key Architecture Patterns

### Actor Concurrency (spawned-concurrency)
- **BlockChain**: Main state machine (GenServer pattern)
- **P2P**: Network event loop with libp2p swarm
- Communication via `mpsc::unbounded_channel`
- Shared storage via `Arc<dyn StorageBackend>` (clone Store, share backend)

### Tick-Based Validator Duties (5 intervals per slot; 4-second slots by default)
```
Interval 0: Block published (at the slot boundary). The build+publish code path is merged into the previous slot's interval 4 (see below) and aligned to publish here; no attestation acceptance happens at interval 0.
Interval 1: Attestation production (all validators, including proposer)
Interval 2: Aggregation (aggregators create proofs from gossip signatures)
Interval 3: Safe target update (fork choice)
Interval 4: Accept accumulated attestations; build the NEXT slot's block and publish it aligned to that slot's interval 0 (build and publish merged into this tick)
```

### Attestation Pipeline
```
Gossip → Signature verification → new_payloads (pending)
  ↓ (intervals 0/4)
promote → known_payloads (fork choice active)
  ↓
Fork choice head update
```
(Store buffer fields are `new_payloads`/`known_payloads`; the accessors are named
`extract_latest_new_attestations`/`extract_latest_known_attestations`.)

### State Transition Phases
1. **process_slots()**: Advance through empty slots, update historical roots
2. **process_block()**: Validate header → process attestations → update justifications/finality
3. **Justification**: 3SF-mini rules (delta ≤ 5 OR n² OR n(n+1))
4. **Finalization**: Source with no unjustifiable gaps to target

## Development Workflow

### Before Committing
```bash
make fmt                                     # Format code (cargo fmt --all)
make lint                                    # Clippy with -D warnings
make test                                    # All tests + forkchoice spec tests
```

`make test` is `test-consensus` plus `test-node`, two halves CI runs as separate
jobs because together they no longer fit a runner's disk. `CONSENSUS_CRATES` in
the Makefile names the first; `test-node` is the workspace minus it. Run one half
directly when iterating on it.

### Common Operations
```bash
rm -rf leanSpec && make leanSpec/fixtures                # Download latest released test fixtures
make update UPDATE_ARGS="-p <crate>"                     # Bump deps under the 14-day publish-age cooldown (nightly resolver)
make cooldown-check                                      # Fail if a lockfile pins crates younger than the cooldown (same as CI)
make docker-build                                        # Build Docker image (DOCKER_TAG=local)
make run-devnet                                          # Run local devnet with lean-quickstart
```

### Testing with Local Devnet

See `.claude/skills/devnet-runner/SKILL.md` for running a local multi-client devnet
(node roster, image tags, pause/unpause instability testing) and
`.claude/skills/devnet-log-review/SKILL.md` for analyzing the dumped logs.

## Important Patterns & Idioms

### Trait Implementations
```rust
// Prefer From/Into traits over custom from_x/to_x methods
impl From<u8> for ResponseCode { fn from(code: u8) -> Self { Self(code) } }
impl From<ResponseCode> for u8 { fn from(code: ResponseCode) -> Self { code.0 } }

// Enables idiomatic .into() usage
let code: ResponseCode = byte.into();
let byte: u8 = code.into();
```

### Ownership for Large Structures
```rust
// Prefer taking ownership to avoid cloning large data (signatures ~2.5KB)
pub fn insert_signed_block(&mut self, root: H256, signed_block: SignedBlock) { ... }

// Add .clone() at call site if needed - makes cost explicit
store.insert_signed_block(block_root, signed_block.clone());
```

### Formatting Patterns
```rust
// Extract long arguments into variables so formatter can join lines
// Instead of:
batch.put_batch(Table::X, vec![(key, value)]).expect("msg");

// Prefer:
let entries = vec![(key, value)];
batch.put_batch(Table::X, entries).expect("msg");
```

### Error Handling Patterns

**Use `inspect` and `inspect_err` for side-effect-only error handling:**
```rust
// ✅ GOOD: Use inspect_err when only logging or performing side effects on error
result
    .inspect_err(|err| warn!(%err, "Operation failed"));

// Extract complex expressions to variables for cleaner formatting
let response = Response::success(ResponsePayload::BlocksByRoot(blocks));
server.swarm.behaviour_mut().req_resp.send_response(channel, response)
    .inspect_err(|err| warn!(%peer, ?err, "Failed to send response"));

// ✅ GOOD: Use inspect + inspect_err when both branches need side effects
operation()
    .inspect(|_| metrics::inc_success())
    .inspect_err(|_| metrics::inc_failed());

// ❌ AVOID: Using if let Err when only performing side effects
if let Err(err) = result {
    warn!(%err, "Operation failed");
}

// ❌ AVOID: Using if/else for both success and error side effects
if let Err(err) = operation() {
    metrics::inc_failed();
} else {
    metrics::inc_success();
}
```

**When NOT to use `inspect_err`:**
```rust
// Use if let Err or match when:
// 1. Early return needed
if let Err(err) = operation() {
    error!(%err, "Fatal error");
    return false;
}

// 2. Error needs transformation (use map_err + ?)
let result = operation()
    .map_err(|err| CustomError::from(err))?;
```

### Metrics Patterns

**Registration with `LazyLock`:**
```rust
// Module-scoped statics (preferred for state_transition metrics)
static LEAN_STATE_TRANSITION_TIME_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!("lean_metric_name", "Description", vec![...]).unwrap()
});

// Function-scoped statics (used in blockchain metrics)
pub fn update_head_slot(slot: u64) {
    static LEAN_HEAD_SLOT: LazyLock<IntGauge> = LazyLock::new(|| {
        register_int_gauge!("lean_head_slot", "Latest slot").unwrap()
    });
    LEAN_HEAD_SLOT.set(slot.try_into().unwrap());
}
```

**RAII timing guard (auto-observes duration on drop):**
```rust
let _timing = metrics::time_state_transition();
```

**All metrics use `ethlambda_metrics::*` re-exports** — the `ethlambda-metrics` crate re-exports
prometheus types (`IntGauge`, `IntCounter`, `Histogram`, etc.) and provides `TimingGuard` + `gather_default_metrics()`.

**Naming convention:** All metrics use `lean_` prefix (e.g., `lean_head_slot`, `lean_state_transition_time_seconds`).

### Logging Patterns

**Use tracing shorthand syntax for cleaner logs:**
```rust
// ✅ GOOD: Shorthand for simple variables
let slot = block.slot;
let proposer = block.proposer_index;
info!(
    %slot,              // Shorthand for slot = %slot (Display)
    proposer,           // Shorthand for proposer = proposer
    block_root = %ShortRoot(&block_root.0),  // Named expression
    "Block imported"
);

// ❌ BAD: Verbose
info!(
    slot = %slot,
    proposer = proposer,
    ...
);
```

**Standardized field ordering (temporal → identity → identifiers → context → metadata):**
```rust
// Block logs
info!(%slot, proposer, block_root = ..., parent_root = ..., attestation_count, "...");

// Attestation logs
info!(%slot, validator, target_slot, target_root = ..., source_slot, source_root = ..., "...");

// Consensus events
info!(finalized_slot, finalized_root = ..., previous_finalized, justified_slot, "...");

// Peer events
info!(%peer_id, %direction, peer_count, our_finalized_slot, our_head_slot, "...");
```

**Root hash truncation:**
```rust
use ethlambda_types::ShortRoot;

// Always use ShortRoot for consistent 8-char display (4 bytes)
info!(block_root = %ShortRoot(&root.0), "...");
```

### Relative Indexing (justified_slots)
```rust
// Bounded storage: index relative to finalized_slot
actual_slot = finalized_slot + 1 + relative_index
// Helper ops in justified_slots_ops.rs
```

## Cryptography & Signatures

**XMSS (eXtended Merkle Signature Scheme):**
- Post-quantum signature scheme
- 52-byte public keys, 2536-byte signatures (`SIGNATURE_SIZE` in `common/types/src/signature.rs`)
- Epoch-based to prevent reuse
- Aggregation via leanVM (previously leanMultisig) for efficiency

**Signature Aggregation (Two-Phase):**
1. **Gossip signatures**: Fresh XMSS from network → aggregate via leanVM
2. **Fallback to proofs**: Reuse previous block proofs for missing validators

## Networking (libp2p)

### Protocols
- **Transport**: QUIC over UDP (TLS 1.3), plus TCP (noise + yamux) on the same port number as a fallback: a peer whose advertised `quic` doesn't answer can still be reached over TCP, and libp2p races both addresses within one dial (list order confers no preference; the default `dial_concurrency_factor` starts both handshakes)
  - Binding TCP puts `--gossipsub-port` in the HTTP servers' namespace, so it must now differ from `--api-port`/`--metrics-port` too. `CommonOptions::validate_ports` rejects every clash before anything binds
- **Gossipsub**: Blocks + Attestations (snappy raw compression)
  - Topic: `/leanconsensus/{fork_digest}/{block|aggregation|attestation_N}/ssz_snappy`
  - `fork_digest` is a 4-byte hex string (no `0x` prefix); currently the dummy `12345678` agreed across clients
  - Mesh size: 8 (6-12 bounds), heartbeat: 700ms
- **Req/Resp**: Status, BlocksByRoot, BlocksByRange (snappy frame compression + varint length)
  - Beacon adds `beacon_blocks_by_{range,root}/2` alongside its Status/Ping/MetaData/Goodbye set.
    Both serve from the checkpoint-anchored store, and `build_status` advertises it
    (head, finalized checkpoint, and the anchor's slot as `earliest_available_slot`), so peers
    have a reason to ask. Asking runs too: a peer's Status starts a range session paced by
    `P2PServer::beacon_fetched_through`, the highest slot handed to the chain actor, rather
    than the store's head, which trails a delivered batch by the whole actor mailbox.
    Fetched blocks reach the actor as `BlockSource::Sync`.
    Their chunks carry four `<context-bytes>` (the block's own epoch's fork digest), which is why
    `BeaconWire` and the codec carry `genesis_validators_root`. See [`docs/beacon_wire.md`](docs/beacon_wire.md)

### Peer Discovery (discv5)
- Always on, on both chains, on `DEFAULT_DISCOVERY_PORT` (9000) unless `--discovery.port` says otherwise (own UDP socket, must differ from `--gossipsub-port`; checked once by `CommonOptions::validate_ports`). There is no `--discovery.enable`: mainnet bootnode ENRs are not statically dialable so a crawl is its only way to find a peer, and a lean node with no `--bootnodes` is in the same position. Co-located nodes on one host must each pass `--discovery.port`
- Reuses ethrex's `DiscoveryServer` + `PeerTable` with discv4 disabled; `spawn` takes the prepared lean ENR, so the record ethrex serves is the one we report
- ENR follows the beacon phase0 spec: `ip`/`udp`/`quic`/`tcp`/`secp256k1`/`eth2`/`attnets`
- Admission mirrors lighthouse: `eth2.fork_digest` must match, `next_fork_*` may differ, a `quic` or `tcp` entry required. Handed to the peer table as `LeanFilter: PeerFilter`, so records are judged on arrival, not at dial time; a reject is re-judged on a higher-`seq` ENR
- Candidates ranked by uncovered attestation subnets. See [`docs/discovery.md`](docs/discovery.md)

### Retry Strategy on Block Requests
- Exponential backoff: doubling from `INITIAL_BACKOFF_MS` (5ms → 2560ms)
- Max `MAX_FETCH_RETRIES` (10) attempts, random peer selection on retry

### Message IDs
- 20-byte truncated SHA256 of: domain (valid/invalid snappy) + topic + data

## One startup path for both chains (`bin/ethlambda/src/main.rs`)

`ethlambda node` and `ethlambda beacon` are the same entry point. Each parses
into one `cli::Options { common, network }`, where `network` is
`Network::Lean(LeanOptions)` or `Network::Mainnet`. The lean variant carries
that chain's own flags, so a lean-only flag is unreachable on the mainnet path
by construction rather than by an `Option` nobody unwraps; `Mainnet` is a unit
variant, since every flag `beacon` takes is a common one.

`run_node` owns everything that is not chain-specific, in order: the discv5
port check, metrics registration, the banner and version log, the
`RLIMIT_NOFILE` raise, the `HIVE_LEAN_TEST_DRIVER` early return (lean-only, and
it must still precede key loading), `--node-key` resolution, reading
`--bootnodes`, and building the aggregator, sync-status and event handles.

It then branches **once**, on `network`, both arms inline, each evaluating to a
`ChainSetup`: the wire configuration, the ENR entries that describe it, the
`Store` the req/resp handlers answer from, the node-name roster, and a
`ChainActor` saying what to spawn this chain's actor with (lean's validator
keys and `BlockChainConfig`, or beacon's `Beacon` marker). The rest of the
discv5 configuration is the node key, the ports, the bootnodes and the peer
target, which are operator input and identical either way, so `run_node` fills
those in once below the match rather than having each arm repeat them.
Everything after that match is shared again: one `build_swarm`, one
`P2P::spawn`, one `start_rpc_server`, and one chain actor, since `ChainActor`
selects between `BlockChain::spawn` and `BlockChain::spawn_beacon` rather than
between spawning one and not. The `InitP2P`/`InitBlockChain` wiring and
`wait_for_shutdown` are then shared too.

`ChainSetup` is a data bag, not an abstraction. The match that fills it stays
inline, because moving it into a method would relocate the branch rather than
remove it.

Two consequences of "one call site" worth knowing. `P2P::spawn` now runs
*before* `BlockChain::spawn`, so gossip arriving in between hits a `P2PServer`
whose `blockchain` is still `None` and is dropped; every access is an `if let
Some`, and the window is a handful of statements. And `beacon` now binds
`--api-port` off a real, DB-backed anchored `Store`, not an empty in-memory
placeholder: checkpoint sync or resume gives it one, the same way `node` gets
its own. The lean-shaped `/lean/v0/...` routes still don't answer for it,
though: they read metadata keys and state variants a beacon directory never
carries, so calling one of them, e.g. `GET /lean/v0/states/finalized`, panics
that request rather than quietly answering for a chain that is not running.
That panic is deliberate, not an accepted placeholder: failing loudly beats
making up an answer in a lean shape for a chain that does not keep one.

`RunningNode.blockchain` is a plain `BlockChain`, not an `Option`: the beacon
follower runs a chain actor too, so there is always exactly one to stop and
join, and `run_node` spawns and wires it before building the struct. Mainnet
therefore gets the same graceful shutdown, metrics bootstrap and fd-limit raise
lean does (it used to park on `std::future::pending()`).

`docs/cli.md` has the step-by-step table.

### Mainnet's genesis is built into the binary

`beacon`'s `genesis_time` and `genesis_validators_root`, which the fork digest
keying every gossip topic, the ENR `eth2` entry and discv5 admission are
computed from, come from `bin/ethlambda/assets/mainnet/genesis.ssz`. That is
`metadata/genesis.ssz` from `eth-clients/mainnet` byte for byte, the same repo
`beacon::MAINNET_BOOTNODES` is copied from, so both of this chain's hardcoded
values have one upstream; `beacon::tests::the_shipped_state_is_eth_clients_file`
pins its SHA-256 so replacing it has to be deliberate.
`beacon::mainnet_genesis_state` decodes it as a **phase0** `BeaconState`, whole
rather than reading the prefix those two fields sit in, so a corrupt asset fails
loudly at startup rather than yielding two plausible numbers. 5.4 MB stored
uncompressed and about 4 ms to decode: a deflated copy is under a third the
size, but paying for it means a zip or gzip decoder in the dependency graph to
read one build-time constant.

Two consequences. `beacon` takes **no genesis** configuration: `genesis_time`
and `genesis_validators_root` need nothing from the command line. And a build
with `ethlambda-types/preset-minimal` on cannot decode this asset, because the
minimal preset shortens the state's fixed-size vectors; nothing enables that
feature for this binary, and failing is the right answer if anything does.

`--checkpoint-sync-url` is no longer merely accepted-but-unused on `beacon`:
the anchor work has landed, and this flag is now how `beacon` fetches its
finalized `BeaconState` and anchor block from a standard Beacon API server,
required on a fresh data directory since this chain has no genesis-sync path
(see `docs/checkpoint_sync.md`).

These genesis values used to come from a Beacon API's `/eth/v1/beacon/genesis`,
which made a `beacon` run depend on a checkpoint provider being reachable. They
are properties of the chain, not of a provider. Checkpoint sync itself is a
separate concern, and now runs on both chains: lean still fetches a
*finalized* anchor, which genuinely has no local source, and `beacon` fetches
one too. The URL cleaning, base-URL trim and first-success fan-out that the
old genesis-fetching path and lean's checkpoint sync once shared through a
`checkpoint_common` module live in `checkpoint_sync.rs`, which today serves
both chains' anchor fetches rather than lean's alone.

## HTTP Servers (API + Metrics)

The RPC crate serves the API router (`--api-port`, default 5052) and the metrics/debug routers
(`--metrics-port`, default 5054). When the two ports differ it binds two independent Axum servers;
when they are equal it merges all three routers onto a single listener, so pointing both flags at
one port is supported and not a misconfiguration.

Both sub-commands bind through one call to `start_rpc_server`, from one site in `run_node`, so
both serve all three routers. `beacon` reaches it with real handles now: the DB-backed anchored
`Store` its `P2PServer` already holds (checkpoint sync or resume gave it one, the same way `node`
gets its own), plus clones of the same `SyncStatusController` and `EventBus` its chain actor
writes to, so the follower's own sync status and chain events are what these report. Only the
`AggregatorController`, seeded `false`, stays a placeholder: this chain has no aggregator duty to
toggle. The lean-shaped `/lean/v0/...` routes still
don't answer for a `beacon` run, though: they read metadata keys and state variants a beacon
directory never carries, so calling one panics that request rather than answering for a chain that
is not running (see "One startup path for both chains" above). That is deliberate for now, to keep
one HTTP call site rather than two; giving the beacon follower its own surface is a change of its
own. `start_http_servers(config, api_router, shutdown)` still takes `api_router` as an `Option` and
`crates/net/rpc/tests/http_servers.rs` still covers the `None` arm, because that is the shape the
beacon follower returns to once it has a surface of its own.

See [`docs/rpc.md`](docs/rpc.md) for the full reference: CLI flags and defaults, the API endpoints (health, finalized state/block, justified checkpoint, blocks by root/slot, fork-choice tree + D3.js UI, runtime aggregator toggle), the metrics/debug endpoints (Prometheus `/metrics`, jemalloc heap profiling), the Hive test-driver endpoints, plus request/response shapes, status codes, and content types.

## Beacon Chain types (`crates/common/types/src/beacon/`)

`ethlambda-types` carries the **Ethereum Beacon Chain** containers (phase0
through fulu) alongside lean's own types. The Beacon Chain is a different
protocol from the Lean consensus this repo implements; the types share a crate
so that one `BlockChainServer` can dispatch on a single state type instead of
existing once per chain.

- `BeaconState` has a **`Lean` variant holding lean's `State`**, and `ForkName`
  a matching `Lean`. Only `fork_name()` and `from_ssz()` handle it; every other
  beacon accessor answers `unreachable!()` naming itself. The guarantee is the
  single `match` at the top of each handler, not the type system, so a lean
  state reaching a beacon accessor should fail as a named panic rather than a
  silent wrong answer.
- **`ForkName::Lean` is deliberately absent from `ForkName::ALL`.** `ALL` is
  what `parse`, `previous` and `next` search, so its absence keeps
  `parse("lean")` at `None` and `Fulu.next()` at `None`, meaning a fork upgrade
  cannot walk off the end into lean. Lean is not a point on the Beacon Chain's
  fork timeline. `Lean` is declared *last* so the derived `Ord` puts it after
  every beacon fork, which is what `fork >= ForkName::X` gating reads.
- Preset is a **compile-time** choice (`preset-minimal` feature on this crate)
  because SSZ container bounds are const-generic arguments; fork scheduling is
  runtime (`beacon::config`) instead. Every lean crate depends on
  `ethlambda-types`, so enabling the feature rebuilds it for the whole graph;
  lean code reads none of the beacon preset constants, so it cannot change lean
  behavior.
- Per-fork containers are plain structs behind an enum, so SSZ stays derived:
  two of phase0's fields are *replaced* in altair, one field changes type in
  five separate forks, and the state's merkle tree gains a level at electra.
- **`beacon::primitives::Root` *is* `primitives::H256`**, not a second 32-byte
  hash converted at the boundary, and `beacon::primitives::HashTreeRoot`
  re-exports lean's convenience trait rather than declaring its own. The
  primitive family a beacon container needs beyond that is two newtypes,
  `H160` and `U256`, so the crate declares them instead of depending on
  `ethereum-types`. Two consequences worth knowing:
  - `U256` holds the **32 little-endian bytes SSZ encodes it as**, so its
    stored byte order is the reverse of its numeric one and `Ord` is written
    out by hand. Do not derive it: a derived `Ord` compares the least
    significant byte first, which would silently invert
    `terminal_total_difficulty` comparisons.
  - `H160` writes out `libssz_merkle::HashTreeRoot` because the derive drops
    `is_basic_type`, and at 20 bytes wide that answer changes the merkle tree
    of any list or vector of addresses. Everything else here is 32 bytes,
    where packing and per-element padding coincide, so the derive is fine.
- **Requires mutable element access on `SszList`**, which no published libssz
  release has, so all four libssz crates are **git dependencies** on
  `lambdaclass/libssz` (for lambdaclass/libssz#33), pinned by `rev` rather than
  tracking `main`: this is the SSZ encoder and merkleizer behind every
  `hash_tree_root`, so a routine `cargo update` must not be able to move it.
  Return them to a crates.io version once a release carries #33. A git dependency rather than a
  `[patch.crates-io]` override because nothing outside this workspace depends on
  libssz, so there is no second copy to unify; that also keeps the manifest free
  of a `[patch]` table, which `shadow/cargo-patch.toml` would collide with.
- The state transition consuming these containers is **not** in this repo yet;
  it lives on `feat/beacon-chain-stf`, where these types are verified against
  consensus-specs v1.6.1 (5705 mainnet / 40009 minimal cases). What runs here
  is the containers' own round-trip and shape tests.

## Beacon Chain STF (`crates/blockchain/state_transition/src/beacon/`)

The **Ethereum Beacon Chain** consensus specs (phase0 through fulu), a different
protocol from the Lean consensus the rest of this repo implements, live in the
`beacon` module of `ethlambda-state-transition` beside lean's own state
transition. The module holds the *behavior* (state transition, fork choice,
helpers, BLS and KZG); the containers, presets, configuration and primitives it
transitions are in `ethlambda-types`, per the section above. Nothing above
`beacon` reads anything inside it, and nothing inside it reads lean's modules.

- **`blst` and `c-kzg` are now on the lean binary's dependency path**, since
  `ethlambda-blockchain`, `ethlambda-rpc` and `ethlambda-test-fixtures` all
  depend on this crate. That is the cost of one crate holding both chains'
  rules; the module is not feature-gated.
- Tests: `make test-beacon` (builds once per preset), or `test-beacon-mainnet` /
  `test-beacon-minimal` for one. CI runs the two as a job each, so they build and
  run concurrently. `make test` covers the whole
  workspace, in two halves, and still needs no fixture download: the
  `beacon_spec_tests` target declares `required-features = ["beacon-spec-tests"]`
  so `cargo test` skips it, and the BLS and KZG fixture vectors, which are unit
  tests inside the module, are `#[cfg_attr(not(feature = ...), ignore)]` so they
  report as ignored rather than silently absent. Turning the feature on is what
  `make test-beacon` does, and it runs `--lib` too so those 15 are not missed.
- Every fixture case is its own test, named `<runner>/<fork>/<handler>/<suite>/<case>`,
  so a failure names the case and not the suite around it. The spec binary
  therefore supplies its own harness (`harness = false`), since a case is only
  known once the fixture tree is walked. A substring filter selects a whole
  suite or one case: `cargo test -p ethlambda-state-transition --test
  beacon_spec_tests --features beacon-spec-tests -- electra/attester_slashing`.
- Fixtures: `make consensus-spec-tests`, pinned to a `consensus-specs` release.
  The tree is stamped with the version *and* the configs it holds, so changing
  either wipes and re-downloads rather than leaving the old cases in place and
  silently green, or marking a partial tree complete.
  `CONSENSUS_SPEC_TESTS_CONFIGS` narrows the download: a run reads its own
  preset's tree plus `general` and nothing else, which is what each CI job sets.
- Preset is a **compile-time** choice (`preset-minimal` feature) because SSZ
  container bounds are const-generic arguments; fork scheduling is runtime
  because the `transition` suite moves fork epochs per case.
- Per-fork containers are plain structs behind an enum, so SSZ stays derived. See
  [`docs/beacon_stf.md`](docs/beacon_stf.md) for why, including the fork-by-fork
  field counts and the merkle depth change at electra.
- The types are re-exported at their old paths (`crate::beacon::containers`,
  `crate::beacon::preset`, `crate::beacon::config`, ...), so a use site inside
  the module reads as if they were local, and
  `ethlambda_state_transition::beacon::containers::X` and
  `ethlambda_types::beacon::containers::X` name one type. Two things do move the
  other way: `fork_choice` re-exports `LatestMessage` and `PowBlock` from types
  (`ethlambda-storage` persists them), and `helpers::misc` re-exports
  `compute_fork_data_root` (the networking crate needs the fork digest built on
  it).
- **`BeaconState` and `ForkName` carry a `Lean` variant**, so every match on
  either needs an arm for it. Nothing here can transition a lean value, so those
  arms panic through `lean_state_unreachable`/`lean_fork_unreachable`
  (`src/beacon/lean_boundary.rs`, same names and wording as `ethlambda-types`'
  own `pub(crate)` pair) rather than widening a signature to a `Result` no
  correct caller would see. Functions, not a macro, and `#[cold]` +
  `#[track_caller]` so the panic still reports the arm that was reached rather
  than `lean_boundary.rs`. In the spec tests the same arms call
  `lean_is_not_a_fixture_fork`, which is `#[track_caller]` for the same reason,
  since a case's fork is parsed from a directory name and `ForkName::ALL` has no
  lean entry. Both are named arms rather than a
  catch-all `_`, so a real new fork still breaks every match that must grow one.
- **Needs mutable element access on `SszList`/`SszVector`**, which no published
  libssz release has yet. Nothing extra is required here: the workspace already
  tracks all four libssz crates from git at `36802dd` for the beacon containers
  in `ethlambda-types` (see the section above), and that rev is the `0.3.0`
  release plus the single commit adding `DerefMut`/`IndexMut`
  (lambdaclass/libssz#33). This module needs that commit for the same reason.
- **Status:** all seven forks (phase0 through fulu) have containers, fork
  upgrades, state transitions, and epoch processing. Every fixture case passes
  on both presets: mainnet is 5705 cases and minimal 40009. The crate's lib
  target holds 200 tests with `beacon-spec-tests` on, 185 plus 15 ignored
  without; both figures cover lean's own unit tests as well, since the two
  chains now share one lib target. Fork choice is fixture-verified too: 150 mainnet
  `fork_choice` cases pass, covering bellatrix's `on_merge_block`/terminal-PoW
  validation, `should_override_forkchoice_update`, deneb's blob data
  availability, and fulu's column data availability.
- Nothing is ignored for being unimplemented. Ignored cases are the
  `LightClient*` containers (a different layer, out of scope) and the `gloas`
  and `eip7805` fixture trees. Those two do not parse as a `ForkName`, so
  `collect` would skip them silently; `UNMODELED_FORKS` names them and
  `fixture_forks/every_directory_is_accounted_for` fails on any fork directory
  that is neither parseable nor listed, so a new fork forces a decision.
- A fixture case with no `post` state asserts the input must be **rejected**. That
  rule lives in `check_transition`; do not add a runner that ignores it.

## Configuration Files

**Genesis:** `config.yaml` (YAML format, cross-client compatible)
```yaml
GENESIS_TIME: 1770407233
MILLISECONDS_PER_SLOT: 4000  # optional, defaults to DEFAULT_MILLISECONDS_PER_SLOT
GENESIS_VALIDATORS:
  - attestation_pubkey: "cd323f232b34ab26d6db7402c886e74ca81cfd3a..."  # 52-byte XMSS pubkeys (hex)
    proposal_pubkey: "b7b0f72e24801b02bda64073cb4de6699a416b37..."
```
- Validator indices are assigned sequentially (0, 1, 2, ...) based on array order
- `MILLISECONDS_PER_SLOT` must be a multiple of `INTERVALS_PER_SLOT` and at least
  `MIN_MILLISECONDS_PER_SLOT`: the knob slows a network down, it does not speed one up,
  since timings fixed in milliseconds (`EARLY_AGGREGATION_WINDOW`) are sized for the spec
  cadence. It is persisted in the DB's `Metadata["config"]` and a resume with a different
  value is refused. Other clients ignore the key and stay at their compile-time 4s, so it
  only takes effect on an all-ethlambda network
- All genesis state fields (checkpoints, justified_slots, etc.) initialize to zero/empty defaults
- Matches Ream/Zeam format — no extra state fields in the config file

**Bootnodes:** ENR records (Base64-encoded, RLP decoded for the `quic`/`tcp`/`udp` ports + secp256k1 pubkey). A `0` port means absent everywhere, on read and on write. `build_swarm` dedups by `PeerId`: two entries naming one key merge into a single dial

## Testing

### Test Categories
1. **Unit tests**: Embedded in source files
2. **Spec tests**: From `leanSpec/fixtures/consensus/`
   - `crates/blockchain/tests/forkchoice_spectests.rs` (uses `on_block_without_verification` via `spec_test_runner`)
   - `crates/blockchain/tests/signature_spectests.rs`
   - `crates/blockchain/state_transition/tests/stf_spectests.rs` (state transition)

### Running Tests
```bash
cargo test --workspace --profile release-fast                       # All workspace tests
cargo test -p ethlambda-blockchain --test forkchoice_spectests
cargo test -p ethlambda-blockchain --test forkchoice_spectests -- --test-threads=1  # Sequential
```

Tests run under `release-fast`: release-grade opt-level (needed to avoid stack
overflows in signature verification/aggregation) but no LTO, parallel codegen,
incremental, and line-tables-only debuginfo, so rebuilds are much faster than
`--release`. Artifacts land in `target/release-fast/`, separate from
`cargo build --release`.

## Common Gotchas

### Aggregator Flag Required for Finalization
- At least one node **must** be started with `--is-aggregator` to finalize blocks
- Without this flag, attestations pass signature verification and are logged as "Attestation processed", but the signature is never stored for aggregation (the `is_aggregator` gate in `on_gossip_attestation`, `store.rs`), so blocks are always built with `attestation_count=0`
- The attestation pipeline: gossip → verify signature → store gossip signature (only if `is_aggregator`) → aggregate at interval 2 → promote to known → pack into blocks
- **Symptom**: `justified_slot=0` and `finalized_slot=0` indefinitely despite healthy block production and attestation gossip

### Runtime Aggregator Toggle (Hot-Standby Model)
- `POST /lean/v0/admin/aggregator` with `{"enabled": bool}` toggles the aggregator role at runtime without restart (ported from leanSpec PR #636)
- `GET /lean/v0/admin/aggregator` returns `{"is_aggregator": bool}`
- The CLI `--is-aggregator` flag **seeds** the initial value; runtime toggles are in-process only (not persisted across restarts)
- Runtime toggles do NOT resubscribe gossip subnets — those are frozen at startup by `build_swarm`. Toggling ON at runtime only activates aggregation logic for subnets the node was already subscribed to
- **Operational model**: standby aggregators should boot with `--is-aggregator=true` (so subscriptions are in place), then use the admin endpoint to rotate duties. A node booted with `--is-aggregator=false` and toggled ON later will have no extra subnets to aggregate

### Signature Verification
- Fork choice tests use `on_block_without_verification()` to skip signature checks
- Signature spec tests use `on_block()` which always verifies
- Crypto tests marked `#[ignore]` (slow leanVM operations)

### Storage

Blocks split across `BlockHeaders`/`BlockBodies`/`BlockProof`; states are
snapshot (`States`) + diff (`StateDiffs`) pairs; `BlockRoots` and `LiveChain`
index by slot for range serving and fork choice. Attestations and gossip
signatures are not persisted; they live in in-memory `Store` buffers consumed
during the tick pipeline. See [`docs/data_storage.md`](docs/data_storage.md)
for the full reference: what each of the eight tables holds and how it's
keyed, the snapshot/diff reconstruction algorithm, the block-import write
sequence, pruning rules, what never changes at runtime, and startup/restore
behavior.

- `BlockProof` is the only pruned block table (below the finalized
  boundary); `get_signed_block` returns `None` for a pruned finalized block.
- A `StateDiff` omits `config` and `validators`, trusting they never mutate;
  breaking that invariant would silently corrupt every reconstructed state.
- `Metadata["config"]` is written once at bootstrap and never rewritten; it
  doubles as the DB's genesis-time fingerprint on resume.

### State Root Computation
- Always computed via `hash_tree_root()` after full state transition
- Must match proposer's pre-computed `block.state_root`

### Finalization Checks
- Use `original_finalized_slot` for justifiability checks during attestation processing
- Finalization updates can occur mid-processing

### `justified_slots` Window Shifting
- Call `shift_window()` when finalization advances
- Prunes justifications for now-finalized slots

## External Dependencies

**Critical:**
- `leansig`: XMSS signatures (leanEthereum project)
- `libssz` / `libssz-derive` / `libssz-types`: SSZ serialization
- `libssz-merkle`: Merkle tree hashing (`hash_tree_root()`)
- `spawned-concurrency`: Actor model
- `libp2p`: P2P networking (custom LambdaClass fork)
- `vergen-git2`: Build-time git commit/branch info embedded in binary

**Storage:**
- `rocksdb`: Persistent backend
- In-memory backend for tests

## Resources

**Specs:** `leanSpec/src/lean_spec/spec/` (Python reference implementation; fork logic under `forks/<fork>/`, e.g. `forks/lstar/`)
**Devnet:** `lean-quickstart` (github.com/blockblaz/lean-quickstart)
**Docs:** `docs/` — `rpc.md`, `metrics.md`, `checkpoint_sync.md`, `3sf_mini.md`, `lmd_ghost.md` (mdbook via `make docs`)
**Releases:** See `RELEASE.md` for release process documentation

## Other implementations

- zeam (Zig): <https://github.com/blockblaz/zeam>
- ream (Rust): <https://github.com/ReamLabs/ream>
- qlean (C++): <https://github.com/qdrvm/qlean-mini>
- grandine (Rust): <https://github.com/grandinetech/lean/tree/main/lean_client>
- gean (Go): <https://github.com/geanlabs/gean>
- Lantern (C): <https://github.com/Pier-Two/lantern>
