# ethlambda Development Guide

Development reference for ethlambda - minimalist Lean Ethereum consensus client.
Not to be confused with Ethereum consensus clients AKA Beacon Chain clients AKA Eth2 clients.

## Quick Reference

**Main branch:** `main`
**Rust version:** 1.97.1 (edition 2024)
**Test fixtures release:** Download latest production fixtures from leanSpec releases

## Codebase Structure (13 workspace crates)

```
bin/ethlambda/              # Entry point, CLI, orchestration
  ├─ src/main.rs            # run_node: one entry point for both chains (see below)
  ├─ src/cli.rs             # Options { common, network: Lean | Mainnet }
  ├─ src/command.rs         # Sub-command dispatch + default-subcommand injection
  ├─ src/beacon.rs          # Beacon wire params derived from a resolved network: epoch, fork digest
  ├─ src/checkpoint_sync.rs # Checkpoint sync for both chains (lean's `/lean/v0/...`, beacon's Beacon API)
  ├─ src/network/           # --network resolution: built-in name vs. directory of published files
  │   └─ built_in.rs        # Built-in chains (mainnet, sepolia, hoodi) and their genesis constants
  ├─ assets/{mainnet,sepolia,hoodi}/  # config.yaml + bootstrap_nodes.yaml (eth-clients/<name>'s files)
  ├─ tests/fixtures/networks/mainnet/genesis.ssz  # Mainnet genesis state, test-only
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
    ├─ crypto/              # XMSS sign/verify + aggregation (leanVM wrapper)
    ├─ ssz-tree/            # Persistent Merkle tree (List/Vector) behind the beacon registry and balances
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
- Wire sizes: `PUBLIC_KEY_SIZE` (`common/types/src/state.rs`) and `SIGNATURE_SIZE`
  (`common/types/src/attestation.rs`), static-asserted against leanVM's scheme
  constants in `common/crypto/src/signature.rs`
- Epoch-based to prevent reuse
- Signing, verification, and aggregation all come from leanVM, which internalized
  XMSS in its own `xmss` crate; there is no external leanSig dependency
- BLAKE2s over binary fields, not Poseidon over KoalaBear: a leanVM `main` bump
  across that rewrite invalidates every genesis key and every stored proof, even
  when the wire sizes happen to match
- `ethlambda_crypto::init_leanvm(use_arena)` must run once at startup, before any
  proving or proof decoding. `--prover-arena` opts into leanVM's bump arena,
  which recycles the prover's large buffers across proofs instead of re-faulting
  them, so its pages stay resident for the node's lifetime
- `ethlambda keygen` generates genesis validator keys through the same
  `ValidatorSecretKey` the node loads them with, so a key set cannot be built
  against a different leanVM than the client reading it. Keys are only usable by
  a client on the matching revision, and no file size changes when the scheme
  does, so the manifest records `leanvm_rev`. See [`docs/keygen.md`](docs/keygen.md)

**Aggregation shape (one leanVM `AggregateSignature`, grouped by `(epoch, message)`):**
- Type-1 and Type-2 are the same object: one `XmssGroup` per `(epoch, message)`
  pair, carrying that group's sorted, deduplicated keys
- **A slot can carry several messages.** Validators attesting moments apart
  disagree within a slot, so two distinct `AttestationData` at one slot is
  ordinary rather than equivocation and a block routinely carries both. The
  groups are sorted on the whole pair: with two of them at one slot, sorting on
  the epoch alone rebuilds a different signer set and fails a valid proof
- **The binding is off the wire.** `to_bytes_without_pubkeys()` carries neither
  the keys nor the `(slot, message)` pairs, so every decode rebuilds the whole
  signer set from a `SignerSet` per claim. A wrong set, message or slot decodes
  fine and fails inside the SNARK verifier, so there is no cheap binding check
- Narrowing replaces splitting: re-aggregate the parent with a `declare` naming
  the group to keep (`split_type_2_by_message`)

**Signature Aggregation (Two-Phase):**
1. **Gossip signatures**: Fresh XMSS from network → aggregate via leanVM
2. **Fallback to proofs**: Reuse previous block proofs for missing validators

## Networking (libp2p)

### Protocols
- **Transport**: QUIC over UDP (TLS 1.3), plus TCP (noise, then yamux or mplex) on the same port number as a fallback: a peer whose advertised `quic` doesn't answer can still be reached over TCP. Both addresses go into one dial, `quic` first, and `DIAL_ADDRESS_CONCURRENCY` pins `dial_concurrency_factor` to one, so the order is a real preference and TCP is tried only after the QUIC attempt fails. Mainnet beacon peers answer `na` to a yamux-only proposal, so TCP connections negotiate mplex (see the `muxers` module doc), which is expensive: preferring QUIC is how that cost is avoided where the peer allows it
  - Binding TCP puts `--gossipsub-port` in the HTTP servers' namespace, so it must now differ from `--api-port`/`--metrics-port` too. `Options::validate_ports` rejects every clash before anything binds
- **Gossipsub**: Blocks + Attestations (snappy raw compression)
  - Topic: `/leanconsensus/{fork_digest}/{block|aggregation|attestation_N}/ssz_snappy`
  - `fork_digest` is a 4-byte hex string (no `0x` prefix); currently the dummy `12345678` agreed across clients
  - Mesh size: 8 (6-12 bounds), heartbeat: 700ms
  - Beacon wire: `validate_messages()` is on, so every beacon message waits for a verdict (~4.2s before gossipsub's cache evicts it). Rules in `state_transition::beacon::gossip` (cheap half inline, stateful half on a bounded `spawn_blocking` task); plumbing in `p2p/src/beacon/verdict.rs`. Lean gossip still auto-forwards
  - Data columns: every check runs in p2p. A column gossip did not accept (`Queue`/`Overloaded`), every fetched column, and parked columns replayed after their parent imports go through `column::chain_checks` in `p2p/src/beacon/column_checks.rs`. The chain actor stores what it gets unchecked; only debug builds re-run `chain_checks` there
  - Beacon subscribes seven global topics plus two node-id-derived subnet families: custody
    columns and backbone attestation subnets. `beacon_aggregate_and_proof` and
    `beacon_attestation_{subnet_id}` validate in p2p like blocks/columns, with their own
    permit pool. The actor applies only accepted aggregates, attesting indices already
    gossip-verified, held one slot per `validate_on_attestation`'s `current_slot >= data.slot
    + 1`; subnet attestations are verified and relayed but never applied. See
    [`docs/beacon_wire.md`](docs/beacon_wire.md)
  - `voluntary_exit`, `proposer_slashing`, `attester_slashing` and `bls_to_execution_change`
    validate in p2p like aggregates (`gossip::operations`, against the unadvanced head state) and
    feed `Store::operation_pool`; the attestation pool is in `Store` too. Both are in memory, and
    block production packs the operation pool through `pack_operations`
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
- Always on for `beacon` (mainnet bootnode ENRs are not statically dialable, so a crawl is its only way to find a peer); opt-in for `node` behind the lean-only `--discovery.enable`, off by default, so a lean node peers from `--bootnodes` alone and binds no discovery socket. `Network::discovery_enabled` is the one answer; `P2P::spawn` takes `Option<DiscoverySpawnConfig>` and `P2PServer.discovery` is an `Option`, `None` leaving the dial loop unscheduled
- Where it runs: `DEFAULT_DISCOVERY_PORT` (9000) unless `--discovery.port` says otherwise (own UDP socket, must differ from `--gossipsub-port`; checked once by `Options::validate_ports`, which skips the discovery rules when it is off). Co-located nodes that run discovery must each pass `--discovery.port`
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
`Network::Lean(LeanOptions)` or `Network::Mainnet { mainnet, execution }`. Each
variant carries that chain's own flags, so a flag one chain does not take is
unreachable on the other's path by construction rather than by an `Option`
nobody unwraps. `MainnetOptions` holds the three flags `beacon` has of its own:
`--custody-group-count`, `--safe-slots-to-import-optimistically`, and
`--network` (default `mainnet`). The last is carried unresolved: `run_node` is
where a bad value is reported.

`run_node` owns everything that is not chain-specific, in order: the discv5
port check, metrics registration, the banner and version log, the
`RLIMIT_NOFILE` raise, the `HIVE_LEAN_TEST_DRIVER` early return (lean-only, and
it must still precede key loading), `--node-key` resolution, resolving
`--network` into a `NetworkSource` (mainnet only; must precede the next step,
since a loaded network's own bootnode list is part of its fallback), reading
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
its own, and it serves the **Beacon API** off it rather than the lean-shaped
`/lean/v0/...` routes, which read metadata keys and state variants a beacon
directory never carries. Which surface a node serves follows from
`Store::chain()`, not from the sub-command, so the two cannot disagree; a
`/lean/v0` path on a `beacon` run is a 404 rather than the panicked request it
used to be.

`RunningNode.blockchain` is a plain `BlockChain`, not an `Option`: the beacon
follower runs a chain actor too, so there is always exactly one to stop and
join, and `run_node` spawns and wires it before building the struct. Mainnet
therefore gets the same graceful shutdown, metrics bootstrap and fd-limit raise
lean does (it used to park on `std::future::pending()`).

`docs/cli.md` has the step-by-step table.

### Built-in networks

`beacon` takes a `--network` flag (built-in name `mainnet` (default),
`sepolia` or `hoodi`, or a path to a directory of published network files)
and resolves it into a `NetworkSource` before doing anything else; see
`bin/ethlambda/src/network/`. `genesis_time` and `genesis_validators_root`,
which the fork digest keying every gossip topic, the ENR `eth2` entry and
discv5 admission are computed from, come from that resolved network.

Every built-in chain is a `network::built_in::EmbeddedChain`: its
`eth-clients` repo's `config.yaml` and `bootstrap_nodes.yaml` byte for byte
(`bin/ethlambda/assets/<name>/`), parsed through the same
`ConfigFile::parse`/bootnode reader a directory goes through, plus the two
genesis values as constants. None carries a **genesis state**: a built-in
network never anchors at genesis, and the states are 5 MB (mainnet) to 150 MB
(Hoodi). The constants are checked offline (mainnet's against
`tests/fixtures/networks/mainnet/genesis.ssz`, eth-clients' file, whose SHA-256
`beacon::tests::the_fixture_state_is_eth_clients_file` pins; Sepolia's and
Hoodi's against fork digests published in their own bootnode ENRs), and at
runtime by checkpoint sync and resume, which both check the anchor state
against them. `beacon::tests::the_built_in_network_derives_what_it_always_did`
pins the parsed mainnet config to `Config::mainnet()`, so the file and the
Rust constant cannot drift apart. Sepolia's config schedules gloas, which this
build cannot process, so a Sepolia follower stops tracking the chain at
`GLOAS_FORK_EPOCH`; the ignored-keys warning at startup names it.

A loaded network decodes its own `genesis.ssz` instead, at whatever fork its
own schedule names for epoch 0. Every `config.yaml`, built-in or loaded, goes
through two checks as soon as it parses, and a failure is a hard startup
error. For a directory they run before its `genesis.ssz` is decoded, since
the compiled preset sets that state's container bounds and a mismatch would
otherwise surface as an SSZ error:

- `check_preset`: `PRESET_BASE` must name the compiled preset.
- `check_constants`: every key the node runs on a compile-time constant for
  instead of reading `Config` (the custody counts, subnet counts,
  `MAX_REQUEST_*`, `MAX_PAYLOAD_SIZE`, the snappy message domains,
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY`) must equal that constant.
  `/eth/v1/config/spec` reports these keys off the stored `Config`, so this is
  what keeps it from reporting a value the node does not use. A new such
  constant needs a line in `check_constants`.

Two consequences, on the built-in arm. `beacon` takes **no genesis**
configuration of its own the way `node` does: `genesis_time` and
`genesis_validators_root` need nothing from the command line beyond
`--network`. And a build with `ethlambda-types/preset-minimal` on refuses every
built-in network, since each declares `PRESET_BASE: mainnet`; nothing enables
that feature for this binary, and failing is the right answer if anything does.

`--checkpoint-sync-url` is no longer merely accepted-but-unused on `beacon`:
the anchor work has landed, and this flag is now how `beacon` fetches its
finalized `BeaconState` and anchor block from a standard Beacon API server.
The full anchor precedence is a resumable data directory, then this URL, then,
for a loaded network only, the resolved network's own `genesis.ssz`, then
abort. The URL is therefore required on a fresh data directory only for the
built-in networks, since they alone have no genesis-sync path (see
`docs/checkpoint_sync.md`).

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

Both sub-commands bind from one site in `run_node`, which picks the API router by
`Store::chain()` rather than by sub-command, so the surface and the data behind it cannot
disagree. `node` calls `start_rpc_server` and gets `/lean/v0`; `beacon` calls
`start_beacon_rpc_server` and gets the **Beacon API** under `/eth/v1` and `/eth/v2`
(`crates/net/rpc/src/beacon/`, one file per endpoint group). Both reach it with real
handles: the DB-backed anchored `Store` the `P2PServer` already holds, plus a clone of the
same `SyncStatusController` the chain actor writes to. The beacon arm takes no
`AggregatorController` and no `EventBus`, because a follower has no aggregator duty to
toggle and the chain-events stream is part of the lean surface. It does take the P2P
actor's `RpcToP2PRef` (`crates/net/api`), the one path by which this node gossips on the
beacon wire: `POST /eth/v2/beacon/pool/attestations` validates a validator client's
attestations and publishes them through it.

The two API routers are alternatives, never merged. A `/lean/v0` path on a `beacon` run is
a 404: those handlers read lean state variants and metadata keys a beacon directory never
carries, so serving both off one store would answer lean questions with beacon data, or
panic trying. `crates/net/rpc/tests/http_servers.rs` pins both halves of that.
`start_http_servers(config, api_router, shutdown)` still takes `api_router` as an `Option`
and that test still covers the `None` arm, which is now the test-driver-less shape rather
than the beacon one.

Encoding differs between the two surfaces, deliberately. The Beacon API serves **JSON by
default** and SSZ on `Accept: application/octet-stream`, quotes every integer, and tags
fork-versioned responses with `Eth-Consensus-Version`. The lean surface keeps **SSZ as the
default** on its two SSZ endpoints and bare integers in JSON, because
`checkpoint_sync.rs` and other clients' lean sync read those bytes and may send no
`Accept` at all; `/lean/v0/blocks/finalized` now answers JSON when asked for it by name.

See [`docs/rpc.md`](docs/rpc.md) for the full reference: CLI flags and defaults, the lean API endpoints (health, finalized state/block, justified checkpoint, blocks by root/slot, fork-choice tree + D3.js UI, runtime aggregator toggle), the Beacon API endpoints and the three ids they refuse, the metrics/debug endpoints (Prometheus `/metrics`, jemalloc heap profiling), the Hive test-driver endpoints, plus request/response shapes, status codes, and content types.

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
- **`Validators` and `Balances` are `ethlambda_ssz_tree::List`s**, persistent
  Merkle trees that cache node hashes and share unchanged subtrees between
  states through `Arc`; they have no slices and no `iter_mut`. A leaf holds a
  page-sized run of elements rather than one chunk, and an inner node a page of
  child pointers spanning several binary levels, so a lookup crosses a handful
  of nodes and a rebuilt leaf or node copies one page. Writes are
  buffered until `BeaconState::apply_pending_mutations`, which the state
  transition calls before every state-root computation. A state decoded from
  storage is rebased onto a cached one (`Store::get_state`).
  - **`state.validator(i)` and `balances()[i]` are tree descents, not array
    indexing.** A loop over the registry should walk `validators().iter()`
    (zipped with `balances().iter()` where it needs both), not index per
    validator: helpers that build the active-index `Vec` and then read each
    index back were the largest cost left in the import profile
    (`docs/beacon_stf.md`, "Registry and balances").

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
- The BLS wrapper lives in `ethlambda_crypto::bls` and is re-exported as
  `beacon::bls`, so p2p's operation validation and `ethlambda-rpc` can verify
  signatures without depending on this crate: `ethlambda-storage`'s attestation
  pool (now owned by `Store`) aggregates signatures, and storage cannot depend
  on `ethlambda-state-transition`.
- The `beacon_aggregate_and_proof`/`beacon_attestation_{subnet_id}` gossip rules
  (committees, `is_aggregator`, all the signatures) live in
  `gossip::{aggregate,attestation}`, validated in `ethlambda-p2p` off the vote
  block's own cached post-state, not the chain actor. `aggregate.rs` keeps only
  what the actor's applied-bits gate still needs (`is_non_strict_superset`,
  `MAX_AGGREGATES_PER_SLOT`); `fork_choice::apply_verified_aggregate` is
  apply-only, no committee lookup or signature check left in it. `das.rs` is
  the one module still holding `p2p-interface.md` rules here rather than in
  p2p: it needs no state, but the `networking` fixture suite has handlers for
  `get_custody_groups` and `compute_columns_for_custody_group`, and that runner
  lives in this crate's `tests/beacon_spec/`. The attestation-subnet backbone's
  own subnet-selection math is neither, so it lives with the wire code it
  serves, in `ethlambda-p2p`'s
  `beacon::subnets`.
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
  - attestation_pubkey: "cd323f232b34ab26d6db7402c886e74ca81cfd3a..."  # XMSS pubkeys, hex, PUBLIC_KEY_SIZE bytes
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
for the full reference: what each of the ten tables holds and how it's
keyed, the snapshot/diff reconstruction algorithm, the block-import write
sequence, pruning rules, what never changes at runtime, and startup/restore
behavior.

- `BlockProof` is the only pruned block table (below the finalized
  boundary); `get_signed_block` returns `None` for a pruned finalized block.
- A `StateDiff` omits `config` and `validators`, trusting they never mutate;
  breaking that invariant would silently corrupt every reconstructed state.
- `Metadata["config"]` is written once at bootstrap and never rewritten; it
  doubles as the DB's genesis-time fingerprint on resume. A beacon resume also
  refuses a config file that changes a chain value in it
  (`first_config_difference`: fork schedule, slot time, `PRESET_BASE`, ...),
  but only warns about a changed `CONFIG_NAME`, a label with no consensus
  effect. The stored name is the one the node keeps reporting.
- `PendingDataColumns` holds *unverified* sidecars parked until their block's
  parent has a post-state. `data_column_indices_for` reads `DataColumns` only,
  which is what keeps a parked column from satisfying the availability gate.
  Its only index is the chain actor's in-memory `sidecars_awaiting_parent`, so
  `start_actor` clears the whole table at startup.
- `DB_VERSION` is 4: `Config` gained `PRESET_BASE` and `CONFIG_NAME` (as
  `ConfigName`, a bounded string) at the front of its encoding, and it is
  SSZ-encoded under `KEY_CONFIG`, so a data directory written by an earlier
  version decodes into the wrong fields. (3 was the runtime keys a
  `config.yaml` supplies.) `Store::from_db_state` refuses any other version
  outright; there is no migration.

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
- `leanvm`: XMSS signatures and recursive aggregation, taken from leanVM's facade
  crate (which re-exports `xmss`, `rec_aggregation` and its `rand`) and pinned to
  one `main` revision (leanEthereum project)
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
