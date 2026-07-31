# Integrating ethrex in-process

How ethlambda embeds ethrex as a library and drives its execution layer with direct
function calls — no second process, no JSON-RPC, no JWT.

This is a reproducible guide: the steps, the exact ethrex APIs used, the design
decisions and why they were made, how to run it, and how to verify it actually works.
It documents the integration on branch `feat/ethrex-inprocess-poc` (PR #530).

- [1. Architecture](#1-architecture)
- [2. Prerequisites](#2-prerequisites)
- [3. Step-by-step integration](#3-step-by-step-integration)
- [4. Running a devnet](#4-running-a-devnet)
- [5. Verifying it works](#5-verifying-it-works)
- [6. Gotchas](#6-gotchas)
- [7. Design decisions](#7-design-decisions)
- [8. References](#8-references)

---

## 1. Architecture

A Lean Ethereum node is two layers that must talk every slot:

| Layer | Component | Responsibility |
|---|---|---|
| Consensus (CL) | ethlambda | Ordering, fork choice, attestations, finality |
| Execution (EL) | ethrex | Executing transactions, computing state |

There are two ways to connect them, and both are supported:

```
external (Engine API)                    inprocess (this guide)
┌────────────────────┐                   ┌──────────────────────────┐
│ ethlambda process  │                   │ ethlambda process        │
│  consensus layer   │                   │   consensus layer        │
└─────────┬──────────┘                   │        │ direct fn call  │
     JSON-RPC + JWT                      │   ethrex, embedded       │
┌─────────┴──────────┐                   │   (library crates)       │
│ ethrex process     │                   └──────────────────────────┘
│  execution layer   │
└────────────────────┘                   one binary, no socket, no auth
```

### The seam: one trait, two implementations

The consensus actor never learns which mode is in use. It holds an
`Option<Arc<dyn ExecutionEngine>>` and calls three methods
(`crates/net/ethrex-client/src/client.rs`):

```rust
#[async_trait::async_trait]
pub trait ExecutionEngine: Send + Sync {
    async fn forkchoice_updated_v3(
        &self,
        state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributesV3>,
    ) -> Result<ForkChoiceUpdatedResponse, EngineClientError>;

    async fn get_payload(&self, payload_id: PayloadId)
        -> Result<ExecutionPayloadV3, EngineClientError>;

    async fn new_payload(&self, payload: &ExecutionPayloadV3, parent_beacon_block_root: H256)
        -> Result<PayloadStatus, EngineClientError>;
}
```

| Implementation | Crate | Backing |
|---|---|---|
| `EngineClient` | `crates/net/ethrex-client` | JSON-RPC over HTTP + JWT to a separate EL |
| `EthrexEngine` | `crates/net/ethrex-engine` | Direct calls into embedded ethrex |

**Consequence:** the in-process work adds a crate and a CLI flag. It changes nothing in
`crates/blockchain`'s call sites.

---

## 2. Prerequisites

- Rust 1.97.1 (see `rust-toolchain.toml`).
- Docker, for building the node image used by the devnet.
- An **ethrex checkout** is useful for reading APIs while developing, but is not a build
  requirement — ethrex is consumed as a pinned git dependency.
- A **Cancun** EL genesis JSON. See [Gotcha 2](#gotcha-2-the-el-genesis-must-be-cancun-not-prague).

---

## 3. Step-by-step integration

### Step 1 — Add the ethrex dependencies

Only three ethrex crates are needed. Add them to `[workspace.dependencies]` in the root
`Cargo.toml`, pinned to one revision:

```toml
# ethrex — pinned git rev. Every ethrex crate in the workspace MUST share this rev:
# ethrex-crypto bundles a C SHA3 whose symbols are not namespaced, so two ethrex
# versions in the graph collide at link time under GNU ld (Linux).
ethrex-common     = { git = "https://github.com/lambdaclass/ethrex", rev = "de9b249b…" }
ethrex-storage    = { git = "https://github.com/lambdaclass/ethrex", rev = "de9b249b…" }
ethrex-blockchain = { git = "https://github.com/lambdaclass/ethrex", rev = "de9b249b…" }
```

> **Do not depend on `ethrex-rpc`.** It contains a ready-made payload↔block conversion,
> but it unconditionally pulls in a full Axum HTTP server *and* `ethrex-p2p`, and offers
> no feature to slim that down. Step 3 reimplements the ~40 lines instead.

**Critical:** audit the workspace for *pre-existing* ethrex dependencies and unify them on
the same rev. In our case `ethlambda-p2p` already vendored ethrex v8 for ENR parsing:

```toml
# crates/net/p2p/Cargo.toml — was rev 1af63a4 (v8); now follows the workspace rev
ethrex-p2p.workspace = true
ethrex-rlp.workspace = true
ethrex-common.workspace = true
```

Why this matters is [Gotcha 1](#gotcha-1-two-ethrex-versions-will-not-link).

Verify the graph has exactly one ethrex:

```bash
grep -A2 'name = "ethrex-crypto"' Cargo.lock | grep -E 'version|rev=' | sort -u
# expect a single version + single rev
```

> Do **not** run `cargo generate-lockfile` / `cargo update` to reconcile. It bumps a
> Plonky3 crate past the pinned toolchain and breaks the build. Let plain `cargo build`
> reconcile the lockfile minimally.

### Step 2 — Create the engine crate and bootstrap ethrex

New crate `crates/net/ethrex-engine` (package `ethlambda-ethrex-engine`), added to the
workspace `members`. Its state is an ethrex `Blockchain` + `Store`:

```rust
pub struct EthrexEngine {
    blockchain: Arc<Blockchain>,
    store: Store,
    extra_data: Bytes,
    gas_ceil: u64,
    /// Payloads built in build-mode FCU, drained by `get_payload`.
    built_payloads: Mutex<HashMap<[u8; 8], ExecutionPayloadV3>>,
}

impl EthrexEngine {
    pub async fn from_genesis(genesis: Genesis) -> Result<Self, EngineError> {
        let mut store = Store::new("", EngineType::InMemory)?;
        store.add_initial_state(genesis).await?;      // async
        let blockchain = Arc::new(Blockchain::default_with_store(store.clone()));
        Ok(Self { blockchain, store, extra_data: Bytes::new(),
                  gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
                  built_payloads: Mutex::new(HashMap::new()) })
    }
}
```

`from_genesis_path(path)` wraps this by parsing the EL genesis JSON with `serde_json`.

The ethrex APIs used, all public library calls:

| Purpose | ethrex API |
|---|---|
| Store (in-memory) | `Store::new(path, EngineType::InMemory)` |
| Seed genesis state | `Store::add_initial_state(genesis).await` |
| Engine | `Blockchain::default_with_store(store)` |
| Head hash / number | `store.get_latest_canonical_block_hash().await`, `store.get_latest_block_number().await` |
| Start a payload | `create_payload(&BuildPayloadArgs, &store, extra_data: Bytes) -> Block` |
| Payload id | `BuildPayloadArgs::id() -> Result<u64, _>` |
| Fill the payload | `Blockchain::build_payload(block) -> PayloadBuildResult` (**sync**) |
| Execute + persist | `Blockchain::add_block(block) -> Result<(), ChainError>` (by value) |
| Fork choice | `apply_fork_choice(&store, head, safe, finalized).await` (**async**) |

Import paths:

```rust
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidForkChoice},
    fork_choice::apply_fork_choice,
    payload::{BuildPayloadArgs, BuildPayloadArgsError, create_payload},
};
use ethrex_common::{Address, Bytes, H256, NativeCrypto,
    types::{Block, DEFAULT_BUILDER_GAS_CEIL, ELASTICITY_MULTIPLIER, Genesis, Withdrawal}};
use ethrex_storage::{EngineType, Store, error::StoreError};
```

### Step 3 — Write the payload ⇄ block conversion

`crates/net/ethrex-engine/src/conversion.rs` mirrors ethrex-rpc's
`ExecutionPayload::{into_block, from_block}` but against `ethrex-common` only. Two
functions:

```rust
pub fn payload_to_block(payload: &ExecutionPayloadV3, parent_beacon_block_root: H256)
    -> Result<Block, EngineError>;
pub fn block_to_payload(block: Block) -> ExecutionPayloadV3;
```

The field mappings that need care:

| ethlambda `ExecutionPayloadV3` | ethrex `Block` | Note |
|---|---|---|
| `transactions: SszList<ByteList,_>` | `body.transactions: Vec<Transaction>` | RLP: `Transaction::decode_canonical` / `encode_canonical_to_vec` |
| — | `header.transactions_root` | recompute: `compute_transactions_root(&txs, &NativeCrypto)` |
| `withdrawals` | `body.withdrawals: Option<Vec<Withdrawal>>` | field-by-field; root via `compute_withdrawals_root` |
| `base_fee_per_gas: [u8; 32]` | `header.base_fee_per_gas: Option<u64>` | big-endian; take/write the low 8 bytes |
| `logs_bloom: [u8; 256]` | `header.logs_bloom: Bloom` | `Bloom::from_slice(..)` / `.0` |
| `fee_recipient: [u8; 20]` | `header.coinbase: Address` | `Address::from_slice(..)` |
| `extra_data: ByteList<32>` | `header.extra_data: Bytes` | `Bytes::copy_from_slice(..)` |
| — | `header.ommers_hash` | constant `*DEFAULT_OMMERS_HASH`; `body.ommers = vec![]` |
| — | `header.difficulty = 0`, `nonce = 0` | post-merge |
| (call argument) | `header.parent_beacon_block_root` | the Lean block's `parent_root` |
| n/a | `requests_hash`, `slot_number`, `block_access_list_hash` | `None` — V3 predates them |

### Step 4 — Implement `ExecutionEngine`

```rust
#[async_trait::async_trait]
impl ExecutionEngine for EthrexEngine {
    async fn forkchoice_updated_v3(&self, state, attrs) -> Result<ForkChoiceUpdatedResponse, _> {
        // Best-effort: a head whose block isn't imported yet must not fail the update.
        let _ = apply_fork_choice(&self.store, head, safe, finalized).await;

        // No attributes → just a head update.
        let Some(attrs) = attrs else { return Ok(/* VALID, payload_id: None */) };

        // Build mode: create + fill the payload now, cache it under its derived id.
        let args = BuildPayloadArgs { parent: head, timestamp: attrs.timestamp, /* … */ };
        let payload_id = PayloadId(args.id()?.to_be_bytes());
        let block = self.blockchain.build_payload(create_payload(&args, &self.store, extra)?)?.payload;
        self.built_payloads.lock()?.insert(payload_id.0, block_to_payload(block));
        Ok(/* VALID, payload_id: Some(id) */)
    }

    async fn get_payload(&self, id) -> Result<ExecutionPayloadV3, _> {
        self.built_payloads.lock()?.remove(&id.0).ok_or(/* unknown id */)
    }

    async fn new_payload(&self, payload, parent_beacon_block_root) -> Result<PayloadStatus, _> {
        let block = payload_to_block(payload, parent_beacon_block_root)?; // Err → INVALID
        match self.blockchain.add_block(block) {
            Ok(()) => Ok(/* VALID, latest_valid_hash = block hash */),
            Err(e) => Ok(/* INVALID, validation_error = e */),
        }
    }
}
```

Notes:

- **`new_payload` never returns `Err`.** Execution failure is reported as an `INVALID`
  *status*, matching the Engine API contract and the consensus layer's permissive posture.
- **`PayloadId` is not `Hash`**, so the cache keys on its inner `[u8; 8]`.
- `EngineClientError` has no "internal" variant; internal failures map to
  `EngineClientError::Rpc { code: -32000, .. }`.

### Step 5 — Seed the consensus genesis from the embedded EL

**This step is mandatory; skipping it silently disables the EL.**

The Lean genesis block must carry the EL's genesis block hash, in two places
(`State::from_genesis_with_el_hash`): `state.latest_execution_payload_header.block_hash`
and the genesis block body's `execution_payload.block_hash`. Without it the first
`forkchoiceUpdated` points at a parent ethrex has never seen, so the EL refuses to build
and every proposal silently falls back to a synthetic payload.

In `inprocess` mode there is no need to ask the operator for the hash — the embedded
engine bootstraps from `--el-genesis`, so its startup head *is* the EL genesis block:

```rust
// bin/ethlambda/src/main.rs — resolve the EL *before* state init
let (execution_client, execution_genesis_block_hash) = match options.execution_mode {
    ExecutionMode::InProcess => match build_inprocess_engine(options.el_genesis.as_deref()).await {
        Some((engine, el_hash)) => (Some(engine), Some(el_hash)),
        None => (None, None),
    },
    ExecutionMode::External => { /* … --execution-genesis-block-hash … */ }
};

let store = fetch_initial_state(&urls, &genesis_config, backend, execution_genesis_block_hash).await?;
```

`build_inprocess_engine` reads the hash back out of the engine:

```rust
let engine = EthrexEngine::from_genesis_path(path).await.ok()?;
let el_genesis_hash = H256(engine.head_hash().await.ok()?.0);
info!(el_genesis_hash = %el_genesis_hash, "In-process ethrex execution engine enabled");
Some((Arc::new(engine), el_genesis_hash))
```

### Step 6 — CLI wiring

```rust
// bin/ethlambda/src/cli.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub(crate) enum ExecutionMode {
    #[default]
    External,
    /// Spelled `inprocess` on the CLI (clap would otherwise derive `in-process`).
    #[value(name = "inprocess")]
    InProcess,
}

#[arg(long, value_enum, default_value_t = ExecutionMode::External)]
pub(crate) execution_mode: ExecutionMode,
/// Path to the EL genesis JSON for `--execution-mode inprocess`.
#[arg(long)]
pub(crate) el_genesis: Option<PathBuf>,
```

The engine and fee recipient travel to the actor inside `BlockChainConfig`:

```rust
pub struct BlockChainConfig {
    // …
    pub execution_client: Option<Arc<dyn ExecutionEngine>>,
    pub suggested_fee_recipient: [u8; 20],
}
```

Note the explicit `#[value(name = "inprocess")]` — see [Gotcha 3](#gotcha-3-clap-renames-your-enum-variants).

### Step 7 — Hook it into the slot loop

ethlambda builds the *next* slot's block one interval early, at **interval 4** of the
current slot (`SlotInterval::EndOfSlot`). Since the in-process build is a synchronous
library call with no network latency, build the payload inline there:

```rust
// crates/blockchain/src/lib.rs — SlotInterval::EndOfSlot
if let Some(validator_id) = next_proposer {
    let execution_payload = self.build_execution_payload(next_slot).await;
    self.propose_block(next_slot, validator_id, execution_payload).await;
}
```

`build_execution_payload` (`crates/blockchain/src/el_integration.rs`) is a build-mode FCU
immediately followed by `getPayload`:

```rust
pub(crate) async fn build_execution_payload(&self, slot: u64) -> Option<ExecutionPayloadV3> {
    let client = self.execution_client.as_ref()?.clone();
    let attrs = PayloadAttributesV3 {
        timestamp: compute_time_at_slot(genesis_time, slot),
        prev_randao: H256::ZERO,                      // until Lean defines a RANDAO mix
        suggested_fee_recipient: self.suggested_fee_recipient,
        withdrawals: vec![],
        parent_beacon_block_root: self.store.head().unwrap_or_default(),
    };
    let payload_id = client.forkchoice_updated_v3(state, Some(attrs)).await.ok()?.payload_id?;
    client.get_payload(payload_id).await.ok()
}
```

The remaining EL hooks in the same module, all pre-existing from the Engine-API work:

| Hook | When | What |
|---|---|---|
| `notify_execution_layer` | interval 0, each slot | head/safe/finalized FCU (fire-and-forget) |
| `build_execution_payload` | interval 4, if proposing | build the next block's payload |
| `newPayload` on own block | after building | the EL must import its own candidate |
| `import_gossiped_block` | on gossip | `newPayload` gate before the STF sees the block |

Returning `None` anywhere is safe: `build_block` falls back to `synthetic_payload`, so a
node with no EL (or a failing one) still produces STF-valid blocks.

### Step 8 — Test it

Two integration tests in `crates/net/ethrex-engine/tests/roundtrip.rs`:

1. **`builds_executes_and_advances_head`** — inherent API: genesis → `build_block` →
   `import_block` → `set_forkchoice` → canonical head is block 1.
2. **`engine_trait_build_get_new_payload_roundtrip`** — the trait path *through the
   conversion*: `forkchoice_updated_v3(Some(attrs))` → `get_payload` → `new_payload`, and
   assert `PayloadStatusKind::Valid`.

Test 2 is the one that earns its keep: it exercises the conversion in both directions and
is what caught the Prague/`requests_hash` problem.

```bash
cargo test -p ethlambda-ethrex-engine
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

---

## 4. Running a devnet

Every node embeds its own EL, so there are **no separate ethrex containers**.

```bash
# 0. Update the harness FIRST — a stale lean-quickstart causes a cascade of
#    false failures (unknown CLI flags, wrong genesis schema). See Gotcha 4.
cd lean-quickstart && git pull && cd ..
pip3 install pyyaml          # the genesis generator needs it

# 1. Build the node image from this branch
make docker-build DOCKER_TAG=local

# 2. Put a Cancun EL genesis where the container can see it (/config)
cp crates/net/ethrex-engine/tests/fixtures/genesis.json \
   lean-quickstart/local-devnet/genesis/el-genesis.json
```

**3. Point the harness at the local image and enable in-process mode** — in
`lean-quickstart/client-cmds/ethlambda-cmd.sh`, use `ghcr.io/lambdaclass/ethlambda:local`
and add to both the `node_binary` and `node_docker` commands:

```sh
--execution-mode inprocess --el-genesis /config/el-genesis.json \
```

**4. Configure the nodes** in `lean-quickstart/local-devnet/genesis/validator-config.yaml`:
keep only the `ethlambda_*` entries, make **at least one** `isAggregator: true` (without an
aggregator nothing finalizes), and give each an `apiPort` (the harness passes `--api-port`,
and `--network host` shares the host stack so they must differ):

```yaml
  - name: "ethlambda_0"
    enrFields: { ip: "127.0.0.1", quic: 9001 }
    metricsPort: 8081
    apiPort: 15052
    isAggregator: true
    count: 1
```

**5. Regenerate keys and genesis** — the manifest must be *dual-key*
(`attester_key_pubkey_hex` + `proposer_key_pubkey_hex`), which is what makes the generator
emit `attestation_pubkey` / `proposal_pubkey` in `config.yaml`:

```bash
rm -rf lean-quickstart/local-devnet/genesis/hash-sig-keys
cd lean-quickstart && NETWORK_DIR=local-devnet \
  ./spin-node.sh --node all --generateGenesis --forceKeyGen --stop
```

**6. Run** (timeout = 10s startup + 30s genesis offset + 4s/slot; 160s ≈ 30 slots):

```bash
.claude/skills/devnet-runner/scripts/run-devnet-with-timeout.sh 160
```

Logs land in `ethlambda_0.log`, `ethlambda_1.log`, `ethlambda_2.log` at the repo root.

---

## 5. Verifying it works

The EL hooks log at `trace!`, which is invisible at the default INFO level. To see them,
prepend an env var to `node_docker` in `ethlambda-cmd.sh` (it goes before the image name,
which is valid `docker run` syntax):

```sh
node_docker="-e RUST_LOG=info,ethlambda_blockchain::el_integration=trace ghcr.io/…:local \
```

Then check the ladder, cheapest first:

```bash
# 1. Did the in-process EL come up? (expect one line per node, identical hash)
grep -h "In-process ethrex execution engine enabled" ethlambda_*.log

# 2. Is consensus advancing / finalizing?
grep -c "Block imported" ethlambda_1.log
grep -h "Checkpoint finalized" ethlambda_1.log | tail -1

# 3. Is the EL building and EXECUTING payloads?  (needs the trace filter above)
grep -hc "Built execution payload" ethlambda_*.log
grep -h  "newPayload ok" ethlambda_*.log | tail   # want: status=Valid

# 4. Red flags — all of these must be ZERO
grep -hc "falling back to synthetic\|getPayload failed\|rejected payload" ethlambda_*.log
grep -hc "ERROR\|panicked" ethlambda_*.log
```

`status=Valid` on `newPayload` is the load-bearing signal: it is ethrex's own verdict
*after executing* the payload against its state, not an acknowledgement of receipt.

Reference result from the verified run (3 nodes, 30-slot window):

| Signal | Observed |
|---|---|
| In-process EL enabled | 3/3 nodes, identical EL genesis hash |
| Chain progress | 32 slots, finalized at slot 29 |
| Payloads built per node | 6–7 |
| Payloads executed per node | 11–13, all `status=Valid` |
| FCUs accepted per node | 14–15 |
| Synthetic fallbacks / INVALID / errors | 0 / 0 / 0 |

---

## 6. Gotchas

### Gotcha 1: two ethrex versions will not link

`ethrex-crypto` bundles a C SHA3 implementation whose symbols (`SHA3_absorb`,
`SHA3_squeeze`, …) are not namespaced. Two ethrex versions in the dependency graph means
two copies, and GNU `ld` fails with `multiple definition of 'SHA3_absorb'`.

**macOS `ld64` tolerates it.** So local dev builds, `cargo test`, and a macOS release all
pass while the Linux/Docker release build fails. Unify every ethrex crate on one rev
(Step 1), and de-risk by linking the real binary on the deployment platform.

### Gotcha 2: the EL genesis must be Cancun, not Prague

`ExecutionPayloadV3` is the Cancun shape. A Prague EL genesis (`pragueTime` set) makes
ethrex require a `requests_hash` in the header that a V3 payload cannot carry, so
`new_payload` rejects every block:

```
Invalid Block: Invalid Header, validation failed pre-execution: Requests hash is not present
```

Use a genesis with `cancunTime: 0` and **no** `pragueTime` (and drop the `prague` entry
from `blobSchedule`). Supporting Prague means moving to `ExecutionPayloadV4` + a
`requests_hash`, which is future work.

### Gotcha 3: clap renames your enum variants

`clap::ValueEnum` derives kebab-case value names, so `InProcess` becomes `in-process` —
which silently disagrees with every doc that says `inprocess`. Pin it:
`#[value(name = "inprocess")]`.

### Gotcha 4: a stale devnet harness looks like broken code

An out-of-date `lean-quickstart` produced four consecutive *false* failures — unknown
`--custom-network-config-dir`, unknown `--metrics-address`, single-key
`GENESIS_VALIDATORS`, and a missing `apiPort`. All were harness drift, not integration
bugs. `git pull` the harness before debugging your change.

### Gotcha 5: silence is not failure

The EL hooks log at `trace!`. At INFO, a perfectly healthy in-process run prints nothing
about payload builds — indistinguishable from an EL that never ran. The dependable
INFO-level signal is the *inverse*: fallback and failure paths log at `warn!`, so silence
there means the EL path succeeded. For positive proof, raise the log filter (Section 5).

---

## 7. Design decisions

**Reuse the `ExecutionEngine` trait rather than a parallel abstraction.**
The Engine-API work had already isolated the EL behind three async methods, so the
in-process engine is a second implementation and the actor is untouched. Both modes share
every call site, which keeps them from drifting.

**Build the payload synchronously at interval 4 ("Option A").**
The out-of-process design requests a payload one interval early and fetches it later,
because a networked EL needs time to build; that requires stashing a `payload_id` across
intervals plus stale-head bookkeeping. In-process there is no latency, so the build is
inline at interval 4 and `pending_payload_id`, `request_payload_id_for_next_slot` and
`take_prepared_payload` were dropped. Fewer moving parts, no cross-interval state.

**Reimplement the payload↔block conversion instead of depending on `ethrex-rpc`.**
The mapping is ~40 lines of field copying; `ethrex-rpc` is an Axum server plus the p2p
stack with no way to take only its types. Copying the mapping is far cheaper than the
dependency.

**In-memory EL store.**
Simplest thing that proves the integration; the EL state resets on restart. Enabling
ethrex-storage's `rocksdb` feature is the path to persistence, and pairs with EL-aware
checkpoint sync — both out of scope here.

**`new_payload` reports INVALID rather than erroring.**
Consensus must keep running regardless of EL state. Transport/internal failures are
permissive (block still imported, warning logged); only an explicit INVALID verdict drops
a block. Same policy as the Engine-API path.

**Derive the EL genesis hash instead of asking for it.**
The external path needs `--execution-genesis-block-hash` because the EL is a separate
process. In-process, the engine *is* the source of truth, so the hash is read from it —
removing a manual step whose omission fails silently.

---

## 8. References

- **PR #530** — this integration. Commits, in order: dependency scaffold → engine core →
  merge of #367 → trait impl + CLI → genesis seeding → ethrex unification → merge main →
  CLI value-name fix.
- **PR #367** — the out-of-process Engine-API integration this builds on
  (`docs/plans/engine-api-integration.md`).
- `docs/plans/ethrex-inprocess-poc.md` — the original plan and phase breakdown.
- ethrex: <https://github.com/lambdaclass/ethrex> (pinned rev `de9b249b`)
  - `crates/blockchain/{blockchain,payload,fork_choice}.rs` — the driving APIs
  - `crates/networking/rpc/types/payload.rs` — the reference conversion
- execution-apis (payload/FCU shapes): <https://github.com/ethereum/execution-apis>
- `.claude/skills/devnet-runner/SKILL.md` — devnet workflows.
