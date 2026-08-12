# Embedding ethrex as the execution layer

ethlambda runs its execution layer **in-process**: ethrex is linked in as a
library and driven by direct function calls. One binary, no Engine API, no
JSON-RPC, no JWT.

This is a working reference — the steps, the exact ethrex APIs used, the design
decisions and why, how to run a devnet, and how to prove the embedded EL is
actually doing the work.

- [1. How it fits together](#1-how-it-fits-together)
- [2. Prerequisites](#2-prerequisites)
- [3. Step-by-step](#3-step-by-step)
- [4. Running a devnet](#4-running-a-devnet)
- [5. Verifying it works](#5-verifying-it-works)
- [6. Gotchas](#6-gotchas)
- [7. Design decisions](#7-design-decisions)
- [8. References](#8-references)

---

## 1. How it fits together

A Lean Ethereum node is two layers: **consensus** (ethlambda — ordering, fork
choice, attestations) and **execution** (ethrex — running transactions,
computing state). They interact every slot.

```
┌──────────────────────────────────────────┐
│ ethlambda process                        │
│   consensus layer                        │
│        │  direct function calls          │
│   ethrex, embedded                       │
│   (ethrex-blockchain / -storage / -common)│
└──────────────────────────────────────────┘
```

Three things cross the boundary, and that is the entire execution-layer surface:

| Operation | When | ethrex call |
|---|---|---|
| `build_payload` | interval 4, when this node proposes next | `create_payload` + `Blockchain::build_payload` |
| `execute_payload` | on every block that arrives, and on our own | `Blockchain::add_block` |
| `set_head` | once per slot, at interval 0 | `apply_fork_choice` |

The payload itself travels **inside the Lean block**: the proposer embeds an
`ExecutionPayloadV3` in the block body, and every peer executes it in its own
embedded ethrex. That is why the execution-payload schema lives in the consensus
types and the state transition, not in the engine crate.

## 2. Prerequisites

- Rust per `rust-toolchain.toml`.
- Docker, for the node image used by the devnet.
- A **Cancun** execution-layer genesis JSON (see [gotcha 2](#gotcha-2-the-el-genesis-must-be-cancun-not-prague)).
- An ethrex checkout is handy for reading APIs, but is not a build requirement —
  ethrex is consumed as a pinned git dependency.

## 3. Step-by-step

### Step 1 — Depend on ethrex

Three crates, pinned to one revision in `[workspace.dependencies]`:

```toml
ethrex-common     = { git = "https://github.com/lambdaclass/ethrex", rev = "…" }
ethrex-storage    = { git = "https://github.com/lambdaclass/ethrex", rev = "…" }
ethrex-blockchain = { git = "https://github.com/lambdaclass/ethrex", rev = "…" }
```

> **Every ethrex crate in the workspace must share that revision.** `ethrex-crypto`
> bundles a C SHA3 whose symbols are not namespaced, so two ethrex versions in the
> graph produce `multiple definition of 'SHA3_absorb'` at link time under GNU `ld`.
> Audit for *pre-existing* ethrex dependencies — ours were hiding in the p2p crate
> for ENR parsing. See [gotcha 1](#gotcha-1-two-ethrex-versions-will-not-link).

> **Do not depend on `ethrex-rpc`.** It has a ready-made payload↔block conversion,
> but unconditionally pulls in a full Axum server *and* `ethrex-p2p`, with no
> feature to slim it down. Step 3 reimplements the ~40-line mapping instead.

Verify one ethrex in the graph, and let plain `cargo build` reconcile the
lockfile (`cargo update` can drag transitive crates past the pinned toolchain):

```bash
grep -A2 'name = "ethrex-crypto"' Cargo.lock | grep -E 'version|rev=' | sort -u
```

### Step 2 — Bootstrap the engine

`crates/net/ethrex-engine` wraps an ethrex `Store` + `Blockchain`:

```rust
pub async fn from_genesis(genesis: Genesis) -> Result<Self, EngineError> {
    let mut store = Store::new("", EngineType::InMemory)?;
    store.add_initial_state(genesis).await?;          // async
    let blockchain = Arc::new(Blockchain::default_with_store(store.clone()));
    // …
}
```

The ethrex APIs used, all public library calls:

| Purpose | API | Shape |
|---|---|---|
| Store | `Store::new(path, EngineType::InMemory)` | sync |
| Seed genesis | `store.add_initial_state(genesis)` | **async** |
| Engine | `Blockchain::default_with_store(store)` | sync |
| Head hash / number | `store.get_latest_canonical_block_hash()`, `get_latest_block_number()` | async |
| Payload skeleton | `create_payload(&args, &store, extra_data)` | 3 args → `Block` |
| Fill the payload | `blockchain.build_payload(block)` | **sync**, by value |
| Execute + persist | `blockchain.add_block(block)` | sync, by value |
| Fork choice | `apply_fork_choice(&store, head, safe, finalized)` | **async**, 3×H256 |

### Step 3 — Convert payload ⇄ block

`conversion.rs` maps between ethlambda's `ExecutionPayloadV3` and ethrex's
`Block`, mirroring ethrex-rpc's own `into_block`/`from_block` but against
`ethrex-common`. Most fields copy across; these do not:

| Field | Handling |
|---|---|
| transactions | opaque SSZ bytes ⇄ typed txs via `Transaction::decode_canonical` / `encode_canonical_to_vec` |
| transactions_root, withdrawals_root | not in the payload — recompute with `compute_*_root(.., &NativeCrypto)` |
| base_fee_per_gas | `[u8; 32]` big-endian ⇄ ethrex `Option<u64>` (low 8 bytes) |
| logs_bloom | `[u8; 256]` ⇄ `Bloom` |
| fee_recipient | `[u8; 20]` ⇄ `Address` → header `coinbase` |
| ommers / difficulty / nonce | constants: `*DEFAULT_OMMERS_HASH`, empty, 0, 0 (post-merge) |
| parent_beacon_block_root | supplied by the caller — the Lean block's `parent_root` |
| requests_hash & friends | `None` — V3 predates them (gotcha 2) |

### Step 4 — The engine API

Deliberately *not* Engine-API shaped. Running in-process removes the reasons that
protocol is a stateless two-step exchange, so a payload is built and returned in
one call — no payload id, no server-side cache:

```rust
pub async fn build_payload(&self, timestamp, prev_randao, beacon_root, fee_recipient)
    -> Result<ExecutionPayloadV3, EngineError>;
pub fn execute_payload(&self, payload: &ExecutionPayloadV3, parent_beacon_block_root: H256)
    -> Result<(), EngineError>;
pub async fn set_head(&self, head: H256, safe: H256, finalized: H256)
    -> Result<(), EngineError>;
```

Consensus types cross the boundary (`ExecutionPayloadV3`, ethlambda's `H256`);
ethrex's own types stay behind it.

### Step 5 — Seed the consensus genesis

**Skip this and the execution layer is silently inert.**

The Lean genesis block must carry the EL's genesis block hash, in the state's
cached header *and* in the genesis block body (`State::from_genesis_with_el_hash`
owns that protocol). Without it the first head update names a parent ethrex has
never seen, the EL declines to build, and every proposal quietly falls back to a
synthetic payload — consensus looks healthy while the EL does nothing.

There is no flag for the hash: the engine bootstraps from `--el-genesis`, so its
startup head *is* the EL genesis block. Build the engine before state init and
read it back out:

```rust
let engine = EthrexEngine::from_genesis_path(path).await?;
let el_genesis_hash = engine.head_hash().await?;      // ← seeds the CL genesis
let store = fetch_initial_state(&urls, &cfg, backend, Some(el_genesis_hash)).await?;
```

### Step 6 — Wire it into the slot loop

ethlambda assembles the *next* slot's block one interval early, at interval 4.
Because the embedded build is synchronous with no network latency, the payload is
built right there, inline:

```rust
// SlotInterval::EndOfSlot
if let Some(validator_id) = next_proposer {
    let execution_payload = self.build_execution_payload(next_slot).await;
    self.propose_block(next_slot, validator_id, execution_payload).await;
}
```

The four hooks, all in `crates/blockchain/src/el_integration.rs`:

| Hook | When |
|---|---|
| `notify_execution_layer` → `set_head` | interval 0, every slot (fire-and-forget) |
| `build_execution_payload` → `build_payload` | interval 4, only when proposing next |
| execute our own block's payload | after building — nobody gossips it back to us |
| `import_gossiped_block` → `execute_payload` | on arriving blocks, before the store sees them |

Returning `None`/failing anywhere is safe: `build_block` falls back to
`synthetic_payload`, so a node with no EL — or a failing one — still produces
valid blocks. Consensus is never stalled by the execution layer.

### Step 7 — CLI

One flag. `--el-genesis <path>` enables the embedded EL; omitting it runs
ethlambda as a consensus-only node.

### Step 8 — Tests

`crates/net/ethrex-engine/tests/roundtrip.rs`:

1. **`builds_executes_and_advances_head`** — build → execute → `set_head`, and the
   EL's head advances to block 1. Exercises the conversion in both directions with
   the EL judging its own output.
2. **`rejects_payload_with_mismatched_beacon_root`** — replaying a payload under a
   different beacon root is rejected, since the root is committed to in the block
   hash.

Test 1 is what caught the Cancun/Prague problem before any devnet ran.

```bash
cargo test -p ethlambda-ethrex-engine
cargo clippy --workspace --all-targets -- -D warnings
```

## 4. Running a devnet

`scripts/inprocess-devnet/run.sh` spins up an N-node devnet where every node
embeds its own ethrex — no separate EL containers. It is self-contained: it
generates the validator keys, consensus genesis, ENRs and node keys itself, so it
needs only `docker` and `yq`.

```bash
./scripts/inprocess-devnet/run.sh --build              # 3 nodes, 20 slots
./scripts/inprocess-devnet/run.sh --nodes 1 --slots 10 # single node
./scripts/inprocess-devnet/run.sh --trace --keep       # EL trace logs, stay up
```

See `scripts/inprocess-devnet/README.md` for the flags and the checks it runs.

## 5. Verifying it works

The EL hooks log at `trace!`, so a healthy run prints nothing about payload
builds at the default INFO level. Use `--trace` (which sets
`RUST_LOG=info,ethlambda_blockchain=trace`), then:

```bash
# 1. did the embedded EL come up? (one line per node, identical hash)
grep -h "Embedded ethrex enabled" ethlambda_*.log

# 2. is consensus advancing and finalizing?
grep -c "Block imported" ethlambda_1.log
grep -h "Checkpoint finalized" ethlambda_1.log | tail -1

# 3. is the EL building and executing? (needs --trace)
grep -hc "Built execution payload" ethlambda_*.log
grep -hc "EL executed payload"     ethlambda_*.log

# 4. red flags — all must be ZERO
grep -hc "using synthetic payload\|EL rejected payload" ethlambda_*.log
```

The load-bearing signal is that the EL **accepted** the payloads: that is its own
verdict after executing them against its state, not an acknowledgement of
receipt. Combined with zero synthetic fallbacks it means the embedded execution
layer really did the work.

## 6. Gotchas

### Gotcha 1: two ethrex versions will not link

`ethrex-crypto` bundles a C SHA3 implementation whose symbols (`SHA3_absorb`,
`SHA3_squeeze`, …) are not namespaced. Two ethrex versions means two copies, and
GNU `ld` fails with `multiple definition`. **macOS `ld64` tolerates it**, so local
dev builds and `cargo test` pass while the Linux/Docker release build fails.
Unify every ethrex crate on one rev, and de-risk by linking the real binary on the
deployment platform.

### Gotcha 2: the EL genesis must be Cancun, not Prague

`ExecutionPayloadV3` is the Cancun shape. A Prague genesis (`pragueTime` set)
makes ethrex require a `requests_hash` in the header that a V3 payload cannot
carry, so execution rejects every block:

```
Invalid Block: Invalid Header, validation failed pre-execution: Requests hash is not present
```

Use `cancunTime: 0` with no `pragueTime`, and drop `prague` from `blobSchedule`.
Prague support means moving to `ExecutionPayloadV4` plus a `requests_hash`.

### Gotcha 3: silence is not failure

The EL hooks log at `trace!`. At INFO a perfectly healthy run prints nothing about
payload builds — indistinguishable from an EL that never ran. The dependable
INFO-level signal is the inverse: fallback and failure paths log at `warn!`, so
silence *there* means success. For positive proof, raise the log filter (§5).

### Gotcha 4: a stale devnet harness looks like broken code

An out-of-date test harness can produce a cascade of failures that look like bugs
in your change — unknown CLI flags, a genesis schema mismatch, missing config
fields. Update the harness first. This is why `scripts/inprocess-devnet/run.sh`
owns its inputs end to end.

### Gotcha 5: an EL-enabled node cannot be restarted

The EL store is in-memory while the consensus store is RocksDB, so the two do not
restart together. A node that comes back resumes consensus at its old slot with an
execution layer rewound to genesis, and since block import is gated on EL
execution, every gossiped block fails with `ParentNotFound` and is dropped —
**the node never syncs again.** Checkpoint sync does not help: it moves the
consensus head, which only widens the gap.

The practical consequence is that the usual "stop, wipe, checkpoint-sync" restart
recipe does not apply to an EL-enabled node. Treat a restart as requiring a full
devnet reset until the store is persisted.

Two ways out, neither implemented yet: persist the EL store alongside the
consensus one, or replay payloads at startup. The second is appealing because the
Lean chain already *contains* every `ExecutionPayloadV3`, so executing them in
canonical order from EL genesis is a complete EL sync with no new wire protocol.

### Gotcha 6: blob transactions execute, but blob data is not available

Blob (EIP-4844) transactions can be submitted and are included and executed
normally. What does **not** happen is data availability, and the distinction
matters before anyone builds on it.

A peer executes a blob-bearing block without ever seeing the sidecar, by design:
block validation derives blob gas and blob count from `blob_versioned_hashes`
alone, and every KZG check lives on the mempool-insertion path, not the import
path. That is what makes blob transactions safe to include at all — if peers
needed the sidecar to validate, one blob transaction would fork the network.
`peer_executes_a_blob_block_without_ever_seeing_the_sidecar` pins this down.

The flip side is that nothing retains the blobs. `ExecutionPayloadV3` has no
sidecar field, so the sidecar never crosses the Lean network; it exists only in
the mempools that happened to receive the transaction, and mempool eviction on
import (gotcha: that eviction is required, see §7) discards those. `BLOBHASH` and
the point-evaluation precompile still work, because they need only the versioned
hashes and caller-supplied data, so nothing inside the EVM notices.

In short: **blob transactions execute; blob data is not retained or gossiped by
the Lean layer.** Treat blob support as exercising the fee market and the
execution path, not as a data-availability layer.

One encoding constraint: the EL genesis is Cancun, so the wrapper version must be
**0** (one KZG proof per blob). Version 1 — cell proofs, EIP-7594, an Osaka
encoding — is rejected. Current tooling often emits version 1 by default, so a
transaction built by an up-to-date library may need to be told otherwise.

## 7. Design decisions

| Decision | Rationale |
|---|---|
| A direct three-method API, not an Engine-API-shaped trait | With one implementation, the payload id, the payload cache and the build-then-fetch two-step are pure overhead — they exist only because the Engine API is stateless and networked. |
| Build the payload at interval 4, in one call | No latency to hide in-process, so there is nothing to pre-request or stash across intervals, and no stale-head bookkeeping. The fill itself runs on `spawn_blocking` — it is a full EVM execution plus merkleization, and the caller is the consensus actor. |
| Verify the payload's claimed `block_hash` on execution | Every other header field is rebuilt from the payload, so the hash is the only thing tying claim to contents. Accepting a mismatch would let each node's EL store a different block under a hash consensus already committed to. |
| Evict included transactions from the mempool on import | ethrex does this from its Engine-API fork-choice handler, which the in-process path bypasses. Without it the builder re-fetches the stale copy and drops the sender's whole queue, so each account could send only one transaction. |
| A failed build emits a pass-through payload, not a zero one | The STF caches whatever `block_hash` a payload claims, so a zero would move the network's expected EL parent to a block nobody has — permanently, since every later build would then fail the same way. |
| Reimplement the payload↔block conversion | ~40 lines of field mapping versus pulling in an Axum server and the p2p stack. |
| In-memory EL store | Simplest thing that proves the integration, at the cost of a node that cannot be restarted (gotcha 5). Persistence is an `ethrex-storage` feature away and pairs with EL-aware checkpoint sync. |
| Execution failure drops the block, never stalls consensus | An unexecutable payload means the block is pointless to import; anything else (no EL, internal error) is permissive and logged. |
| Derive the EL genesis hash instead of configuring it | The engine is the source of truth in-process, and the failure mode of forgetting it is silent. |
| No fee-recipient config | Lean has no fee market or block rewards yet, so there is nothing to direct. Add it when that changes. |

## 8. References

- ethrex: <https://github.com/lambdaclass/ethrex>
  - `crates/blockchain/{blockchain,payload,fork_choice}.rs` — the driving APIs
  - `crates/networking/rpc/types/payload.rs` — the reference conversion
- execution-apis (payload shapes): <https://github.com/ethereum/execution-apis>
- `scripts/inprocess-devnet/README.md` — the standalone devnet runner
- `docs/plans/ethrex-inprocess-poc.md` — the original plan and phase breakdown
