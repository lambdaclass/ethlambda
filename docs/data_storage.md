# 💾 Storage: What Lives Where

This doc explains how ethlambda saves data. Especially,
the split between the fork choice `Store` and the `StorageBackend` trait,
what each of the seven tables holds, and which data is in-memory only.

## Overview

All chain data flows through a single high-level type, the **`Store`**
(`crates/storage/src/store.rs`), which persists it through a small pluggable
key-value abstraction, the **`StorageBackend`** trait
(`crates/storage/src/api/traits.rs`). Two backends implement the trait:
[**RocksDB**](https://rocksdb.org/) for production and an **in-memory** backend for tests.
Everything persisted is SSZ-encoded bytes.

```text
                        LAYERED ARCHITECTURE
                        ────────────────────

   ┌──────────────────┐          ┌──────────────────┐
   │ BlockChain actor │          │    P2P actor     │
   └────────┬─────────┘          └────────┬─────────┘
            │      (cloned Store: shared  │
            │       backend + buffers)    │
            ▼                             ▼
   ┌─────────────────────────────────────────────────┐
   │                     Store                       │
   │        crates/storage/src/store.rs              │
   │                                                 │
   │  • table selection, key encoding, SSZ codec     │
   │  • snapshot-vs-diff decisions, pruning          │
   │  • in-memory attestation buffers + state cache  │
   └────────────────────────┬────────────────────────┘
                            │ begin_read() / begin_write()
                            ▼
   ┌─────────────────────────────────────────────────┐
   │              StorageBackend trait               │
   │        crates/storage/src/api/traits.rs         │
   │                                                 │
   │        raw bytes in, raw bytes out              │
   └───────────┬─────────────────────────┬───────────┘
               │ (production)            │ (test)
               ▼                         ▼
   ┌───────────────────────┐   ┌───────────────────────┐
   │    RocksDBBackend     │   │    InMemoryBackend    │
   │  (production, one     │   │  (tests, HashMap per  │
   │   column family per   │   │   table, lost on      │
   │   table)              │   │   drop)               │
   └───────────────────────┘   └───────────────────────┘
```

## The Store / StorageBackend Split

### StorageBackend: dumb bytes

The `StorageBackend` trait knows nothing about consensus types. It moves raw
bytes in and out of named tables:

- `begin_read()` returns a `StorageReadView` with `get(table, key)` and
  `prefix_iterator(table, prefix)`.
- `begin_write()` returns a `StorageWriteBatch` with `put_batch`,
  `delete_batch`, and `commit()`. A batch stages puts and deletes across
  **multiple tables** and applies them **atomically** on commit.

The two implementations live in `crates/storage/src/backend/`:

| Backend           | Details                                                                                                                                                                                                                       |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RocksDBBackend`  | One column family per table. Writes go through a native `WriteBatch` with `sync=false` (no fsync per commit).                                                                                                                 |
| `InMemoryBackend` | A `HashMap` per table behind an `RwLock`. Its `prefix_iterator` sorts keys lexicographically to match RocksDB's iteration order, because pruning relies on slot-ordered early-stop scans (see [Key encoding](#key-encoding)). |

### Store: all the semantics

The `Store` owns everything the backend doesn't: which table each datum goes
to, how keys are built, SSZ encoding/decoding, when to write a full state
snapshot versus a diff, and when to prune. It is the **only** writer to the
backend.

A naming subtlety: the `Store` _struct_ lives in the storage crate
(`crates/storage/src/store.rs`), while the fork choice _logic_ that drives it
(`on_block`, `on_tick`, `update_head`, ...) lives in
`crates/blockchain/src/store.rs` as free functions taking `&mut Store`.

`Store` is `Clone`, and every field is an `Arc`, so clones are cheap and all
clones share the same backend and the same in-memory pools. At startup
(`bin/ethlambda/src/main.rs`) one `Arc<RocksDBBackend>` is opened, one `Store`
is built from it, and clones are handed to the BlockChain and P2P actors.

```text
                        INSIDE THE STORE
                        ────────────────

   ┌──────────────────────────── Store ────────────────────────────┐
   │                                                               │
   │   PERSISTED (via backend)         IN-MEMORY ONLY              │
   │   ──────────────────────          ──────────────────────      │
   │   ┌─────────────────────┐         ┌──────────────────────┐    │
   │   │ BlockHeaders        │         │ new_payloads         │    │
   │   │ BlockBodies         │         │  (pending aggregated │    │
   │   │ BlockSignatures     │         │   attestations)      │    │
   │   │ States              │         │ known_payloads       │    │
   │   │ StateDiffs          │         │  (fork-choice-active │    │
   │   │ Metadata            │         │   attestations)      │    │
   │   │ LiveChain           │         │ gossip_signatures    │    │
   │   └─────────────────────┘         │  (raw XMSS sigs      │    │
   │                                   │   awaiting           │    │
   │   Survives restarts.              │   aggregation)       │    │
   │                                   │ state_cache (LRU)    │    │
   │                                   └──────────────────────┘    │
   │                                                               │
   │                                   Lost on restart.            │
   └───────────────────────────────────────────────────────────────┘
```

## The Tables

The seven variants of the `Table` enum (`crates/storage/src/api/tables.rs`):

| Table             | Key         | Value                                     | Pruned?                          |
| ----------------- | ----------- | ----------------------------------------- | -------------------------------- |
| `BlockHeaders`    | root        | `BlockHeader`                             | never                            |
| `BlockBodies`     | root        | `BlockBody`                               | never                            |
| `BlockSignatures` | slot ‖ root | aggregate proof (`MultiMessageAggregate`) | yes: finalized older than ~1 day |
| `States`          | root        | full `State` snapshot                     | never                            |
| `StateDiffs`      | root        | `StateDiff`                               | never                            |
| `Metadata`        | string      | SSZ scalars                               | never                            |
| `LiveChain`       | slot ‖ root | `parent_root`                             | yes: below finalized             |

### Key encoding

Two key layouts are used:

- **Root-keyed** tables use the 32-byte SSZ encoding of the block root
  (`root.to_ssz()`).
- **Slot-prefixed** tables (`BlockSignatures`, `LiveChain`) use
  `encode_slot_root_key`: an 8-byte **big-endian** slot followed by the
  32-byte root. Big-endian means lexicographic key order equals numeric slot
  order, so pruning can iterate from the start of the table and stop at the
  first key past its cutoff instead of scanning everything.

### BlockHeaders

`root → BlockHeader`. Written for every block, including the genesis/anchor
block, and never pruned: headers are the permanent record of the chain.
Headers are also read back during state reconstruction (see
[State Storage](#state-storage-snapshots--diffs)).

### BlockBodies

`root → BlockBody`. Written for every block **except** those with an empty
body: if `header.body_root == EMPTY_BODY_ROOT` (the hash tree root of
`BlockBody::default()`), nothing is stored and reads synthesize
`BlockBody::default()`. This covers the genesis block and checkpoint sync
anchors, whose bodies are either empty or unavailable. Never pruned.

### BlockSignatures

`slot ‖ root → MultiMessageAggregate`. Despite the name, this table stores the
block's **merged aggregate proof blob**, not individual signatures — the name
is historical and kept to avoid a RocksDB column-family migration (renaming to
`BlockProof` is a follow-up). It is keyed by `slot ‖ root` (not plain root)
precisely so that pruning can scan in slot order and stop early.

Stored separately from headers/bodies because the genesis block has no proof.
`get_signed_block` synthesizes an empty proof for the slot-0 anchor only; for
any other block a missing entry (a pruned finalized block) surfaces as `None`
rather than a fabricated block.

This is the one block table that **is** pruned; see [Pruning](#pruning).

### States

`root → State` (full SSZ snapshot). Holds full-state snapshots **only**: the
bootstrap anchor written at initialization, plus one anchor whenever a block
crosses a 1024-slot boundary. Never pruned — these anchors are the base every
diff chain resolves against, so reconstruction always terminates.

### StateDiffs

`root → StateDiff`. A parent-linked diff written for **every** non-genesis
state. Never pruned, so together with the snapshots this preserves the full
state history. See [State Storage](#state-storage-snapshots--diffs) for what a
diff contains and how states are rebuilt.

### Metadata

String keys mapping to SSZ-encoded scalars — the `Store`'s own persistent
fields:

| Key                | Type          | Meaning                                                |
| ------------------ | ------------- | ------------------------------------------------------ |
| `time`             | `u64`         | Intervals elapsed since genesis (the store clock)      |
| `config`           | `ChainConfig` | Chain configuration (genesis time, validator count)    |
| `head`             | `H256`        | Current fork choice head                               |
| `safe_target`      | `H256`        | Current safe target (see [lmd_ghost.md](lmd_ghost.md)) |
| `latest_justified` | `Checkpoint`  | Latest justified checkpoint                            |
| `latest_finalized` | `Checkpoint`  | Latest finalized checkpoint                            |

### LiveChain

`slot ‖ root → parent_root`. A pure **index** for fork choice: it lets
`get_live_chain()` build the `root → (slot, parent_root)` block tree without
deserializing a single block. It contains the finalized anchor plus all
non-finalized blocks, and is pruned as finalization advances (the finalized
block itself is kept).

Presence in `LiveChain` is what makes a block _visible to fork choice_:
`insert_pending_block` deliberately writes a block's header/body/proof
**without** a `LiveChain` entry, persisting the heavy proof data (~3 KB+)
while the block waits for its parent. When the block is later processed,
`insert_signed_block` overwrites the same keys (idempotent) and adds the
`LiveChain` entry.

## State Storage: Snapshots + Diffs

Storing a full `State` per block would be wasteful: most fields never change
or change predictably. Instead, `insert_state` writes:

1. **Always** a `StateDiff` keyed by the block root, linked to its parent via
   `base_root` (the block's `parent_root`).
2. **Only at anchors** a full snapshot into `States`. A block is an anchor
   when it crosses a `SNAPSHOT_ANCHOR_INTERVAL = 1024` slot boundary relative
   to its parent (~68 minutes at 4-second slots). This bounds any
   reconstruction walk to at most 1024 diff applications.

A `StateDiff` stores only what cannot be recovered elsewhere: the target slot,
justified/finalized checkpoints, and the justification fields
(`justified_slots`, `justifications_roots`, `justifications_validators`,
stored in full — they are bounded by the non-finalized window, so they stay
small under healthy finality). The rest is deliberately omitted:

| Omitted field             | Recovered from                                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config`, `validators`    | The snapshot (they never change)                                                                                                                              |
| `latest_block_header`     | The `BlockHeaders` table                                                                                                                                      |
| `historical_block_hashes` | Regenerated from `base_root` + the slot gap (the state transition appends the parent root plus one zero per skipped slot, so the append is fully predictable) |

Reads go through `get_state`, which tries three levels:

1. An in-memory LRU cache (`STATE_CACHE_CAPACITY = 32` states, keyed by block
   root). States are content-addressed and immutable, so the cache never
   needs invalidation. The common case — reading the parent state right
   after importing its block — is a cache hit.
2. A full snapshot in `States`.
3. Reconstruction: walk `base_root` pointers back through `StateDiffs` until
   a snapshot is found, then replay the diffs forward.

```text
                    STATE RECONSTRUCTION
                    ────────────────────

   get_state(D): not in the cache and no snapshot → rebuild in two passes.

   Pass 1: walk backward from D, following each diff's base_root pointer
           and collecting diffs, until a block with a snapshot is found:

   ┌────────┐  base=C   ┌────────┐  base=B   ┌────────┐  base=A   ┌──────────┐
   │ diff D │ ───────▶  │ diff C │ ───────▶  │ diff B │ ───────▶  │ snapshot │
   └────────┘           └────────┘           └────────┘           │   at A   │
    (target)           (StateDiffs table)                         └──────────┘
                                                                 (States table)

   Pass 2: starting from the snapshot, apply the diffs oldest-first:

   state A ──apply B──▶ state B ──apply C──▶ state C ──apply D──▶ state D ✓

   The rebuilt state D gets its latest_block_header from the BlockHeaders
   table and is memoized in the LRU cache before being returned.
```

If the diff chain is broken or the target's header is missing, `get_state`
returns `None` rather than a partial state.

## Write Paths: What a Block Import Persists

Block import (`on_block` in `crates/blockchain/src/store.rs`) commits a
sequence of independent write batches:

```text
                 BLOCK IMPORT WRITE SEQUENCE
                 ───────────────────────────

  on_block(signed_block)
   │
   ├─ 1. update_checkpoints()          Metadata: head,
   │      (only if the post-state      latest_justified
   │       justified a higher slot)    (+ triggers pruning)
   │
   ├─ 2. insert_signed_block()  ┐            BlockHeaders[root]
   │                            │            BlockBodies[root]    (if non-empty)
   │                            ├─one batch─ BlockSignatures[slot‖root]
   │                            │            LiveChain[slot‖root]
   │                            ┘
   │
   ├─ 3. insert_state()         ┐            StateDiffs[root]
   │                            ├─one batch─ States[root]         (anchors only)
   │                            ┘            (+ LRU cache insert)
   │
   └─ 4. update_head()                 Metadata: head
          (re-runs fork choice)        (+ justified/finalized if advanced,
                                          + pruning on finalization)
```

Each numbered step is atomic on its own, but the import as a whole is **not**
one transaction. The commit order keeps the on-disk store consistent after any
prefix of these steps: the justified checkpoint written in step 1 always names
an already-persisted **ancestor** of the imported block (the state transition
only counts attestations whose roots match the state's own
`historical_block_hashes`, and every ancestor was fully persisted when it was
imported), and the head only advances in step 4, after the block and state are
durable. A crash mid-import can therefore lose the tail of the import — e.g. a
persisted block and state the head does not point to yet — but never leave
metadata referencing missing data. Re-importing the block is idempotent (a
duplicate is skipped via `has_state`).

## Pruning

Pruning is driven by finalization and splits into a cheap immediate phase and
a deferred heavy phase.

**Immediately, when finalization advances** (inside `update_checkpoints`):

- `prune_live_chain`: deletes `LiveChain` entries below the finalized slot,
  keeping the finalized block itself. This keeps the fork choice working set
  bounded to the non-finalized chain.
- `prune_gossip_signatures`: drops buffered in-memory gossip signatures at or
  below the finalized slot.
- `prune_stale_aggregated_payloads`: drops in-memory aggregated payloads
  (both pending and known) whose target slot is at or below the finalized
  slot.

**Deferred** (`prune_old_data`, called after a batch of blocks has been
processed):

- `prune_old_block_signatures`: deletes `BlockSignatures` entries below
  `cutoff = tip_slot − SIGNATURE_PRUNING_RANGE` (21,600 slots, ~1 day at
  4-second slots) — but **only** when `cutoff ≤ finalized_slot`, i.e. the
  entire pruned range lies within finalized history. Non-finalized proofs
  are never touched. Finalized blocks can never revert, so their proofs are
  not needed for fork choice, reorg safety, or re-aggregation once outside
  the window.

**Never pruned:** `BlockHeaders`, `BlockBodies`, `States`, `StateDiffs`, and
`Metadata`. Headers, bodies, and the snapshot+diff chain are the full
historical record; only the proof blobs and the fork choice index are
disposable.

## In-Memory Only (Lost on Restart)

Four `Store` fields never touch the backend. All are bounded buffers shared
across `Store` clones:

| Buffer              | Capacity        | Contents                                                                                 |
| ------------------- | --------------- | ---------------------------------------------------------------------------------------- |
| `new_payloads`      | 64 messages     | Pending aggregated attestation proofs, not yet active for fork choice                    |
| `known_payloads`    | 512 messages    | Fork-choice-active aggregated proofs                                                     |
| `gossip_signatures` | 2048 signatures | Raw per-validator XMSS signatures awaiting aggregation (each ~3 KB, so ~6 MB worst case) |
| `state_cache`       | 32 states       | LRU memoization of reconstructed/imported states                                         |

The payload buffers evict FIFO when full, and redundant proofs (whose
participants are a subset of an existing proof for the same attestation data)
are skipped on insert.

Note that the per-validator "latest attestation" maps used by fork choice are
not stored anywhere — they are derived on demand from these buffers via
`extract_latest_known_attestations` and friends. See the attestation pipeline
section of [lmd_ghost.md](lmd_ghost.md) for how attestations move between the
pools.

After a restart these buffers start empty: pending attestations and
un-aggregated gossip signatures are lost and must be re-collected from the
network. Everything persisted in the seven tables survives.

## Startup and Restore

A `Store` is created through one of three constructors in
`crates/storage/src/store.rs`:

| Constructor            | When                                   | What it does                                                                                       |
| ---------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `from_anchor_state`    | Genesis boot                           | Initializes from the genesis state (no anchor block body)                                          |
| `get_forkchoice_store` | [Checkpoint sync](checkpoint_sync.md)  | Initializes from a downloaded finalized state + anchor block, after validating they are consistent |
| `from_db_state`        | Resume from an existing data directory | Re-opens the persisted store as-is                                                                 |

The first two funnel into `init_store`, which writes the anchor in **one
atomic batch**: all six `Metadata` keys (time = 0, config, head = safe_target
= anchor root, justified = finalized = anchor checkpoint), the anchor header,
the body if non-empty, a full snapshot into `States` (the base of every future
diff chain), and the anchor's `LiveChain` entry.

`from_db_state` is the restore path: it reads `config` and `latest_finalized`
from `Metadata`, returning `None` for an empty DB or a `genesis_time`
mismatch (wrong network). At startup the node prefers this path but only
accepts the on-disk store if its head is at most `MAX_RESUMABLE_DB_STATE_AGE
= 450` slots (~30 minutes) behind the current slot; a staler DB falls through
to checkpoint sync, which writes a fresh anchor on top of the existing data.

## Key Files

| File                                      | Component                                                            |
| ----------------------------------------- | -------------------------------------------------------------------- |
| `crates/storage/src/store.rs`             | `Store`: persistence logic, in-memory buffers, pruning, constructors |
| `crates/storage/src/api/traits.rs`        | `StorageBackend`, `StorageReadView`, `StorageWriteBatch`             |
| `crates/storage/src/api/tables.rs`        | The `Table` enum                                                     |
| `crates/storage/src/state_diff.rs`        | `StateDiff`: diff creation and state reconstruction                  |
| `crates/storage/src/backend/rocksdb.rs`   | Production RocksDB backend                                           |
| `crates/storage/src/backend/in_memory.rs` | Test backend                                                         |
| `crates/blockchain/src/store.rs`          | Fork choice logic driving the `Store` (`on_block`, `on_tick`, ...)   |
