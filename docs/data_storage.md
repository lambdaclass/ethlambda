# 💾 Storage: What Lives Where

This doc explains how ethlambda saves data. Especially,
the split between the fork choice `Store` and the `StorageBackend` trait,
what each of the ten tables holds, and which data is in-memory only.

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
   │   │ BlockProof          │         │   attestations)      │    │
   │   │ BlockRoots          │         │ known_payloads       │    │
   │   │ States              │         │  (fork-choice-active │    │
   │   │ StateDiffs          │         │   attestations)      │    │
   │   │ Metadata            │         │ gossip_signatures    │    │
   │   │ LiveChain           │         │  (raw XMSS sigs      │    │
   │   │ DataColumns         │         │   awaiting           │    │
   │   │ PendingDataColumns  │         │   aggregation)       │    │
   │   └─────────────────────┘         │ state_cache (LRU)    │    │
   │                                   └──────────────────────┘    │
   │   Survives restarts, except                                   │
   │   PendingDataColumns, which       Lost on restart.            │
   │   is cleared at startup.                                      │
   └───────────────────────────────────────────────────────────────┘
```

## The Tables

The ten variants of the `Table` enum (`crates/storage/src/api/tables.rs`):

| Table              | Key                        | Value                                     | Pruned?                          |
| ------------------ | --------------------------- | ----------------------------------------- | --------------------------------- |
| `BlockHeaders`     | root                        | `BlockHeader`, or a whole beacon block    | never                            |
| `BlockBodies`      | root                        | `BlockBody` (lean only)                   | never                            |
| `BlockProof`       | slot ‖ root                 | aggregate proof (`MultiMessageAggregate`) | yes: finalized older than ~1 day |
| `BlockRoots`       | slot                        | block root (`H256`)                       | never                            |
| `States`           | root                        | full `State` snapshot                     | never                            |
| `StateDiffs`       | root                        | `StateDiff`                               | never                            |
| `Metadata`         | string                      | SSZ scalars                               | never                            |
| `LiveChain`        | slot ‖ root                 | `parent_root`                             | yes: below finalized             |
| `DataColumns`      | slot ‖ root ‖ column_index  | `DataColumnSidecar` (SSZ-encoded)         | no (see [DataColumns](#datacolumns) below) |
| `PendingDataColumns` | slot ‖ root ‖ column_index | `DataColumnSidecar` (SSZ-encoded), unverified | yes: on replay, below finalized, and wholly at startup |

### Key encoding

Four key layouts are used:

- **Root-keyed** tables use the 32-byte SSZ encoding of the block root
  (`root.to_ssz()`).
- **Slot-prefixed** tables (`BlockProof`, `LiveChain`) use
  `encode_slot_root_key`: an 8-byte **big-endian** slot followed by the
  32-byte root. Big-endian means lexicographic key order equals numeric slot
  order, so pruning can iterate from the start of the table and stop at the
  first key past its cutoff instead of scanning everything.
- **Slot-prefixed, then column** (`DataColumns`) extends the same
  `slot ‖ root` prefix with an 8-byte big-endian `column_index`, via
  `data_column_key`. A block's own sidecars therefore share one lexicographic
  run under their `slot ‖ root`, so a prefix scan over just that pair (what
  `data_column_indices_for` and the by-range handler both do; see
  [DataColumns](#datacolumns)) recovers every column of one block without
  touching any other block's.
- **Slot-only** (`BlockRoots`) uses `encode_block_root_key`: just the 8-byte
  big-endian slot, since the value already holds the root. This table is
  never pruned, so the ordering buys nothing here; it is kept only for
  consistency with the other slot-prefixed keys.

### BlockHeaders

`root → BlockHeader`. Written for every block, including the genesis/anchor
block, and never pruned: headers are the permanent record of the chain.
Headers are also read back during state reconstruction (see
[State Storage](#state-storage-snapshots--diffs)).

On a **beacon** directory this row holds the whole `SignedBeaconBlock`
instead, prefixed with a one-byte fork selector the way a `States` value is,
since a beacon block's shape varies by fork and SSZ carries no type tag. The
two shapes never coexist in one table: a data directory holds one chain for
its whole life (see `Chain`).

`Store::block_entry` is the chain-agnostic reader for a stored block's slot
and parent root, and is what the fork-choice tree walk and the `BlockRoots`
index diff share. On the beacon arm it decodes the whole block to reach those
two fields, so a caller walking a chain of them should build
`Store::block_index` once instead, which reads the same links out of
`LiveChain`.

### BlockBodies

`root → BlockBody`, **lean only**. Written for every block **except** those
with an empty body: if `header.body_root == EMPTY_BODY_ROOT` (the hash tree
root of `BlockBody::default()`), nothing is stored and reads synthesize
`BlockBody::default()`. This covers the genesis block and checkpoint sync
anchors, whose bodies are either empty or unavailable. Never pruned.

The split exists so a header-only query need not pay for the body, and so an
empty body can be left out entirely. A beacon block has neither property, and
nothing reads a beacon header without its block, so the beacon arm writes no
row here at all: a second row would only add a write and a way for the two to
disagree.

### BlockProof

`slot ‖ root → MultiMessageAggregate`. This table stores the block's **merged
aggregate proof blob**. It is keyed by `slot ‖ root` so that pruning can scan in
slot order and stop early.

Stored separately from headers/bodies because the genesis block has no proof.
`get_signed_block` synthesizes an empty proof for the slot-0 anchor only; for
any other block a missing entry (a pruned finalized block) surfaces as `None`
rather than a fabricated block.

This is the one block table that **is** pruned; see [Pruning](#pruning).

### BlockRoots

`slot → H256`, the canonical block root at each slot. Rewritten on every head
update inside `update_checkpoints`: `block_root_index_changes` walks the old
and new head's branches back to their common ancestor, deleting the slots
that leave the canonical chain and writing the ones that join it. A reorg
therefore touches only the affected slot range, not the whole table. Never
pruned.

Backs `get_signed_blocks_by_slot_range`, which serves BlocksByRange requests
over req/resp (`crates/net/p2p/src/req_resp/handlers.rs`). It does **not**
back the RPC `GET /lean/v0/blocks/:slot` endpoint: that handler resolves a
slot through the head state's `historical_block_hashes` instead
(`resolve_slot` in `crates/net/rpc/src/blocks.rs`), so a block on a side fork
is reachable there only by root, never by slot.

### States

`root → State` (full SSZ snapshot). Holds full-state snapshots **only**: the
bootstrap anchor written at initialization, plus one anchor whenever a block
crosses a `SNAPSHOT_ANCHOR_INTERVAL`-slot boundary. Never pruned — these
anchors are the base every diff chain resolves against, so reconstruction
always terminates.

The genesis validator registry is constant for the life of the chain
(`validators` is fixed at genesis; the lean STF never mutates it), but it has
no table of its own: it rides inside every `States` snapshot alongside
`config`, which `StateDiff` reconstruction relies on (see
[State Storage](#state-storage-snapshots--diffs)).

### StateDiffs

`root → StateDiff`. A parent-linked diff written for **every** non-genesis
state. Never pruned, so together with the snapshots this preserves the full
state history. See [State Storage](#state-storage-snapshots--diffs) for what a
diff contains and how states are rebuilt.

### Metadata

String keys mapping to (mostly) SSZ-encoded scalars — the `Store`'s own
persistent fields. Four are written on every directory, whichever chain it
holds; the rest are chain-specific, since lean and a beacon directory keep
different checkpoints.

| Key                            | Type         | Chain  | Meaning                                                       |
| ------------------------------ | ------------ | ------ | ------------------------------------------------------------- |
| `db_version`                   | `u64`        | both   | On-disk format version this directory was written at          |
| `chain`                        | raw byte     | both   | Which consensus protocol this directory holds (`Chain`)       |
| `preset`                       | raw byte     | both   | Which SSZ preset the writing build used (`Preset`)            |
| `time`                         | `u64`        | both   | The store clock, as a **UNIX timestamp in milliseconds**      |
| `config`                       | `Config`     | both   | The node's runtime configuration                              |
| `head`                         | `H256`       | both   | Current fork choice head                                      |
| `anchor_slot`                  | `u64`        | both   | The slot this directory's chain begins at                     |
| `safe_target`                  | `H256`       | lean   | Current safe target (see [lmd_ghost.md](lmd_ghost.md))        |
| `latest_justified`             | `Checkpoint` | both   | Latest justified checkpoint                                   |
| `latest_finalized`             | `Checkpoint` | both   | Latest finalized checkpoint                                   |
| `beacon_unrealized_justified`  | `Checkpoint` | beacon | Unrealized justified checkpoint (beacon `Checkpoint`)         |
| `beacon_unrealized_finalized`  | `Checkpoint` | beacon | Unrealized finalized checkpoint (beacon `Checkpoint`)         |

Rows marked for one chain are never written on the other, so reaching one
through the wrong chain's accessor panics naming the key rather than reading a
zero. That is deliberate: a data directory holds one chain for its whole life.

#### One clock, three readings

`time` is the only clock either chain keeps, and it is a UNIX millisecond.
Milliseconds because the row has to be fine enough for the finest grid either
chain schedules on, which is lean's interval: with `INTERVALS_PER_SLOT`
intervals to a slot, most interval boundaries fall strictly between two whole
seconds, and a second-resolution row could not name them.

Everything coarser is derived from it, exactly and in one direction:

| Reading | Method | Used by |
| --- | --- | --- |
| Milliseconds past genesis | `Store::ms_since_genesis` | placing a moment within the current slot, against the beacon basis-point deadlines |
| Intervals past genesis | `Store::intervals_since_genesis` | lean's tick pipeline, its future-slot guards, its fork-choice fixtures and the Hive driver |
| Slot | `Store::current_slot` | both chains, including the beacon `get_slots_since_genesis` |

Nothing stores a derived reading, so none of them can fall out of step with
the row or with each other. The beacon specification denominates its own
`Store.time` in seconds, so `on_tick` and `on_tick_per_slot` convert on the
way in and the fixture harness divides on the way out; that conversion lives
at those edges rather than in a second row.

Lean's `on_tick` writes the row only at interval boundaries, since the
boundary is what it has actually processed: it walks forward one interval at a
time running that interval's duty, and the leftover milliseconds up to the
tick's own timestamp carry no duty that has run. The one time it moves the
clock backwards is the deliberate rewind that replays a slot after a gap.

#### Format and shape tags

`db_version`, `chain` and `preset` are what `from_db_state` checks before it
decodes anything else, and the two tags are raw bytes rather than SSZ for that
reason: they have to be readable by a build that would decode the rest of the
directory into the wrong shape. `db_version` catches a layout change this build
knows about; `chain` catches lean rows being opened as beacon or the reverse;
`preset` catches a `preset-minimal` build opening a mainnet directory, which
the other two cannot, since both presets write the same layout at the same
version while bounding every SSZ container differently. None of the three has a
migration path.

`config` and `chain` are the odd ones out among the mutable rows: written once
at bootstrap (`init_store` for lean, `init_beacon` for beacon) and never
rewritten afterward (`config` has a getter, `Store::config`, and `chain` has
`Store::chain`, but neither has a setter). Because they never change, the
`Store` keeps a copy of each in memory, and reads of them never reach the
backend. Every other `Metadata` key is mutated in place as the chain
progresses.

`config` used to double as the DB's fingerprint on its own, with
`from_db_state` refusing to resume a data directory belonging to another
network. `from_db_state` no longer judges the network or the chain (see
[Startup and Restore](#startup-and-restore)): it reads `config` and `chain`
back and hands both to the caller, which compares `config`'s `genesis_time`
and slot duration (and `genesis_validators_root`, computed off the anchored
state itself rather than stored in `Metadata`) against the network it was
configured for, and `chain` against the sub-command it is running.

A beacon directory **shares** `head`, `latest_justified` and `latest_finalized`
rather than keeping parallel ones. `init_beacon` seeds all three from one
trusted anchor, exactly as `init_store` seeds them on a lean directory, so
`update_checkpoints` is a single writer for both chains instead of growing an
absent-key branch per chain. The specification gives a trusted anchor's
finality the same starting value as its justification, rather than one actually
reached through the FFG rules, which is why both start equal.

The two chains denominate a checkpoint differently, and the stored form is
lean's: a beacon epoch is written as its own start slot. That is what makes the
conversion exact in both directions, through
`Store::beacon_checkpoint_as_stored` on the way in and
`Store::beacon_finalized_checkpoint` on the way out, and it is what lets the
shared finalization-advance comparison read a beacon checkpoint with no second
rule for it.

Note what is *not* in the table. There is no stored beacon head row:
`beacon_head()` derives its pair from `head` plus the head block's own entry,
because a second row denominated in `slot ‖ root` would be a value that could
drift from the first.

`init_beacon` writes the two beacon-only keys plus `db_version`, `chain`,
`preset`, `config`, `time`, `head`, `anchor_slot`, `latest_justified` and
`latest_finalized` in one atomic batch.

`anchor_slot` is the odd one among these: every other row is either a format
tag or something a later writer moves, while this one is written once at
bootstrap and never again, like `config` and `chain`. It has to be persisted
rather than derived because it is the store's only record of where its chain
starts. `latest_finalized` is seeded to the anchor as well, but climbs away
from it at the first finalization, so after that nothing else on disk can
answer the question. Both bootstrap paths take it from the anchor block's own
slot — `anchor_state.latest_block_header.slot` on lean, `anchor_state.slot()`
on beacon — rather than from the anchor checkpoint, whose beacon form is
epoch-denominated and would name the epoch's start slot instead. `from_db_state`
reads it back into a `Store` field, so `Store::anchor_slot()` costs no backend
round trip; the `Status` message's `earliest_available_slot` and the
`data_column_sidecars_by_range/1` floor are both that one value, which is what
keeps a refusal from contradicting an advertisement. A directory's finalized state root, whichever chain it
holds, is read through `Store::finalized_state_root`. That needs no
chain-specific branch: both chains keep their finalized checkpoint in
`latest_finalized`, and the epoch-to-slot conversion above touches only the
slot, never the root. It treats a zero root as `Error::UnanchoredDirectory`
rather than a valid answer, since both `init_store` and `init_beacon` always
anchor at a real block root, so a zero root means the directory was built some
other way or its metadata was corrupted at rest.

Note that this is *not* the SSZ `StateConfig` carried inside `State`. That one is
merkleized into the state root, so its layout is fixed by the spec and holds only
`genesis_time`; the runtime `Config` adds the slot duration and the beacon fork
schedule, which the node needs to schedule duties but which never enter a state
root.

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

### DataColumns

`slot ‖ root ‖ column_index → DataColumnSidecar` (SSZ-encoded). Beacon only:
this is where a fulu data-availability-sampling follower keeps the column
sidecars its own node id assigned it custody of, so it can verify a block's
availability and answer `data_column_sidecars_by_{root,range}/1` for peers;
see [beacon_wire.md](./beacon_wire.md#data-column-sidecars) for the wire side
and how a node's custody set is selected.

Keyed slot-first, ahead of the root, for the same reason `BlockProof` is: it
gives a by-range answer a prefix scan per slot instead of a full-table scan,
and gives a future pruner a scan that stops early once it passes its cutoff.
Every writer and reader already has the slot in hand — an arriving sidecar
carries `signed_block_header.message.slot`, and the availability check and the
held-block release path both start from the block itself — so the slot prefix
costs nothing to supply.

Sidecars are written on arrival, once `on_gossip_data_column` has verified
one, rather than at block import. That ordering is what lets the availability
gate read a block's columns before the block itself is allowed to import (a
column has to exist first for the gate to find it), and what lets a restart
keep every sidecar this node already paid a KZG batch to verify rather than
re-fetching and re-verifying them. One consequence: a sidecar is stored for
any block whose header, parent and proposer check out, whether or not that
block ever actually imports — an equivocation or an orphaned fork's sidecars
land here too, since gossip only requires a known, unfinalized parent, not a
canonical one. `data_column_sidecars_in_range` (the by-range handler's source)
compensates by restricting each slot's answer to that slot's canonical root
via `BlockRoots`, so a losing sibling's columns are stored but never served.

`DataColumns` is the one table in the enum with **no pruning rule at all**,
not even the finalized-window pruning `LiveChain` and `BlockProof` get: every
sidecar this node has ever custodied is kept forever, by design, until a
pruner is written (`MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` is the
epoch depth spec gives a future one permission to prune below). That makes it
the one table whose size a long-running node must actually watch rather than
assume bounded: at the blob cap this is roughly 360 KB per slot across the
columns this node custodies, nearer 1 GB per day at current mainnet blob
counts. `lean_table_bytes{table="data_columns"}` (see [metrics.md](./metrics.md))
is that growth made visible; watch it, and size the disk against however long
the node runs unattended before a pruner exists.

### PendingDataColumns

Same key and same encoding as `DataColumns`, holding sidecars that have **not
been verified yet**. A sidecar lands here when its block's parent has no
post-state for `on_gossip_data_column` to check the proposer against: the
parent may still be in flight, or it may be a block the availability gate is
itself holding. The specification's gossip rule for that case is `[IGNORE]`
with an explicit licence to come back to it, so the sidecar is parked rather
than dropped, and replayed when the parent gains a post-state.

Two tables rather than one, and that is the whole point of this one. A parked
sidecar has passed only the cheap structural checks — not its inclusion proof,
not its KZG batch, not its proposer signature, which are held back so a replay
pays for them once rather than once per attempt. `data_column_indices_for`
reads `DataColumns` and nothing else, and that read is what the data
availability gate believes; an unverified row there would let a peer satisfy
the gate with a column nothing ever judged. A row moves from here to
`DataColumns` only by passing every check on replay.

The chain actor keeps one key per parked row in memory
(`sidecars_awaiting_parent`, keyed by the parent root it waits on) and the
bytes here, because a sidecar carries a cell per blob and the queue's size is
chosen by whichever peer is gossiping.

Nothing caps that queue. The finality sweep that evicts held blocks also
deletes the rows of parked sidecars at or below the finalized slot, and that is
the only thing reclaiming them, so it bounds how *long* a row lives but not how
fast rows arrive. `on_gossip_data_column` does not require a sidecar's
`parent_root` to name a block this node knows, and the p2p layer's
`seen_data_columns` dedups on the header's own slot, proposer and index, all
three of which a fabricated header chooses freely, so a peer willing to make
them up can park rows as fast as gossip carries them. Watch
`lean_sidecars_awaiting_parent`: it is the only signal that this is happening,
and unlike `DataColumns` these rows were written on a peer's say-so.

That in-memory map is also the *only* index into this table, and it does not
survive a restart, so `start_actor` clears the table outright before building
an empty one. Nothing is lost: a parked sidecar had passed no check worth
preserving, and the block it belongs to asks for its columns again. Without
that, every crash would leave every row it had parked unreadable, kept until
the directory was deleted.

## State Storage: Snapshots + Diffs

Storing a full `State` per block would be wasteful: most fields never change
or change predictably. Instead, `insert_state` writes:

1. **Always** a `StateDiff` keyed by the block root, linked to its parent via
   `base_root` (the block's `parent_root`).
2. **Only at anchors** a full snapshot into `States`. A block is an anchor
   when it crosses a `SNAPSHOT_ANCHOR_INTERVAL` slot boundary relative
   to its parent (~68 minutes at 4-second slots). This bounds any
   reconstruction walk to at most `SNAPSHOT_ANCHOR_INTERVAL` diff applications.

A `StateDiff` stores only what cannot be recovered elsewhere: the target slot,
justified/finalized checkpoints, and the justification fields
(`justified_slots`, `justifications_roots`, `justifications_validators`,
stored in full — they are bounded by the non-finalized window, so they stay
small under healthy finality). The rest is deliberately omitted:

| Omitted field             | Recovered from                                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config`, `validators`    | The snapshot (they never change)                                                                                                                              |
| `latest_block_header`     | The `BlockHeaders` table                                                                                                                                      |
| `historical_block_hashes` | Regenerated from `base_root` + the slot gap |

The `historical_block_hashes` append is checked rather
than trusted blindly: `validate_history_append`
(`crates/storage/src/state_diff.rs`) rejects a diff whose appended hashes
don't match the expected slot gap or aren't zero-filled for skipped slots,
so a broken append surfaces at diff-creation time instead of corrupting a
later reconstruction.

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
   │                            │            BlockBodies[root]    (lean, if non-empty)
   │                            ├─one batch─ BlockProof[slot‖root]
   │                            │            LiveChain[slot‖root]
   │                            ┘
   │
   ├─ 3. insert_state()                 cache + PendingStates insert (synchronous),
   │      (hands the state to the        then a hand-off to the background writer
   │       storage crate's own writer     thread, which commits
   │       thread; see below)                   StateDiffs[root]
   │                                            States[root]         (anchors only)
   │                                      on its own schedule, not this one
   │
   └─ 4. update_head()                 Metadata: head
          (re-runs fork choice)        (+ justified/finalized if advanced,
                                          + BlockRoots diff (canonical index),
                                          + pruning on finalization)
```

Each numbered step is atomic on its own, but the import as a whole is **not**
one transaction, and step 3 is no longer one write at all: `insert_state`
returns once the state is cached and buffered (see `crates/storage/src/state_writer.rs`),
not once the writer thread has actually committed it. That thread drains a
FIFO one state behind the importer at most (`STATE_WRITE_QUEUE_CAPACITY = 2`,
plus the one write it can be holding), so steps 1, 2 and 4 can all reach disk
before step 3's own commit does. An unclean shutdown inside that window can
therefore leave `head` (from step 4), or `latest_justified` (from step 1, for
an even earlier block whose own step 3 might itself still be mid-flight), or
the finalized checkpoint `update_head` derives from the head state, naming a
root this directory has no state for yet — the exact thing "never leave
metadata referencing missing data" used to rule out, before the state write
moved off the importer's thread.

`Store::repair_head`, called by a resuming caller (see
[Startup and Restore](#startup-and-restore) below), is what restores that
property for the head: it walks back to the newest ancestor with a persisted
state and rewinds there, dropping the `LiveChain` rows of whatever it hops
over so fork choice does not walk straight back to the stateless tip.
Justified and finalized are never rewound the same way — they are consensus
statements, not a pointer a repair may quietly move to an earlier one — so
`Store::verify_anchor_states` checks them instead, and a directory that fails
it is treated as needing a fresh anchor. Re-importing a block whose `LiveChain`
row was dropped this way is idempotent the same way any duplicate is: the skip
check is keyed on `has_state`, not on whether the block is already on record,
so a stateless block is reprocessed rather than skipped.

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

- `prune_old_block_proofs`: deletes `BlockProof` entries below
  `cutoff = tip_slot − BLOCK_PROOF_PRUNING_RANGE` (21,600 slots, ~1 day at
  4-second slots) — but **only** when `cutoff ≤ finalized_slot`, i.e. the
  entire pruned range lies within finalized history. Non-finalized proofs
  are never touched. Finalized blocks can never revert, so their proofs are
  not needed for fork choice, reorg safety, or re-aggregation once outside
  the window.

**Never pruned, by design:** `BlockHeaders`, `BlockBodies`, `BlockRoots`,
`States`, `StateDiffs`, and `Metadata`. Headers, bodies, the canonical slot
index, and the snapshot+diff chain are the full historical record; only the
proof blobs and the (non-finalized) fork choice index are disposable.

**Not pruned yet, unlike the six above:** `DataColumns`. It is not part of the
historical-record set above; it simply has no pruning rule written for it,
which is a gap rather than a decision — see [DataColumns](#datacolumns) for
what bounds it in the meantime (`lean_table_bytes{table="data_columns"}`) and
where a future pruner is meant to land
(`MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS`).

## In-Memory Only (Lost on Restart)

Five `Store` fields never touch the backend. All are bounded buffers (or, for
`beacon`, bounded in practice by the validator set and the unfinalized window)
shared across `Store` clones:

| Buffer              | Capacity        | Contents                                                                                 |
| ------------------- | --------------- | ---------------------------------------------------------------------------------------- |
| `new_payloads`      | 64 messages     | Pending aggregated attestation proofs, not yet active for fork choice                    |
| `known_payloads`    | 512 messages    | Fork-choice-active aggregated proofs                                                     |
| `gossip_signatures` | 2048 signatures | Raw per-validator XMSS signatures awaiting aggregation (each ~3 KB, so ~6 MB worst case) |
| `state_cache`       | 32 states       | LRU memoization of block *and* checkpoint post-states (either chain), each held behind an `Arc` so a hit is not a copy; one bound covers both kinds, keyed apart by a small enum, and a miss is just a reconstruction rather than an error |
| `beacon`            | unbounded       | Beacon fork-choice scratch: proposer boost root, block timeliness, equivocating validator indices, latest messages, PoW blocks, and unrealized justifications. None of it is persisted: proposer boost resets every slot, timeliness is read only by the same-slot reorg helpers, equivocators come back from replaying attester slashings on sync, latest messages from one epoch of attestations, PoW blocks stand in for an execution-client call a restarted node would simply make again, and unrealized justifications are refilled as a node re-imports the unfinalized window from its anchor |

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
network. Everything persisted in the ten tables survives, except `PendingDataColumns`, which is cleared outright: its only index is in memory.

## Startup and Restore

A `Store` is created through one of four constructors in
`crates/storage/src/store.rs`:

| Constructor            | When                                    | What it does                                                                                       |
| ---------------------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `from_anchor_state`    | Lean genesis boot                       | Initializes from the genesis state (no anchor block body)                                          |
| `get_forkchoice_store` | Lean [checkpoint sync](checkpoint_sync.md) | Initializes from a downloaded finalized state + anchor block, after validating they are consistent |
| `init_beacon`          | Beacon [checkpoint sync](checkpoint_sync.md) | Writes a beacon directory's `Metadata` in one atomic batch, all seeded to one trusted anchor. The anchor block and state themselves are written separately, by `ethlambda_state_transition::beacon::fork_choice::get_forkchoice_store` (the specification's own construction rules, which this crate cannot depend on) |
| `from_db_state`        | Resume from an existing data directory   | Loads whichever chain the directory holds, without judging whether it is the right one            |

The first two funnel into `init_store`, which writes the anchor in **one
atomic batch**: the `Metadata` keys a lean directory needs (the format version
and the chain and preset tags, time, config, head = safe_target = anchor root,
justified = finalized = anchor checkpoint), the anchor header, its
`BlockRoots` entry, the body if non-empty, a full snapshot into `States` (the
base of every future diff chain), and the anchor's `LiveChain` entry. `time`
starts at genesis rather than at zero because it is an absolute timestamp, so
genesis is the value that means "the clock has not moved yet"; every derived
reading is zero there.

`init_beacon`'s own atomic batch is the beacon-directory keys listed under
[Metadata](#metadata) above; the anchor's `States`/`BlockHeaders`/`BlockBodies`
entries are written by its caller instead, through the same `insert_state` and
`insert_signed_block` an ordinary block import uses.

`from_db_state` is the restore path: it reads `db_version`, `preset`, `chain`,
`config` and `anchor_slot` from `Metadata`, returning `None` for an empty DB. A format
mismatch is still fatal, failing with `Error::DbVersionMismatch` or
`Error::PresetMismatch` rather than reading on, but `from_db_state` no longer
judges the network or the chain, and it does not mutate anything either: it
hands back whichever chain the directory holds, without comparing either
against anything or repairing anything. Both are now the caller's job, in a
fixed order: `fetch_initial_state` (lean) and `fetch_initial_beacon_state`
(beacon) each check `Store::chain()` against the sub-command they are running
under, then call `Store::verify_anchor_states` — which reads back both the
justified and finalized checkpoints (see [Metadata](#metadata) above) and
confirms each has a persisted state, returning the finalized state — before
running `verify_state_genesis` against it. Only once both of those pass does
either caller call `Store::repair_head`, described under
[Write Paths](#write-paths-what-a-block-import-persists) above: it is a
mutation, so it waits until the store it would mutate has been judged fit to
resume at all, and it leans on `verify_anchor_states` having already confirmed
finalized has a state, which is what lets it treat reaching finalized's slot
during its own walk as a plain stopping point rather than something it has to
guard against.

A chain mismatch aborts with `CheckpointSyncError::WrongChain`; a genesis
mismatch aborts with `CheckpointSyncError::Genesis`, wrapping
`GenesisMismatch::GenesisTime` or `::GenesisValidatorsRoot`; a missing anchor
state (`storage::Error::AnchorStateLost`) is treated exactly like a stale DB,
described next. All three used to be raised (the first two) or were not yet
possible to raise (the third) from inside `from_db_state` itself; none of that
judgment lives in the storage crate anymore, now that the checks that need it
moved one layer up, to the caller that actually knows which network and which
chain it wants. None of these failures are treated as an empty directory:
writing a fresh anchor on top would leave the foreign (or merely incomplete)
chain's rows in place, to be served to peers.

At startup, each chain prefers this path but only accepts the on-disk store if
its head is at most `MAX_RESUMABLE_DB_STATE_AGE = 450` slots behind the
current slot: ~30 minutes at lean's four-second slots, ~90 minutes at beacon's
twelve-second ones. A staler DB, or one whose anchor checkpoint state is
missing, falls through to checkpoint sync, which writes a fresh anchor on top
of the existing data.

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
