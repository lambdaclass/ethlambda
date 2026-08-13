# Beacon Chain Sync

How `ethlambda beacon` gets from nothing to following the mainnet head, and how
to tell whether it did.

## Startup order

Checkpoint sync runs **before** the libp2p swarm exists. This is not an
implementation accident:

```
fetch the finalized block         GET /eth/v2/beacon/blocks/finalized
  └─ block.state_root
     └─ fetch that exact state    GET /eth/v2/debug/beacon/states/0x{state_root}
        ├─ genesis_validators_root ─┐
        ├─ genesis_time             ├─► fork digest
        └─ slot ──► epoch ──────────┘      ├─► gossip topic names
                                           ├─► ENR `eth2` entry
                                           └─► discv5 admission
                                                └─► build the swarm
```

`genesis_validators_root` and `genesis_time` are read off the anchor state, and
the fork digest computed from them names every topic this node subscribes to,
the `eth2` entry in its ENR, and the test it applies to every discovered peer.
None of that is knowable earlier, which is why this repository carries **no
hardcoded mainnet genesis-validators-root** anywhere and why
`--checkpoint-sync-url` is required on `beacon` while it is optional on `lean`.

The block is fetched first and the state second, *by that block's own
`state_root`*. The second request is therefore content-addressed, so the pair
cannot disagree and there is no retry loop for a provider that advances
finalization mid-fetch. Lean's client, which fetches both concurrently from
endpoints that each mean "whatever is finalized right now", does need one.

The epoch the digest is computed for is the **wall-clock** epoch, not the
anchor's. The anchor is two epochs behind, so a fork or blob-parameter boundary
falling in between would otherwise leave this node on the previous side of it.

The digest is computed once and never recomputed. A boundary crossed while
running strands the node on topics the network has left, and the only symptom is
peers quietly draining away, so startup logs the next boundary's epoch and
wall-clock time as a warning. Restart before it. Re-subscribing across a
boundary is out of scope here.

### Every boot checkpoint-syncs

`ethlambda beacon` fetches a fresh anchor on every start, including a restart
against a populated `--data-dir`. `--checkpoint-sync-url` is required for the
same reason: the fork digest needs `genesis_validators_root`, and reading that
back off disk needs a beacon equivalent of lean's `Store::from_db_state`, which
is separate work. The cost is one state download per restart; the benefit is
that the node can never boot onto a digest derived from stale data.

## Anchor to head

The anchor is a **finalized** state, roughly two epochs (~64 slots) behind the
live head, and `on_block` refuses a block whose parent is not in the store. So
the first gossiped block at the head lands on a chain this node knows nothing
about:

```
anchor (finalized)                                    head (wall clock)
   |<----------------- ~64 slots to fetch ----------------->|
   |                                                        |
   └─ beacon_blocks_by_range/2, 128 slots per batch, from ───┘
      the highest-head peer; blocks arriving on gossip
      meanwhile are held by parent root and released in
      slot order the moment that parent imports
```

A block still held after the range fetch has passed its slot is on a fork off
the canonical chain, so it is fetched individually with
`beacon_blocks_by_root/2`.

Forward only. Backfill below the anchor, which a node needs before it can serve
historical requests, is a separate piece of work.

### Why this is worth being careful about

The failure mode is not a crash. A follower that imports tip blocks without
fetching the gap has a head that climbs normally and a finalized checkpoint that
never moves, because every block it accepted is orphaned. It looks healthy from
the outside. Several clients on this network have shipped exactly that, and the
metrics below exist to make it visible in seconds rather than days.

`beacon_pending::take_children` is the function that enforces it, and
`a_tip_block_must_not_become_importable_just_because_it_arrived` is the test
that pins it. That test is proven non-vacuous: replacing `take_children` with
one that releases every held block regardless of parentage turns it red.

### `on_block` refuses an unknown parent twice, on purpose

`fork_choice::on_block` checks `has_beacon_block(parent_root)` explicitly, and
then `block_state` fails on the same missing parent one line later. Deleting the
explicit check leaves **every test green**, so it reads like dead code.

It is not. The explicit check is the cheap path: a block on a chain we have
never heard of costs an index lookup instead of a state read, and a state read
on this path may replay from an anchor. Correctness is held by `block_state`;
throughput is held by the check. Remove it and nothing fails except
performance, which no test in this repository measures.

## Metrics

| Series | Meaning |
|---|---|
| `lean_sync_anchor_slot` | The checkpoint anchor this process started from. Constant for the life of the process |
| `lean_head_slot` | Current fork-choice head (`ethlambda_beacon::fork_choice::get_head`), recomputed once per beacon-block cascade and once per tick when the slot advances |
| `lean_sync_local_head_slot` | Forward-sync watermark: the highest slot the store holds a block for, on any branch. Not the head — see below |
| `lean_current_slot` | Wall-clock slot |
| `lean_latest_justified_slot`, `lean_latest_finalized_slot` | The FFG checkpoints |
| `lean_sync_pending_blocks` | Blocks held on a parent the store does not have |
| `lean_sync_pending_dropped_total` | Blocks dropped because that buffer was full |
| `lean_sync_range_blocks_total` | Blocks imported while closing the gap |
| `lean_fork_choice_reorgs_total` | Count of times the head moved to a block that does not descend from the previous head |
| `lean_fork_choice_reorg_depth` | Histogram of how many slots back each reorg had to walk to find the shared ancestor |
| `lean_node_sync_status` | 0 idle, 1 syncing, 2 synced |

`lean_head_slot` and `lean_sync_local_head_slot` answer different questions and
are expected to disagree while syncing: the watermark is how far the range
fetch has reached on *any* branch, the head is which block fork choice has
actually settled on. A range-fetch batch can land blocks past the point fork
choice is currently building on; a competing branch can also import deeper
than the one fork choice weighs heavier. Neither is a bug in the other.

Reading them together:

| Symptom | Diagnosis |
|---|---|
| `sync_local_head_slot == sync_anchor_slot`, `sync_pending_blocks` climbing | The range fetch never started. No peer's `Status` arrived, or every peer is at or behind the anchor |
| `sync_range_blocks_total` flat, `sync_pending_blocks` climbing | The range fetch stalled. Check for `rotating peer` warnings |
| `sync_local_head_slot` climbing, `head_slot` frozen well behind it | Blocks are importing but fork choice is not following. Almost always staleness rather than a defect: once the node is more than two epochs behind wall clock, `filter_block_tree` rejects every leaf and the descent returns the justified root. Run with `RUST_LOG=ethlambda_beacon::fork_choice=debug` and read `Beacon fork choice rejected a leaf as unviable`, which names the failing condition. See "Why the head stays at the anchor" below |
| `head_slot` climbing, `latest_finalized_slot` frozen | Fork choice is following a chain that never finalizes, the failure this page is about — now visible on the real head rather than the import watermark |
| `sync_pending_dropped_total` rising | A peer is feeding blocks on fabricated parents, or the gap is wider than the buffer |
| `fork_choice_reorgs_total` rising with no corresponding drop in `latest_finalized_slot` | Ordinary proposer/fork competition being resolved, not by itself a problem; `fork_choice_reorg_depth` says how far each one reached back |
| `current_slot - head_slot <= 1`, finalized advancing every 32 slots | Healthy |

## Manual verification

No test in this repository can assert that the head tracks wall clock: it needs
reachable mainnet peers and a finalizing chain. This procedure is the check.

### 1. Build and prepare

```bash
make lint && make test && make test-beacon
cargo build --profile release-fast --bin ethlambda
# Optional: --node-key is not required on `beacon`. Omitting it generates an
# ephemeral key in memory each start, logged as a warning, with a different
# PeerId and ENR every restart. Supply a file for a stable identity:
openssl rand -hex 32 > /tmp/beacon-node.key
rm -rf /tmp/beacon-data && mkdir -p /tmp/beacon-data
```

### 2. Run

```bash
./target/release-fast/ethlambda beacon \
  --checkpoint-sync-url https://beaconstate.ethstaker.cc \
  --node-key /tmp/beacon-node.key \
  --data-dir /tmp/beacon-data \
  --gossipsub-port 9000 \
  --api-port 5052 \
  --metrics-port 5054 \
  2>&1 | tee /tmp/beacon-run.log
```

Drop `--node-key /tmp/beacon-node.key` to run without one; the startup log
then shows the generated-key warning instead of nothing.

`https://mainnet-checkpoint-sync.attestant.io` is a second provider if the first
is down. Discovery is forced on for `beacon` and its port defaults to
`--gossipsub-port + 1`, so neither needs a flag.

Providers vary enormously in how fast they serve
`/eth/v2/debug/beacon/states/`. Measured at ~1 MB/s from
`beaconstate.ethstaker.cc`, which puts a several-hundred-megabyte state at
around six minutes before the first interesting log line appears. Check the
rate before concluding the node has hung:

```bash
curl -s -o /dev/null -w '%{speed_download} B/s\n' --max-time 30 \
  -H 'Accept: application/octet-stream' \
  https://beaconstate.ethstaker.cc/eth/v2/debug/beacon/states/finalized
```

### 3. Watch the log, in order

| Within | Line | What it proves |
|---|---|---|
| ~1-6 min | `Beacon checkpoint sync complete` with `anchor_slot`, `genesis_validators_root`, `fork_digest`, `digest_epoch` | The anchor downloaded and verified. Dominated by the provider's rate, not by this node |
| immediately after | the same line's `fork_digest` | Must match the digest recorded for the current epoch in [`discovery.md`](./discovery.md). A wrong digest means zero peers, silently |
| immediately after | `Restart this node before the epoch above` with `boundary_epoch` and `boundary_unix_time` | The next boundary is named. If `boundary_unix_time` is in the past, the digest is already stale and no peer will match |
| ~2 min | `Peer connected` at least 8 times, `transport` field showing a mix of `quic` and `tcp` | Peering found enough of the network over both transports. Fewer than 4 after five minutes, or a `transport` value that is always `quic`, means the TCP fallback is not doing what it was added for; see "Known limitation" below |
| ~2 min | `Anchor-to-head range sync started` with `gap` near 64 | A peer's `Status` opened a session |
| ~3 min | `Anchor-to-head range sync complete` | The gap closed. A ~64-slot gap is one 128-block batch |
| continuously | `Beacon block imported` roughly every 12s | Gossip is now importable, which it was not before the line above |

### 4. Watch the metrics

```bash
while true; do
  date +%H:%M:%S | tr -d '\n'
  curl -s localhost:5054/metrics \
    | grep -E '^lean_(sync_anchor_slot|head_slot|sync_local_head_slot|current_slot|latest_finalized_slot|sync_pending_blocks|sync_range_blocks_total) ' \
    | sed 's/^lean_//' | tr '\n' ' '
  echo
  sleep 12
done
```

### 5. Call it healthy after 15 minutes

Fifteen minutes, not five: two epochs of finalization lag is 12.8 minutes, so a
shorter window cannot distinguish a node that finalizes from one that only
appears to. `head_slot` is now `get_head`'s actual output rather than the raw
import watermark, so the first condition below is a real answer to "does this
node's own view track wall clock", not a coincidence of the two having stayed
close together. All five must hold:

```
current_slot - head_slot          <= 1
sync_pending_blocks               == 0
sync_range_blocks_total           >  0        (the gap really was fetched)
latest_finalized_slot             >  sync_anchor_slot
latest_finalized_slot             advanced by >= 32 during the window
```

The fourth and fifth are the ones that matter. A head within one slot of wall
clock proves nothing on its own: that is exactly what the failure mode looks
like.

### 6. Check the restart path

Ctrl-C the node, then start it again with the same command.

Expected: a second `Beacon checkpoint sync complete`, with an `anchor_slot`
**higher** than the first run's, since the chain finalized while the node was up.
`lean_sync_anchor_slot` reports the new one. The node reaches the head again and
§5's five conditions hold within another 15 minutes.

Re-downloading the anchor is the intended behaviour, not a regression: see
"Every boot checkpoint-syncs" above.

## What a live run has actually shown

Two runs against mainnet from a developer machine, 2026-08-12. Recorded here
because the gap between "starts up correctly" and "follows the chain" is the
whole subject of this page, and only the first half is currently proven.

Confirmed working on live data:

| | |
|---|---|
| Checkpoint sync | anchor slot 14977216, fork `fulu`, ~3.5 min at ~1 MB/s |
| `genesis_validators_root` | `0x4b363db9…bfe95`, matching the value the digest tests pin |
| Fork digest | `8c9f62fe`, matching [`discovery.md`](./discovery.md)'s record for this epoch |
| Boundary warning | "No fork or blob-schedule boundary is scheduled" |
| Topics | 7, no subnet families |
| Local ENR | `attnets`, `cgc`, `eth2=8c9f62fe`, `quic`, and no `tcp` (predates TCP support, see below) |
| Admission | live rejects for "no quic port", "missing or undecodable eth2 entry", "fork digest mismatch" |
| `lean_sync_anchor_slot` | served, and equal to the anchor slot in the log |

Not shown: sustained gossip, a closed gap, or finality advancing. Peers
connect and drop.

### Known limitation (as of the 2026-08-12 runs above): QUIC-only peering on mainnet

ethlambda spoke QUIC and no TCP, and mainnet nodes widely advertise a `quic`
ENR entry that does not answer. Across both runs, dials failed with
`Handshake with the remote timed out` far more often than they succeeded; an
earlier run reached ten admitted peers with correctly decoded `attnets`,
connected to one, exchanged a `Status`, and correctly decoded that peer's
`Goodbye` before losing it. Discovery, admission, the fork digest and the codec
were all proven on live data; the transport was what did not hold.

### What changed since, and what is still unverified

TCP (noise + yamux) now runs alongside QUIC on both swarms, on the same port
number as the QUIC listener. The local ENR advertises `tcp` in addition to
`quic` (see [`discovery.md`](./discovery.md)'s entry table), admission accepts
a peer that offers either transport, and a dial carries every address a peer
advertises so libp2p races QUIC and TCP within one attempt — the mechanism
meant to let a live TCP address rescue a dial whose advertised `quic` does
not answer.

## The 2026-08-13 runs: what the transport change bought, and what it exposed

Re-run against mainnet after the TCP work, then again after each fix below.
Recorded in the order the failures surfaced, because each one hid the next.

| | |
|---|---|
| Peering | `Peer connected` with `transport=tcp` and `transport=quic`. TCP carries the sessions that survive; QUIC-only never got one past the handshake |
| Muxer | mainnet peers answer `NotAvailable` to a yamux-only proposal and negotiate `/mplex/6.7.0`. A yamux-only node peers with nothing over TCP |
| Gossip | live and decoding: ~500 `beacon_aggregate_and_proof`, 20 `sync_committee_contribution_and_proof` and several `beacon_block` in a six-minute window |
| Range sync | `Status` exchanged, `BeaconBlocksByRange` issued and answered |
| Block import | **blocks import, in consecutive slots**, which had never happened before |
| Head | still pinned at the anchor, and that part is fork choice behaving correctly. See below |

Three defects had to be fixed before one block could import, none visible from
outside the process:

1. **No chain actor.** `beacon::run` spawned discovery, the metrics server and
   the P2P actor and no `BlockChain`, so `P2PServer::blockchain` stayed `None`
   and every decoded block hit its "no blockchain handler available" branch at
   debug level. The tell was in the metrics: eight `lean_` series exposed and
   not one tick-driven one, because they register lazily on first update.
2. **A lean accessor on the beacon path.** The held-block logic asked
   `store.head_slot()`, which reads a metadata key a beacon store never
   writes. The actor panicked on the first gossiped block with an unknown
   parent, and a panicked handler leaves the process running, so the node went
   on peering and decoding with nothing behind it.
3. **Registry rescans inside the state transition.** Import went from never
   completing to ~13-16s per block.

### Why the head stays at the anchor

Not a defect. `filter_block_tree` rejects a leaf whose voting source is stale:

```text
correct_justified = justified.epoch == GENESIS_EPOCH
                 || voting_source.epoch == justified.epoch
                 || voting_source.epoch + 2 >= current_epoch
```

Observed live, at debug level on `ethlambda_beacon::fork_choice`:

```text
Beacon fork choice rejected a leaf as unviable
  correct_justified=false correct_finalized=true
  voting_source_epoch=468251 justified_epoch=468252 current_epoch=468255
```

468251 + 2 is below 468255, so every imported block is unviable, the filtered
tree is empty, and the descent returns the justified root: the anchor. That is
the specification protecting fork choice from following a branch whose
justification has fallen more than two epochs behind wall clock.

The node is in that state because **import is slower than block production**.
At ~13-16s per block against a 12s slot it loses ground every slot and can
never re-enter the two-epoch window. Nothing about peering or fork choice
fixes that; import throughput is the whole remaining gap. Profiling a live
import puts roughly 60% of samples in committee derivation
(`compute_shuffled_index`, `get_active_validator_indices`,
`get_beacon_committee`, `compute_committee`) — the shuffling cache this
codebase does not yet have — with `hash_tree_root` and `aggregate_verify`
next behind it.

So the honest reading of `head_slot` frozen at `sync_anchor_slot` while
`sync_local_head_slot` climbs is: blocks are importing, too slowly, and fork
choice is right to refuse them.

### Peer retention is still unresolved

Peers accept the connection, complete the beacon handshake, and answer
`Goodbye(129)` — too many peers — within a millisecond. Fifteen connections
over six minutes, ten of them ending that way. Two contributing factors are
outside this code (the test host is behind NAT with no inbound, and the node
serves no blocks, so a peer at its cap sheds it first) and one is inside it:
the dial loop now retries every second while at zero peers rather than every
five, which roughly tripled attempts. Whether that is enough on a
reachable host is unmeasured.
