# Metrics

We collect various metrics and serve them via a Prometheus-compatible HTTP endpoint at `http://<http_address>:<metrics_port>/metrics` (default: `http://127.0.0.1:5054/metrics`).

A ready-to-use Grafana + Prometheus monitoring stack with pre-configured [leanMetrics](https://github.com/leanEthereum/leanMetrics) dashboards is available in [lean-quickstart](https://github.com/blockblaz/lean-quickstart).

The exposed metrics follow [the leanMetrics specification](https://github.com/leanEthereum/leanMetrics/blob/2719baad8351c9ad5eaf3c8621f33fcec20a1dc7/metrics.md), with some metrics not yet implemented. We have a full list of implemented metrics below, with a checkbox indicating whether each metric is currently supported or not.

## Node Info Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Supported     |
|--------|-------|-------|-------------------------|--------|---------------|
| `lean_node_info` | Gauge | Node information (always 1) | On node start | name, version | ✅ |
| `lean_node_start_time_seconds` | Gauge | Start timestamp | On node start | | ✅ |


## PQ Signature Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_pq_sig_attestation_signatures_total` | Counter | Total number of individual attestation signatures | On each attestation signing | | | ✅ |
| `lean_pq_sig_attestation_signatures_valid_total` | Counter | Total number of valid individual attestation signatures | On each attestation signature verification | | | ✅ |
| `lean_pq_sig_attestation_signatures_invalid_total` | Counter | Total number of invalid individual attestation signatures | On each attestation signature verification | | | ✅ |
| `lean_pq_sig_attestation_signing_time_seconds` | Histogram | Time taken to sign an attestation | On each attestation signing | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | ✅ |
| `lean_pq_sig_attestation_verification_time_seconds` | Histogram | Time taken to verify an attestation signature | On each attestation signature verification | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | ✅ |
| `lean_pq_sig_aggregated_signatures_total` | Counter | Total number of aggregated signatures | On aggregated signature production | | | ✅ |
| `lean_pq_sig_aggregated_signatures_valid_total` | Counter | Total number of valid aggregated signatures | On aggregated signature verification | | | ✅ |
| `lean_pq_sig_aggregated_signatures_invalid_total` | Counter | Total number of invalid aggregated signatures | On aggregated signature verification | | | ✅ |
| `lean_pq_sig_attestations_in_aggregated_signatures_total` | Counter | Total number of attestations included into aggregated signatures | On aggregated signature production | | | ✅ |
| `lean_pq_sig_aggregated_signatures_building_time_seconds` | Histogram | Time taken to build an aggregated attestation signature | On aggregated signature production | | 0.1, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 4 | ✅ |
| `lean_pq_sig_aggregated_signatures_verification_time_seconds` | Histogram | Time taken to verify an aggregated attestation signature | On aggregated signature verification | | 0.1, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 4 | ✅ |

## Block Production Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_block_aggregated_payloads` | Histogram | Number of `aggregated_payloads` in a block | On block production | | 1, 2, 4, 8, 16, 32, 64, 128 | ✅ |
| `lean_block_building_payload_aggregation_time_seconds` | Histogram | Time taken to build `aggregated_payloads` during block building | On block production | | 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 | ✅ |
| `lean_block_building_time_seconds` | Histogram | Time taken to build a block | On block production | | 0.1, 0.25, 0.5, 0.75, 1, 2, 4, 8 | ✅ |
| `lean_block_building_success_total` | Counter | Successful block builds | On block production | | | ✅ |
| `lean_block_building_failures_total` | Counter | Failed block builds (error building the block, signing the block root, or processing it locally) | On block production failure | | | ✅ |
| `lean_block_proposal_attestation_build_phase_seconds` | Histogram | Phase-level time in block proposal: attestation selection, compaction, state transition, then the seal (proposer signature, type-1 wrap, type-2 merge) | On block production | phase=select_payloads,compact,stf_simulate,sign_proposer,wrap_proposer,merge_type2 | 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8 | ✅ |
| `lean_block_proposal_attestation_builds_total` | Counter | Attestations selected during block-proposal selection (one per selection-loop round that picks an `AttestationData`) | On each attestation selection | | | ✅ |
| `lean_block_proposal_child_payloads_consumed_total` | Counter | Child aggregated payloads selected during greedy proof picking (before compaction) | On block production | | | ✅ |
| `lean_block_proposal_attestation_data_selected` | Histogram | Distinct `AttestationData` entries in the proposal block body | On block production | | 0, 1, 2, 4, 8, 16, 32 | ✅ |
| `lean_block_proposal_aggregates_selected` | Histogram | Aggregated signature proofs in the proposal result after compaction | On block production | | 0, 1, 2, 4, 8, 16, 32, 64, 128 | ✅ |

> `lean_block_building_time_seconds` intentionally deviates from the leanMetrics bucket
> set, which tops out at 1s. Real builds on our devnets routinely run past that, so every
> sample landed in `+Inf` and `histogram_quantile` reported a flat 1s ceiling. The range
> now covers the same span as the `lean_block_proposal_attestation_build_phase_seconds`
> phases it contains.

## Fork-Choice Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_head_slot` | Gauge | Latest slot of the lean chain | On get fork choice head | | | ✅ |
| `lean_current_slot` | Gauge | Current slot of the lean chain | On scrape | | | ✅(*) |
| `lean_safe_target_slot` | Gauge | Safe target slot | On safe target update | | | ✅ |
|`lean_fork_choice_block_processing_time_seconds`| Histogram | Time taken to process block | On fork choice process block | | 0.005, 0.01, 0.025, 0.05, 0.1, 1, 1.25, 1.5, 2, 4 | ✅ |
|`lean_attestations_valid_total`| Counter | Total number of valid attestations | On validate attestation | | | ✅ |
|`lean_attestations_invalid_total`| Counter | Total number of invalid attestations | On validate attestation | | | ✅ |
|`lean_attestation_validation_time_seconds`| Histogram | Time taken to validate attestation | On validate attestation | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | ✅ |
| `lean_fork_choice_reorgs_total` | Counter | Total number of fork choice reorgs | On fork choice reorg | | | ✅ |
| `lean_fork_choice_reorg_depth` | Histogram | Depth of fork choice reorgs (in blocks) | On fork choice reorg | | 1, 2, 3, 5, 7, 10, 20, 30, 50, 100 | ✅ |
| `lean_tick_interval_duration_seconds` | Histogram | Elapsed time between clock ticks in seconds | At the start of each tick interval | | 0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6 | ✅ |
| `lean_gossip_signatures` | Gauge | Number of gossip signatures in fork-choice store | On gossip signatures update | | | ✅ |
| `lean_latest_new_aggregated_payloads` | Gauge | Number of new aggregated payload items | On `latest_new_aggregated_payloads` update | | | ✅ |
| `lean_latest_known_aggregated_payloads` | Gauge | Number of known aggregated payload items | On `latest_known_aggregated_payloads` update | | | ✅ |
| `lean_committee_signatures_aggregation_time_seconds` | Histogram | Time taken to aggregate committee signatures | On committee signatures aggregation | | 0.05, 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 | ✅ |
| `lean_node_sync_status` | Gauge | Node sync status | On node sync status change | status=idle,syncing,synced | | ✅ |

## State Transition Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_latest_justified_slot` | Gauge | Latest justified slot | On state transition | | | ✅ |
| `lean_latest_finalized_slot` | Gauge | Latest finalized slot | On state transition | | | ✅ |
| `lean_justified_slot` | Gauge | Current justified slot | On state transition | | | ❌ |
| `lean_finalized_slot` | Gauge | Current finalized slot | On state transition | | | ❌ |
| `lean_finalizations_total` | Counter | Total number of finalization attempts | On finalization attempt | result=success,error | | ✅ |
|`lean_state_transition_time_seconds`| Histogram | Time to process state transition | On state transition | | 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4 | ✅ |
|`lean_state_transition_slots_processed_total`| Counter | Total number of processed slots | On state transition process slots | | | ✅ |
|`lean_state_transition_slots_processing_time_seconds`| Histogram | Time taken to process slots | On state transition process slots | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | ✅ |
|`lean_state_transition_block_processing_time_seconds`| Histogram | Time taken to process block | On state transition process block | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | ✅ |
|`lean_state_transition_attestations_processed_total`| Counter | Total number of processed attestations | On state transition process attestations | | | ✅ |
|`lean_state_transition_attestations_processing_time_seconds`| Histogram | Time taken to process attestations | On state transition process attestations | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | ✅ |

## Validator Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
|`lean_validators_count`| Gauge | Number of validators managed by a node | On scrape |  | | ✅(*) |
|`lean_is_aggregator`| Gauge | Validator's `is_aggregator` status. True=1, False=0 | On node start | | | ✅ |
|`lean_attestations_production_time_seconds`| Histogram | Time taken to produce attestation | On attestation production | | 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1 | ✅ |

## Network Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Supported |
|--------|-------|-------|-------------------------|--------|-----------|
|`lean_attestation_committee_count`| Gauge | Number of attestation committees | On node start | | ✅ |
|`lean_attestation_committee_subnet`| Gauge | Node's attestation committee subnet | On node start | | ✅ |
|`lean_connected_peers`| Gauge | Number of connected peers | On scrape | client=ethlambda,grandine,lantern,lighthouse,qlean,ream,zeam | ✅(*) |
|`lean_gossip_mesh_peers`| Gauge | Number of peers in the gossipsub mesh | On scrape | client=`<name>_<N>`,unknown (ex. zeam_0) | ✅(*) |
|`lean_peer_connection_events_total`| Counter | Total number of peer connection events | On peer connection | direction=inbound,outbound<br>result=success,timeout,error | ✅ |
|`lean_peer_disconnection_events_total`| Counter | Total number of peer disconnection events | On peer disconnection | direction=inbound,outbound<br>reason=timeout,remote_close,local_close,error | ✅ |

## Custom Metrics (non-leanMetrics)

The metrics below are not part of the [leanMetrics specification](https://github.com/leanEthereum/leanMetrics/blob/2719baad8351c9ad5eaf3c8621f33fcec20a1dc7/metrics.md). They are ethlambda-specific observability around on-wire message sizes and post-quantum aggregated proof sizes.

### PQ Signature Sizes

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_aggregated_proof_size_bytes` | Histogram | Bytes size of an aggregated signature proof's `proof_data` field | On aggregated signature production | | 1024, 4096, 16384, 65536, 131072, 262144, 524288, 1048576 |

### Network Sizes

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_gossip_block_size_bytes` | Histogram | Bytes size of a gossip block message (raw SSZ or snappy on-wire) | On gossip block send/receive | compression=raw,snappy | 10000, 50000, 100000, 250000, 500000, 1000000, 2000000, 5000000 |
| `lean_gossip_attestation_size_bytes` | Histogram | Bytes size of a gossip attestation message (raw SSZ or snappy on-wire) | On gossip attestation send/receive | compression=raw,snappy | 512, 1024, 2048, 4096, 8192, 16384 |
| `lean_gossip_aggregation_size_bytes` | Histogram | Bytes size of a gossip aggregated attestation message (raw SSZ or snappy on-wire) | On gossip aggregation send/receive | compression=raw,snappy | 1024, 4096, 16384, 65536, 131072, 262144, 524288, 1048576 |
| `lean_reqresp_request_size_bytes` | Histogram | Bytes size of a req/resp request (raw SSZ or snappy on-wire) | On req/resp request send/receive | protocol=status,blocks_by_root<br>compression=raw,snappy | 64, 128, 256, 512, 1024, 4096, 16384, 65536 |
| `lean_reqresp_response_chunk_size_bytes` | Histogram | Bytes size of a single req/resp response chunk (raw SSZ or snappy on-wire) | On req/resp response chunk send/receive | protocol=status,blocks_by_root<br>compression=raw,snappy | 128, 1024, 10000, 100000, 500000, 1000000, 5000000, 10000000 |

### Peer Discovery

See [Peer discovery](./discovery.md), which is always on. Counts dials
discovery initiated, as opposed to
the static bootnode dials every node makes. Connection outcomes are not repeated
here: a discovery dial that succeeds or fails shows up in
`lean_peer_connection_events_total` like any other.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_discovered_peers_dialed_total` | Counter | Peers dialed as a result of discv5 discovery | On dialing a discovered peer | |

### Transport Mix

Which transport actually carried each established connection, read off the
connection's own multiaddr rather than off the address we dialed: libp2p races a
peer's QUIC and TCP addresses within one dial, so the answer is not knowable
before the connection exists. `tcp` counts are what say the fallback in
[Peer discovery](./discovery.md) is doing work rather than merely being
advertised.

Counts connections rather than peers, so it can exceed
`lean_peer_connection_events_total{result="success"}`, which fires only on a
peer's first connection. `unknown` covers a multiaddr naming neither transport,
which nothing ethlambda binds produces.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_peer_connections_by_transport_total` | Counter | Established peer connections by the transport that carried them | On connection established | direction=inbound,outbound<br>transport=quic,tcp,unknown |

### Peer Supply

Who this node is connected to, and whether those peers can serve what it needs.
All three are set from a full re-count of the state that decides them rather
than incremented and decremented per event: a gauge meant to reveal a leak must
not be able to leak itself.

`lean_peers_by_direction` read against `lean_swarm_established_connections` is
that leak check. The first counts peers this node believes it holds; the second
libp2p's own counters, which the connection limits in
[discovery.md](./discovery.md) are enforced against. A persistent gap is a
connection charged to the cap that no live peer is using.

`lean_custody_column_peers` is the supply side of the data-availability gate: a
fulu block is held until every column this node custodies arrives, so a column
sitting at zero connected custodians is a stall waiting to happen, and it is
invisible in a total peer count. Only the columns this node samples get a
series, since publishing all 128 would bury the ones that can actually block an
import. Read it beside `lean_blocks_held_for_columns`. Beacon-only; a lean node
samples nothing and publishes no series here.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_peers_by_direction` | Gauge | Connected peers by the direction the connection was opened in | On every connection established and closed | direction=inbound,outbound |
| `lean_swarm_established_connections` | Gauge | Established connections as libp2p itself counts them | On the swarm's own metric tick | direction=inbound,outbound |
| `lean_custody_column_peers` | Gauge | Connected peers known to custody each data column this node samples | On every connection established and closed, and whenever a peer's custody is recorded from its `metadata/3` answer or its ENR `cgc` | column=`<index>` |

### Block Import Timing

These record where a block's time goes between coming off the wire and having a post-state, which is the question `lean_fork_choice_block_processing_time_seconds` cannot answer: it starts inside `store::on_block`, so the mailbox hop, the holds, the head update and the per-table size estimates every import pays for all fall outside it. The sections here are the same ones the `Block import timing` log prints as a tree, and a test asserts the two lists stay identical.

One histogram carries every section, including `total` for a whole import and the sections an arrival is charged once for. They share a unit and a bucket set, and the query that matters is `rate(..._sum[5m])`, seconds spent per second, which does not divide by an event count and so does not care that some sections are counted per block and others per arrival. `lean_block_import_cascade_blocks` is what relates the two counts when you do need them.

`total` is written only when the block actually imported. A held block publishes every section it crossed and no total, because its import has not finished: that is what keeps a block that waited two slots for its parent out of the import-cost percentiles, and why there is no `outcome` label to filter on.

`parent_wait` and `columns_wait` are separate sections rather than one "pending", so a block held for its parent and a block held for its custody columns never collapse into the same number. An absent `columns_wait` still has two readings, and only the log separates them: its `da_complete_on_arrival` field says whether the columns were never missing, or landed while the block was held for its parent.

The bookkeeping an import triggers (chain-event emission, the finality eviction sweep, the gauge refresh including a RocksDB size estimate per table) has no section of its own. It is charged to the section it follows, which is `fc_head` on lean and `block_atts` on beacon. Those three were sections once: across 5248 imports on a mainnet follower none of them reached a millisecond, so they were three rows that never moved in every tree and three label values that never said anything. The work is still counted, just where it happens.

`decode` is a gossip-only section, so `queue` is the only one a fetched block crosses before the chain actor. The req/resp codec has already turned the bytes into a block before any handler sees one, leaving no decode boundary to take; the path reports nothing rather than a zero, since a zero reads as free work rather than as unmeasured work and would drag the decode histogram down with samples that measured nothing. Two consequences: `decode` is a gossip population even though the `source` label allows `sync`, and a fetched block's `total` starts later in its life than a gossiped block's, having never counted the request round trip at all.

`engine` and `fcu` are execution-client round trips. They are I/O waits rather than work, so a node whose import time is dominated by them is waiting on its execution client, not spending CPU.

The `source` label has two values, `gossip` and `sync` (req/resp backfill). Two populations are deliberately absent. A block re-delivered to itself because its slot had not started reports under the source it first arrived on, since the hold is already visible as its `defer` section and a third label value would take the block out of the population it belongs to for every section it has left. A block this node built itself is not measured at all: it crossed no wire, so it has no `decode` and an empty `queue` taken when the import began. Both still appear in the log, which names them `deferred` and `local`.

Series appear as blocks arrive rather than being seeded, since a third of the phases are beacon-only and a lean node can never write to them.

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_block_import_phase_seconds` | Histogram | Time one section of a block's import, or of the arrival carrying it, took | Per section that ran, on each import, hold or failure | phase (see below); source=gossip,sync | 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1, 1.5, 2, 3, 4, 6, 8, 12, 16, 32 |
| `lean_block_import_cascade_blocks` | Histogram | Blocks one arrival put through the import path (attempts, so a block that ends held or pended counts) | Once per arriving block message | | 1, 2, 3, 5, 8, 16, 32, 64, 128 |

Per-block phases, in the order a block crosses them, plus `total` for a completed import:

| Phase | What it covers | Chain |
|-------|----------------|-------|
| `decode` | Snappy decompression, SSZ decode and the root the p2p handler computes. Gossip only; see above | both |
| `queue` | The wait in the chain actor's mailbox | both |
| `defer` | Held because the block's own slot had not started yet | beacon |
| `guards` | Finality and future-slot checks, the already-imported check, the parent-state lookup | both |
| `preamble` | The checks `store::on_block` makes before verifying: parent state load, duplicate attestation data scan | lean |
| `parent_wait` | Held because the parent had no post-state | both |
| `cascade_wait` | Between the parent's import finishing and this block being popped off the cascade queue | both |
| `da_check` | The custody-column availability check itself, not the wait | beacon |
| `columns_wait` | Held because custody columns had not all arrived | beacon |
| `engine` | The `engine_newPayload` round trip, including its retry ladder | beacon |
| `verify_struct` | Participant bounds checks and pubkey resolution | lean |
| `verify_crypto` | The leanVM multi-message aggregate verification | lean |
| `stf` | The state transition. On beacon this bundles the transition, the state root and the state write | both |
| `db_write` | The block and post-state writes | lean |
| `fc_head` | `update_head` | lean |
| `block_atts` | Replaying the block's own attestations and slashings into fork choice | beacon |
| `total` | The whole import, wire to post-state, spanning any holds. Only on a completed import | both |

Per-arrival phases, charged once per arriving message however many blocks its cascade imported:

| Phase | What it covers |
|-------|----------------|
| `arrival` | The whole handler call: the cascade plus everything after it |
| `cascade` | The block drain alone |
| `prune` | `prune_old_data` after the cascade (lean) |
| `get_head` | `fork_choice::get_head` (beacon) |
| `fcu` | The `engine_forkchoiceUpdated` round trip (beacon) |

### Gossip Arrival Timing

These histograms record the absolute distance between a gossip message's arrival and the start of the interval it was due in, so an arrival that is early by some amount and one that is late by the same amount land in the same bucket; the counters' `position` label is what tells them apart. `inside` means the message arrived within the interval it was due in, not merely somewhere in the right slot: an attestation for slot 10 that lands during slot 10's interval 2 is `after`, not `inside`, since it missed the AttestationProduction interval it was actually due in.

The bucket boundaries are the interval and slot edges of the default 4-second cadence. Prometheus fixes buckets when a histogram is registered, so a network that sets `MILLISECONDS_PER_SLOT` reads these histograms against the default grid rather than its own; the `position` label still follows the configured interval width.

Blocks anchor to interval 0 of their own slot and attestations to interval 1 of their data slot; both are unbounded above, so a message that never arrives close to real time can be arbitrarily late. Aggregates anchor instead to the most recent aggregation-interval boundary rather than their own data slot, since a stale-group catch-up aggregate can carry a `data.slot` several slots in the past; anchoring to the latest boundary bounds the delay to one slot and rules out `before` entirely.

Only gossip-received blocks are sampled here: blocks fetched via req/resp during sync are excluded, since sync backfill delivers blocks long after they were due and would swamp these histograms with catch-up noise rather than gossip-health signal.

The aggregate metrics do include an aggregator's own freshly produced aggregates, which never come back over gossip; without them an aggregator would report an empty aggregate profile. The two populations are not quite the same measurement: delivery of a locally produced aggregate is held until the interval-2 boundary, so it lands near zero unless proving overran the interval, whereas a received one adds propagation on top of whenever the producer managed to publish it.

In practice the distribution is bimodal and dominated by production rather than propagation: a mode in the lowest bucket for aggregates that made their interval, plus a tail for those whose proving overran it. A late aggregate is late for every node at once, so that tail shows up on receivers too and is not evidence of a slow network. Read a rising tail as aggregation cost, and cross-check `lean_pq_sig_aggregated_signatures_building_time_seconds` and `lean_committee_signatures_aggregation_time_seconds` to confirm.

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_gossip_block_arrival_delay_seconds` | Histogram | Absolute delay between a gossip block's arrival and the start of the interval it was due in | On gossip block receipt, before import | | 0.05, 0.1, 0.2, 0.4, 0.8, 1.2, 1.6, 2.4, 4, 8, 16 |
| `lean_gossip_attestation_arrival_delay_seconds` | Histogram | Absolute delay between a gossip attestation's arrival and the start of the interval it was due in | On gossip attestation receipt | | 0.05, 0.1, 0.2, 0.4, 0.8, 1.2, 1.6, 2.4, 4, 8, 16 |
| `lean_gossip_aggregation_arrival_delay_seconds` | Histogram | Absolute delay between an aggregate becoming available (gossip receipt, or local production) and the most recent aggregation-interval boundary at or before it | On gossip aggregated-attestation receipt, or on local aggregate production | | 0.05, 0.1, 0.2, 0.4, 0.8, 1.2, 1.6, 2.4, 4, 8, 16 |
| `lean_gossip_block_arrival_total` | Counter | Gossip blocks by arrival position relative to the interval they were due in | On gossip block receipt, before import | position=before,inside,after | |
| `lean_gossip_attestation_arrival_total` | Counter | Gossip attestations by arrival position relative to the interval they were due in | On gossip attestation receipt | position=before,inside,after | |
| `lean_gossip_aggregation_arrival_total` | Counter | Aggregates by arrival position relative to the most recent aggregation-interval boundary | On gossip aggregated-attestation receipt, or on local aggregate production | position=inside,after | |

### Storage

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_table_bytes` | Gauge | Estimated byte size of a storage table (key + value bytes) | After each processed block (one update per table); retains its previous value on empty slots | table=`<table_name>` |

**On a beacon follower, watch `lean_table_bytes{table="data_columns"}`.** Every
other table's series either stays flat or is bounded by pruning; `data_columns`
backs `Table::DataColumns`, the one table with no pruning rule (see
[data_storage.md](./data_storage.md#datacolumns)), so this is the disk-growth
trajectory for the whole node. Budget roughly 360 KB per slot across the
columns this node custodies at the blob cap, nearer 1 GB per day at current
mainnet blob counts, and size the disk against however long the node is meant
to run before a pruner exists.

### Data Column Sidecars (Fulu DAS)

`ethlambda beacon` is a fulu data-availability-sampling custodian: it derives
a slice of the column matrix from its own discv5 node id (see
[beacon_wire.md](./beacon_wire.md#data-column-sidecars)), verifies what gossip
and req/resp deliver for that slice, stores what verifies, serves it back to
peers, and refuses to import a fulu block until every column it owes for that
block is on hand. These are ethlambda-specific, not part of the leanMetrics
spec.

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_data_columns_stored_total` | Counter | Data column sidecars verified and written to `Table::DataColumns` | On a gossiped or fetched sidecar clearing every check in `on_gossip_data_column` | | |
| `lean_data_columns_rejected_total` | Counter | Sidecars the chain actor dropped, by reason | On each rejection in `on_gossip_data_column` | reason=malformed,finalized,future,finalized_ancestor,inclusion_proof,kzg,proposer | |
| `lean_data_column_kzg_verify_seconds` | Histogram | Time spent batch-verifying one sidecar's cells against its own commitments | On each KZG batch verification | | 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0 |
| `lean_data_column_fetch_failures_total` | Counter | `DataColumnsByRoot` lookups this node gave up on, by reason | On lookup abandonment | reason=no_peers,max_retries | |
| `lean_blocks_held_for_columns` | Gauge | Blocks held out of fork choice pending their custody columns | On every hold, release, and finality eviction of the held-block set | | |
| `lean_sidecars_awaiting_parent` | Gauge | Sidecars parked until their block's parent has a post-state | On every park, replay, and finality eviction of the parked set | | |

`lean_data_columns_rejected_total`'s reasons are the chain actor's own, one
layer past gossip's cheaper checks. A malformed, wrong-subnet, stale, future,
or duplicate sidecar is usually caught one layer down, in gossip, and shows up
instead as `lean_beacon_gossip_messages_total{topic="data_column_sidecar",
result=...}`; `reason="malformed"` on this counter therefore fires almost
exclusively for a *fetched* sidecar, which skips gossip's checks entirely and
reaches the chain actor first.

**Watch `lean_blocks_held_for_columns`.** It is the first symptom of a stalled
availability gate, and a healthy node returns it to zero within a slot or two
of a hold: fetch or gossip should complete well inside the retry ladder
`lean_data_column_fetch_failures_total` counts down. A gauge that sits above
zero for several slots means either the fetch is failing — check whether
`lean_data_column_fetch_failures_total`'s `no_peers` or `max_retries` reason
is climbing — or no reachable peer actually serves the missing columns; short
of that, only finality passing the held block's slot clears it, which can be
minutes away.

**Read `lean_sidecars_awaiting_parent` beside it.** A sidecar whose block's
parent has no post-state yet is parked rather than dropped, and a held block is
precisely a block with no post-state, so the two gauges rise together while the
gate waits: held blocks on one, their children's columns on the other. Both
returning to zero is a recovered hold. `lean_sidecars_awaiting_parent` climbing
without coming back down while `lean_blocks_held_for_columns` stays above zero
is the signature of a gate that is not recovering. The parked queue is
uncapped, so that gauge is also the only warning that a peer is parking
sidecars under parents it never means to supply: each one holds a
`Table::PendingDataColumns` row until finality passes its slot.

### Attestation Aggregate Coverage

Observability into how many validators/subnets are covered by the attestations the node has aggregated, broken down by pipeline section (the `section` label). The slot is the X-axis. These are sampled roughly once per slot, but emission is gated by the section's source data, so a gauge can retain its previous value:

- `timely`, `late`, `block`, `combined` and the `diff_validators` directions are emitted on block import, and **only when the canonical head block carries that round's votes** (otherwise the round is skipped and prior values are kept).
- `agg_start_new` is emitted at interval 2, right before fork-choice aggregation runs.
- `proposal_combined` is emitted only when this node proposes a block.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_attestation_aggregate_coverage_validators` | Gauge | Validator coverage in attestation aggregate reports | Per round, per section (see note above) | section=timely,late,block,combined,agg_start_new,proposal_combined<br>subnet=combined,subnet_0,subnet_1,…,subnet_N-1 |
| `lean_attestation_aggregate_coverage_subnets` | Gauge | Number of covered subnets in attestation aggregate reports | Per round, per section (see note above) | section=timely,late,block,combined,agg_start_new,proposal_combined |
| `lean_attestation_aggregate_coverage_diff_validators` | Gauge | Validators in the symmetric difference between block-included aggregates and locally-aggregated timely aggregates for the same slot | On block import, when the head carries the round's votes (see note above) | direction=block_only,timely_only |

---

✅(*) **Partial support**: These metrics are implemented but not collected "on scrape" as the spec requires. They are updated on specific events (e.g., on tick, on block processing) rather than being computed fresh on each Prometheus scrape.

## Troubleshooting

### Docker Desktop on MacOS

lean-quickstart uses the host network mode for Docker containers, which is a problem on MacOS.
To work around this, enable the ["Enable host networking" option](https://docs.docker.com/enterprise/security/hardened-desktop/settings-management/settings-reference/#enable-host-networking) in Docker Desktop settings under Resources > Network.
