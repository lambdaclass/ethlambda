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
|`lean_aggregation_window_width`| Histogram | Width in subnets of the subnet window derived for one aggregation candidate | On each aggregation candidate | | ✅ |
|`lean_aggregation_skipped_redundant_total`| Counter | Candidates this aggregator sat out because the redundancy-skipping rotation gave their level to another duty subnet | On each skipped aggregation candidate | | ✅ |
|`lean_aggregation_window_fallback_total`| Counter | Merges the subnet window would have dropped, recovered by retrying selection at the full committee set | On each aggregation candidate the full-width retry recovers | | ✅ |
|`lean_connected_peers`| Gauge | Number of connected peers | On scrape | client=ethlambda,grandine,lantern,lighthouse,qlean,ream,zeam | ✅(*) |
|`lean_gossip_mesh_peers`| Gauge | Number of peers in the gossipsub mesh | On scrape | client=`<name>_<N>`,unknown (ex. zeam_0) | ✅(*) |
|`lean_peer_connection_events_total`| Counter | Total number of peer connection events | On peer connection | direction=inbound,outbound<br>result=success,timeout,error | ✅ |
|`lean_peer_disconnection_events_total`| Counter | Total number of peer disconnection events | On peer disconnection | direction=inbound,outbound<br>reason=timeout,remote_close,local_close,error | ✅ |

> All three are emitted only by aggregators, once per candidate `AttestationData` per interval-2 session. `lean_aggregation_window_width` has buckets 1, 2, 4, 8, 16, 32, 64 and climbs from 1 as the aggregator's anchor proof climbs the reduction tree; it is capped at `lean_attestation_committee_count`, so samples pinned there mean the window no longer restricts selection. Compare against that gauge rather than reading the buckets alone: at a committee count that is not a power of two, two different widths can share a bucket. A width stuck at 1 while the network is aggregating means the pool holds nothing on this node's duty subnet, so it is only aggregating its own raw signatures; check the duty subnet against the aggregator placement. `lean_aggregation_skipped_redundant_total` only increments with `--skip-redundant-aggregation`, once per candidate handed to another duty subnet; read it against `lean_aggregation_window_width_count` for the share of candidates sat out. `lean_aggregation_window_fallback_total` counts recoveries, not attempts: it increments only when a windowed selection produced no viable job and the full-committee-width retry did. Candidates that are non-viable whatever the window, a lone raw signature or a group with a single proof, never reach the retry and never increment it, so a sparse (strided) aggregator placement across subnets is the only expected cause and the counter should stay at or near zero on a well-tiled deployment. It stays flat entirely under `--skip-redundant-aggregation`, which disables the fallback.

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

See [Peer discovery](./discovery.md), which is always on for `beacon` and
opt-in (`--discovery.enable`) for `node`. Counts dials
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

### Why Peers Leave

`lean_peer_disconnection_events_total` above is leanMetrics-specified down to
its `reason` values, and those four cannot carry this: measured on the mainnet
follower, 92% of outbound closes land in `error`, which says only that libp2p
handed back a cause. These two split that bucket without widening the specified
metric, the same way the transport counter above sits beside the specified
connect counter rather than inside it.

`lean_peer_goodbye_total` is the only one of the three that is not an
inference. A `goodbye` is the peer stating why it is dropping us, and the two
readings that matter are indistinguishable from the socket alone:
`too_many_peers` means the peer had no room, while `bad_score`, `banned` and
`banned_ip` mean it decided against *this node*, and those call for opposite
responses. It has no `direction` label because `goodbye/1` is registered
inbound-only; ethlambda never sends one. The reason is a `u64` off the wire, so
the labels are a fixed set with `other` as the residue: a remote must not be
able to choose this node's metric cardinality.

`lean_peer_disconnect_cause_total` covers the closes that carry no `goodbye`,
read off the `ConnectionError` variant and the error types inside it. It is
charged on the same event as the specified counter, once per peer fully
disconnecting rather than once per connection, so the two total to the same
number and can be read against each other directly. `clean_close` is libp2p
reporting no error at all, which for a beacon peer is the ordinary shape of a
deliberate disconnect and should be read beside `lean_peer_goodbye_total`.

An I/O close almost always arrives as `ErrorKind::Other` with the muxer's own
error inside, so the label comes from that inner error. The `quic_*` values
are QUIC's close reasons: `quic_application_close` is the peer's application
closing (libp2p's normal close after a `goodbye`, and go-libp2p's connection
gater), `quic_transport_close` a transport-level close. TCP closes resolve to
the socket error beneath the muxer where there is one (`unexpected_eof`,
`connection_reset`), otherwise `yamux_closed` for a clean yamux shutdown.
`io_other` is the residue and should stay near empty; the `Peer connection
closed` line at `DEBUG` prints the full cause for whatever lands there.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_peer_goodbye_total` | Counter | Goodbye messages received, by the reason code the peer sent | On receiving a `goodbye/1` | reason=unknown,client_shutdown,irrelevant_network,fault,unable_to_verify_network,too_many_peers,bad_score,banned,banned_ip,other |
| `lean_peer_disconnect_cause_total` | Counter | Closed peer connections by the cause libp2p reported for the close | On a peer's last connection closing | direction=inbound,outbound<br>cause=clean_close,keep_alive_timeout,connection_reset,connection_aborted,broken_pipe,not_connected,timed_out,unexpected_eof,quic_application_close,quic_transport_close,quic_reset,quic_timed_out,quic_local_close,quic_other,yamux_closed,yamux_other,mplex_other,io_other |

Reason codes 1, 2 and 3 are the only ones
[the spec](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md)
names; it reserves `[4, 127]` and leaves 128 and up to each client. The four
above 127 follow lighthouse's `GoodbyeReason`, which is what mainnet peers
actually send.

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

On the beacon wire, `decode` for `source="gossip"` spans more than its name says. `BlockArrival::decode_start` is still the wire arrival, but `handed_off` is stamped only once the block has a gossip verdict, so the section also covers the cheap, stateless checks, the stateful check's own `spawn_blocking` task, and the verdict's trip back through the p2p actor's mailbox. There is no wait for a free validation slot to attribute here either: `try_acquire_owned` never blocks, and a message arriving with none free is reported `Ignore(Overloaded)` (and still forwarded to the chain actor) rather than queued. A rising `decode` on the beacon wire alone therefore does not mean decoding got slower; check `lean_beacon_gossip_validation_seconds` before assuming so.

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
| `decode` | Snappy decompression, SSZ decode and the root the p2p handler computes; on the beacon wire this also spans gossip validation. Gossip only; see above | both |
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
| `db_write` | The block write and handing the post-state off to the storage crate's background writer; the state's own encode/diff/commit cost is `lean_state_write_seconds` instead, not this row | lean |
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
| `lean_state_write_queue_depth` | Gauge | States handed to the background writer but not yet committed | On every hand-off and on every commit | |
| `lean_state_write_seconds` | Histogram | Time the background writer spends encoding, diffing and committing one state | Per state written | |

**On a beacon follower, watch `lean_table_bytes{table="data_columns"}`.** Every
other table's series either stays flat or is bounded by pruning; `data_columns`
backs `Table::DataColumns`, the one table with no pruning rule (see
[data_storage.md](./data_storage.md#datacolumns)), so this is the disk-growth
trajectory for the whole node. Budget roughly 360 KB per slot across the
columns this node custodies at the blob cap, nearer 1 GB per day at current
mainnet blob counts, and size the disk against however long the node is meant
to run before a pruner exists.

**`lean_state_write_queue_depth` is the early warning for a slow disk.** Up to
three states can be in flight without the importer ever blocking — two queued
plus the one the writer thread is currently encoding, diffing and committing —
so a depth resting at or below three is healthy overlap. A depth climbing past
three means `insert_state` blocked on the full channel waiting for the writer,
and `lean_state_write_seconds` says whether that time went into the encode or
the commit. A depth that stays at zero means the writer has nothing
outstanding.

### Beacon Gossip Validation

Every beacon gossip message gets a verdict before gossipsub forwards it
(`validate_messages()` is on for the beacon wire only), `beacon_aggregate_and_proof`
and `beacon_attestation_{subnet_id}` included: both are validated the same way
blocks and columns are, in `ethlambda_state_transition::beacon::gossip::{aggregate,attestation}`.
See [beacon_wire.md](./beacon_wire.md#gossip) for the flow and
[beacon_wire.md](./beacon_wire.md#aggregate-attestations) for the two topics'
own section. These are ethlambda-specific, not part of the leanMetrics spec.

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_beacon_gossip_validation_total` | Counter | Verdicts, by topic kind, outcome and reason | On every verdict reported to gossipsub | kind, outcome=accept,queue,ignore,reject, reason | |
| `lean_beacon_gossip_validation_seconds` | Histogram | Time from a message's arrival to its verdict | On every verdict reported to gossipsub | kind | 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8 |
| `lean_beacon_gossip_verdict_expired_total` | Counter | Verdicts that arrived after gossipsub evicted the message, so an Accept propagated nothing | When `report_message_validation_result` returns `false` | kind | |

`kind` is the topic kind, with every `data_column_sidecar_{subnet}` sharing the
label `data_column_sidecar` and every `beacon_attestation_{subnet_id}` sharing
`beacon_attestation`. The gloas topics `execution_payload` and
`payload_attestation_message` are labelled by their own name. `queue` means
IGNORE to gossipsub while the chain actor still receives the object and parks
it; of the gloas topics only `execution_payload` answers it, for an envelope
whose block is not known yet (`block_unknown`), has no post-state yet
(`block_not_ready`), or has one that is not in the cache the checks read
(`state_not_cached`, as when the block was imported moments ago; the actor
verifies the signature itself, so the envelope is forwarded rather than dropped). The aggregate, attestation and
`payload_attestation_message` topics never answer `queue`, since the vote
block's post-state is either cached or it is not
(`IgnoreReason::UnknownBlock`/`StateUnavailable`), with nothing to hold the
message for. **`verdict_expired_total` should stay at
zero**: a rising count means validation is too slow for gossipsub's message
cache.

The two topics add reasons the others do not, all `reason` label values on
`lean_beacon_gossip_validation_total`: `outside_epoch_window`, `covered_bits`
(aggregate only), `unknown_block`, `state_unavailable`,
`finalized_not_ancestor`, `ancestry_unknown`, `payload_envelope_unseen` and
`payload_optimistic` (gloas only) on the ignore side;
`epoch_mismatch`, `no_participants` (aggregate only), `non_zero_data_index`,
`committee_bits` (aggregate only), `committee_index`, `bits_length` (aggregate
only), `not_aggregator` (aggregate only), `not_in_committee`,
`unknown_validator`, `selection_proof` (aggregate only),
`aggregator_signature` (aggregate only), `aggregate_signature` (aggregate
only), `target_not_ancestor`, `wrong_subnet` (attestation only), and gloas's
`data_index_out_of_range`, `same_slot_payload_flag` and `payload_invalid` on the
reject side. `already_seen`, `overloaded` and `unsupported_fork` are shared with the
other topics: `unsupported_fork` is an ignore reason for a message of a fork this
build has no gossip rules for, so an honest peer past the fork epoch is not
scored as a bad decoder. Gloas blocks, data columns, aggregates and attestations
are validated, so they carry their own verdict reasons instead.

Two permit pools bound the blocking-thread half of validation:
`gossip_validation_permits` for blocks and columns,
`attestation_validation_permits` for aggregates and subnet attestations. They
are deliberately separate: a mainnet slot's worth of aggregates and backbone
attestations arrives every slot, not only during a range sync, and sharing one
pool would let that burst answer `Ignore(Overloaded)` for a block or a column
instead. Neither pool has a metric of its own yet; a permit exhausted on
either shows up as `outcome="ignore",reason="overloaded"` on
`lean_beacon_gossip_validation_total`, for the topics that draw from it.

### Beacon Committee Cache

`ethlambda beacon` derives an epoch's attester committees with one whole-epoch
shuffle and keeps the result in `CommitteeCache`, keyed by epoch and the block
that decided the shuffling. The cache itself lives in the `Store`
(`crates/storage/src/committee_cache.rs`), shared by both actors: the chain
actor's own attestation processing and p2p's gossip validation for
`beacon_aggregate_and_proof`/`beacon_attestation_{subnet_id}` read the same
entries rather than each keeping a copy, which is what lets a validation task
and the actor race a shuffle at an epoch boundary and have only the first one
pay for it. `CommitteeCacheExt` in
`crates/blockchain/state_transition/src/beacon/helpers/accessors.rs` is the
consensus-logic wrapper (`ShufflingKey` derivation, the shuffle itself) around
the storage-side container. This is ethlambda-specific, not part of the
leanMetrics spec.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_beacon_committee_cache_lookups_total` | Counter | Committee lookups, by whether the cache served them | On every `CommitteeCacheExt::committees` call: the state transition's, fork choice's and p2p's gossip validation's attestation processing | result=hit,miss,unkeyable |

**Read the miss rate against the epoch rate, not the hit rate.** A follower on
one chain misses about once per epoch, when the first block of a new epoch asks
for that epoch's shuffling, and hits on everything else. Misses that track
imports instead mean entries are being evicted and rebuilt, which happens when
more branches are being imported at once than the cache has room for; each miss
is a registry scan plus a whole-epoch shuffle on the import thread. `unkeyable`
is a lookup the cache could not key at all, mostly the genesis state asking
about its own first epochs, and should be zero on a checkpoint-synced follower.

### Beacon Justified Balances

Beacon fork choice weighs every vote by the voter's effective balance at the
justified checkpoint. `justified_balances` (in
`crates/blockchain/state_transition/src/beacon/fork_choice.rs`) flattens that
state into one array, keyed by the justified checkpoint and rebuilt on the first
`get_head` after the checkpoint moves. This is ethlambda-specific, not part of
the leanMetrics spec.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_beacon_justified_balances_lookups_total` | Counter | Snapshot lookups, by whether the cached snapshot served them | On every `justified_balances` call: `get_head`'s weights, the proposer boost, and the reorg helpers | result=hit,miss |
| `lean_beacon_justified_balances_build_seconds` | Histogram | Time to build one snapshot from the checkpoint state | On every miss, around the registry pass (the checkpoint state lookup is not included) | |

**Read the miss rate against the justified-checkpoint rate**: about one miss
per justified checkpoint change, so a handful per hour on a healthy chain.
Misses that track `get_head` calls mean the justified checkpoint is flapping
between branches, or the snapshot is being replaced between two readers.

### Beacon Epoch Precompute

The beacon chain actor advances the head state across the next epoch boundary
ahead of time, so the first block of an epoch does not run `process_epoch` on
the import path. See "Epoch-transition precompute" in
[`beacon_stf.md`](beacon_stf.md). This is ethlambda-specific, not part of the
leanMetrics spec.

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_beacon_epoch_precompute_lookups_total` | Counter | Epoch-crossing imports, by whether a precomputed boundary state was cached | On each import whose parent is before the block's epoch start and whose block is at or after it | result=hit,miss | |
| `lean_beacon_epoch_precompute_seconds` | Histogram | Worker time to advance, flush and hash one state | When a precompute worker finishes | | 0.1, 0.25, 0.5, 0.75, 1, 1.5, 2, 3, 4, 8 |
| `lean_beacon_epoch_precompute_started_total` | Counter | Workers started, by trigger | When a worker is spawned | trigger=head,timer | |

**Read the hit ratio against epochs.** On a synced follower nearly every
epoch-crossing import should hit. Misses mean the worker had not finished (the
block raced it, see `lean_beacon_epoch_precompute_seconds` against the slot
duration), the node was syncing, or the entry was evicted from the state cache.
A `timer` start with no matching `head` start means the last slot was skipped.

### Beacon Pubkey Cache

Every BLS signature check `ethlambda beacon` runs (block import, fork choice,
gossip validation) resolves its signers' compressed public keys to validated
curve points through one process-wide cache, keyed by the compressed bytes. See
`PubkeyCache` in `crates/blockchain/state_transition/src/beacon/bls.rs`. This is
ethlambda-specific, not part of the leanMetrics spec.

| Name | Type | Usage | Sample collection event | Labels |
|------|------|-------|-------------------------|--------|
| `lean_beacon_pubkey_cache_lookups_total` | Counter | Public keys resolved for a signature check, by whether the cache already held them | Once per signature check, counting every signer | result=hit,miss |
| `lean_beacon_pubkey_cache_entries` | Gauge | Validated public keys the cache holds | On each key added; the cache never removes one | |

**Misses should fall to near zero within an epoch of a start**, once every
active validator has signed something the node checked. A steady miss rate
after that means keys the cache is refusing to hold: either the entry bound is
reached (the gauge stops rising), or the keys are invalid, which are never
cached and pay the full check every time. `entries` is also the cache's memory
footprint, roughly a decompressed point plus its compressed key per entry.

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
| `lean_data_columns_stored_total` | Counter | Data column sidecars verified and written to `Table::DataColumns` | On the chain actor storing a sidecar the p2p layer verified | | |
| `lean_data_columns_rejected_total` | Counter | Sidecars the p2p layer's chain checks dropped, by reason | On each drop in `beacon::column_checks`, except an already stored sidecar | reason=malformed,future_slot,finalized,not_after_parent,unknown_proposer,bad_signature,wrong_proposer,finalized_not_ancestor,parent_not_ready,inclusion_proof,kzg,internal | |
| `lean_data_column_kzg_verify_seconds` | Histogram | Time spent batch-verifying one sidecar's cells against its own commitments | On each KZG batch verification, in gossip validation or the chain checks | | 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0 |
| `lean_data_column_fetch_failures_total` | Counter | `DataColumnsByRoot` lookups this node gave up on, by reason | On lookup abandonment | reason=no_peers,max_retries | |
| `lean_blocks_held_for_columns` | Gauge | Blocks held out of fork choice pending their custody columns | On every hold, release, and finality eviction of the held-block set | | |
| `lean_sidecars_awaiting_parent` | Gauge | Sidecars parked until their block's parent has a post-state | On every park, replay, and finality eviction of the parked set | | |
| `lean_envelopes_awaiting_block` | Gauge | Gloas execution payload envelopes held until their block is imported | On every hold, release, and finality eviction of the held envelopes | | |
| `lean_envelopes_awaiting_columns` | Gauge | Gloas execution payload envelopes held until every sampled column is stored | On every hold, release, and finality eviction of the held envelopes | | |
| `lean_blocks_awaiting_parent_payload` | Gauge | Gloas blocks held until their FULL parent's payload envelope is verified | On every hold, release, and finality eviction of the held blocks | | |

`lean_data_columns_rejected_total` counts the chain checks, which run in the
p2p layer on every sidecar gossip did not accept: every fetched sidecar, a
gossiped one reported `Queue` or `Ignore(Overloaded)`, and a parked one sent
back once its parent imported. A gossiped sidecar is judged first by the
gossip rules and counted in
`lean_beacon_gossip_validation_total{kind="data_column_sidecar"}`; the reasons
here are that counter's reason labels. The chain actor stores what reaches it
without checking it again.

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

### Beacon Aggregate Attestations

`ethlambda beacon` applies `beacon_aggregate_and_proof` to fork choice, which is
how it sees votes for the current head rather than only the votes a block body
carries (see
[beacon_wire.md](./beacon_wire.md#aggregate-attestations)). These are
ethlambda-specific, not part of the leanMetrics spec, and lean nodes never emit
them.

| Name | Type | Usage | Sample collection event | Labels | Buckets |
|------|------|-------|-------------------------|--------|---------|
| `lean_beacon_aggregate_decode_seconds` | Histogram | Time the p2p actor spent decoding one aggregate off the wire | On each successful decode in the gossip handler | | 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05 |
| `lean_beacon_aggregate_mailbox_wait_seconds` | Histogram | Time an already-verified aggregate spent in the chain actor's mailbox | On the chain actor taking one off the mailbox | | 0.0005 … 2.5 |
| `lean_beacon_aggregate_processing_seconds` | Histogram | Time the chain actor spent applying one already-verified aggregate (`apply_verified_aggregate` plus the applied-bits gate) | On each aggregate the actor processed, applied or not | | 0.0005 … 2.5 |
| `lean_beacon_aggregate_end_to_end_seconds` | Histogram | Wire to fork choice, for aggregates applied on arrival | On applying an aggregate that was not deferred | | 0.0005 … 2.5 |
| `lean_beacon_aggregate_total` | Counter | Aggregates by outcome | On each aggregate reaching a verdict | outcome=applied,invalid,known_subset,queue_full | |
| `lean_beacon_aggregates_deferred` | Gauge | Aggregates held until their own slot has passed | On every defer and every per-slot drain | | |

`decode` is the only one of the four histograms still timing what it always
did. The other three no longer include gossip validation: committees, all
three signature checks and the specification's own seen sets moved to p2p
(`lean_beacon_gossip_validation_seconds{kind="beacon_aggregate_and_proof"}`
covers that half now), so `processing` and `end_to_end` read a great deal
lower than before this change, and a comparison against an older deployment's
values is comparing two different things. What is left for these three to
measure is real, though: `validate_on_attestation_indexed` and the applied-bits
gate still cost a `Table::LiveChain` scan and a hash-map lookup per aggregate,
so a slow chain-actor number still points at the store rather than at
cryptography.

**Watch `lean_beacon_aggregate_mailbox_wait_seconds`.** It is the failure mode
this path introduces and the one no other timing can show: a mainnet slot
carries up to `MAX_COMMITTEES_PER_SLOT * TARGET_AGGREGATORS_PER_COMMITTEE`
aggregates, and if they queue behind block imports their votes arrive too late
to move the head while every per-aggregate timing still looks healthy.

**Read `lean_beacon_aggregate_total{outcome}` as a ratio, not a rate.**
`known_subset` is the actor's own applied-bits gate now, not the specification's
seen set (that one is p2p's, and a duplicate or already-covered aggregate is
refused there, under `lean_beacon_gossip_validation_total`, before it ever
reaches this counter). `known_subset` dominating is still the design working:
a committee's aggregators mostly converge on the same votes, and each one the
running union already covers is dropped before another
`apply_verified_aggregate` call. `applied` falling toward zero while
`known_subset` stays high means the node is seeing only aggregates it has
already covered, which is normal; `invalid` climbing means aggregates gossip
already accepted are failing `apply_verified_aggregate` regardless, most often
because this node has not imported the block being voted for, or has since
finalized past its target.

**`queue_full` should be zero.** The deferral queue holds two slots' worth, and
reaching its cap means aggregates are arriving faster than the once-per-slot
drain clears them. Read it beside `lean_beacon_aggregates_deferred`, which sits
near one slot's worth in the steady state and near the cap when the drain is
falling behind.

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

## Validator client

Served by `ethlambda validator` on its own `--metrics-port`, separate from the
node's. Prefixed `ethlambda_validator_` rather than `lean_`, because this
process follows the beacon chain and a `lean_` series here would be misleading
on a shared dashboard.

Every series is registered at startup rather than on first use, so each reads
zero from the moment the process is up. That matters for alerting: a rule on
"attestations stopped" cannot fire against a series that does not exist yet,
and absent is not the same as zero.

| Metric | Type | Description |
|---|---|---|
| `ethlambda_validator_validators_loaded` | Gauge | Validator keys loaded from the keystores |
| `ethlambda_validator_validators_resolved` | Gauge | Loaded keys that have an index on chain, out of `validators_loaded`. A persistent gap means validators are deposited but not yet activated |
| `ethlambda_validator_duties_held` | Gauge | Attester duties currently scheduled |
| `ethlambda_validator_attestations_published_total` | Counter | Attestations a beacon node accepted |
| `ethlambda_validator_attestation_failures_total` | Counter | Slots whose attestation duty failed and returned |
| `ethlambda_validator_attestation_deadline_missed_total` | Counter | Slots whose duty never returned in time and was abandoned. Points at a slow or hung beacon node rather than a rejected attestation |
| `ethlambda_validator_attestations_refused_total` | Counter | Signatures deliberately not attempted, because this process had already signed a conflicting attestation for that validator. Should normally read zero |
| `ethlambda_validator_signing_failures_total` | Counter | Signatures attempted and failed |
| `ethlambda_validator_blocks_proposed_total` | Counter | Blocks signed and accepted by a beacon node |
| `ethlambda_validator_blocks_broadcast_not_imported_total` | Counter | Blocks a node broadcast but could not import into its own database, which is what a 202 means. A subset of `blocks_proposed_total`, not a failure: the block reached the network. Points at that node's execution layer |
| `ethlambda_validator_blocks_refused_total` | Counter | Blocks deliberately not signed, because this process had already proposed that slot for that validator. Should normally read zero |
| `ethlambda_validator_block_proposal_failures_total` | Counter | Proposal duties that did not end in a published block, including ones abandoned for overrunning |
| `ethlambda_validator_aggregates_published_total` | Counter | Aggregates accepted by a beacon node. Bursty rather than steady: a validator is selected a few times a day, so hours at zero are normal for a small deployment |
| `ethlambda_validator_aggregation_failures_total` | Counter | Aggregation duties that ended in no published aggregate, including ones abandoned for overrunning the slot |
| `ethlambda_validator_fee_recipient_mismatches_total` | Counter | Blocks paying execution rewards to an address this client did not request. Should read zero forever; a non-zero value means every proposal is paying somewhere else |
| `ethlambda_validator_block_publication_delay_seconds` | Histogram | Slot start to block accepted. Its buckets are tighter than the attestation histogram's, because a block is due at the slot boundary rather than a third of the way in |
| `ethlambda_validator_beacon_node_available` | Gauge | 1 when a beacon node answered the last duty refresh or attestation |
| `ethlambda_validator_signing_duration_seconds` | Histogram | Time to sign one slot's batch, store read lock included |
| `ethlambda_validator_publication_delay_seconds` | Histogram | Slot start to attestations accepted. The headline health number: it should sit near the one-third-slot duty offset |

Three of these distinguish failures that look alike on a dashboard but have
different causes, and the distinction is the reason they are separate series:
`attestation_failures_total` is a duty that ran and failed,
`attestation_deadline_missed_total` is one that never finished, and
`attestations_refused_total` is one deliberately not attempted. A rise in the
second points at the beacon nodes; a rise in the third points at the clock or
the duty schedule and is worth investigating even though the attestation was
correctly suppressed.

The proposal series split the same way, plus one that is neither a success nor
a failure. `blocks_proposed_total` counts blocks a node accepted;
`block_proposal_failures_total` counts duties that produced none;
`blocks_refused_total` counts blocks deliberately not signed. Between them,
`blocks_broadcast_not_imported_total` counts blocks that did reach the network
but that the node answering could not import, which is a beacon-node fault
rather than a validator one and is why it is not folded into either.

Two series should read zero for the life of a healthy deployment, and are the
ones worth alerting on at any non-zero value rather than on a rate:
`attestations_refused_total` and `blocks_refused_total` mean this client's own
guards caught a duty they judged unsafe, and `fee_recipient_mismatches_total`
means blocks are being proposed that pay someone else.

## Troubleshooting

### Docker Desktop on MacOS

lean-quickstart uses the host network mode for Docker containers, which is a problem on MacOS.
To work around this, enable the ["Enable host networking" option](https://docs.docker.com/enterprise/security/hardened-desktop/settings-management/settings-reference/#enable-host-networking) in Docker Desktop settings under Resources > Network.
