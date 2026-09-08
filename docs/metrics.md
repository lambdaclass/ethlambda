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
| `lean_block_proposal_attestation_build_phase_seconds` | Histogram | Phase-level time in block-proposal attestation selection | On block production | phase=select_payloads,compact,stf_simulate | 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8 | ✅ |
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
| `lean_committee_signatures_aggregation_time_seconds` | Histogram | Wall time one committee-signature aggregate's proof took | On each aggregate the aggregation worker produces | | 0.05, 0.1, 0.25, 0.5, 0.75, 1, 2, 3, 4 | ✅ |
| `lean_node_sync_status` | Gauge | Node sync status | On node sync status change | status=idle,syncing,synced | | ✅ |

Three of these changed quantity when aggregation moved to the always-on worker, so thresholds and alerts carried over from before that change are comparing against something else now. `lean_committee_signatures_aggregation_time_seconds` used to time a whole interval-2 session, covering every group that session proved, and now times a single proof, so readings drop accordingly. `lean_aggregator_skipped_total{reason="other"}` counted jobs a cancelled session dropped unattempted, and now counts proofs the worker attempted and failed. `reason="not_synced"`, previously always zero, now fires once per vote-aggregation interval on an aggregator whose worker the sync gate is parking.

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

Only emitted when discv5 discovery is enabled (`--discovery.enable`); see
[Peer discovery](./discovery.md). Counts dials discovery initiated, as opposed to
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

### Gossip Arrival Timing

These histograms record the absolute distance between a gossip message's arrival and the start of the interval it was due in, so an arrival that is early by some amount and one that is late by the same amount land in the same bucket; the counters' `position` label is what tells them apart. `inside` means the message arrived within the interval it was due in, not merely somewhere in the right slot: an attestation for slot 10 that lands during slot 10's interval 2 is `after`, not `inside`, since it missed the AttestationProduction interval it was actually due in.

The bucket boundaries are the interval and slot edges of the default 4-second cadence. Prometheus fixes buckets when a histogram is registered, so a network that sets `MILLISECONDS_PER_SLOT` reads these histograms against the default grid rather than its own; the `position` label still follows the configured interval width.

Blocks anchor to interval 0 of their own slot and attestations to interval 1 of their data slot; both are unbounded above, so a message that never arrives close to real time can be arbitrarily late. Aggregates anchor instead to the most recent aggregation-interval boundary rather than their own data slot, since a stale-group catch-up aggregate can carry a `data.slot` several slots in the past; anchoring to the latest boundary bounds the delay to one slot and rules out `before` entirely.

Only gossip-received blocks are sampled here: blocks fetched via req/resp during sync are excluded, since sync backfill delivers blocks long after they were due and would swamp these histograms with catch-up noise rather than gossip-health signal.

The aggregate metrics do include an aggregator's own freshly produced aggregates, which never come back over gossip; without them an aggregator would report an empty aggregate profile. The two populations are not the same measurement. A local aggregate is sampled when it is published, and since proving runs continuously off the interval grid, publication happens at one of two times: an aggregate finishing outside intervals 2 and 3 is held to the interval-2 boundary and lands in the lowest bucket by construction, while one finishing inside them goes out on arrival and carries its real offset from that boundary. Only the second kind says anything about when a proof finished. A received aggregate still adds propagation on top of whenever the producer managed to publish it.

On an aggregator the distribution therefore carries a structural component: a spike in the lowest bucket, one sample per buffered aggregate, on top of the genuine arrival profile of peers' aggregates and of our own on-arrival publications. Nothing separates them by label, so a slot that buffers several aggregates pulls the whole histogram down. A rising tail is still aggregation cost rather than a slow link, since a late aggregate is late for every node at once. For this node's own proving cost use `lean_pq_sig_aggregated_signatures_building_time_seconds` and `lean_committee_signatures_aggregation_time_seconds` instead.

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

### Attestation Aggregate Coverage

Observability into how many validators/subnets are covered by the attestations the node has aggregated, broken down by pipeline section (the `section` label). The slot is the X-axis. These are sampled roughly once per slot, but emission is gated by the section's source data, so a gauge can retain its previous value:

- `timely`, `late`, `block`, `combined` and the `diff_validators` directions are emitted on block import, and **only when the canonical head block carries that round's votes** (otherwise the round is skipped and prior values are kept).
- `agg_start_new` is emitted at interval 2, and only on a node holding the aggregator role, so the series stays a measurement of what our own aggregation covered by the boundary. On a non-aggregator the same reading would come from `new_payloads` filled by gossip, a different population.
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
