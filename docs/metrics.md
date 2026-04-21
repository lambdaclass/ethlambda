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
| `lean_aggregated_proof_size_bytes` | Histogram | Bytes size of an aggregated signature proof's `proof_data` field | On aggregated signature production | | 1024, 4096, 16384, 65536, 131072, 262144, 524288, 1048576 | ✅ |

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
| `lean_gossip_signatures` | Gauge | Number of gossip signatures in fork-choice store | On gossip signatures update | | | ✅ |
| `lean_latest_new_aggregated_payloads` | Gauge | Number of new aggregated payload items | On `latest_new_aggregated_payloads` update | | | ✅ |
| `lean_latest_known_aggregated_payloads` | Gauge | Number of known aggregated payload items | On `latest_known_aggregated_payloads` update | | | ✅ |
| `lean_committee_signatures_aggregation_time_seconds` | Histogram | Time taken to aggregate committee signatures | On committee signatures aggregation | | 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1 | ✅ |

## State Transition Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_latest_justified_slot` | Gauge | Latest justified slot | On state transition | | | ✅ |
| `lean_latest_finalized_slot` | Gauge | Latest finalized slot | On state transition | | | ✅ |
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
|`lean_peer_connection_events_total`| Counter | Total number of peer connection events | On peer connection | direction=inbound,outbound<br>result=success,timeout,error | ✅ |
|`lean_peer_disconnection_events_total`| Counter | Total number of peer disconnection events | On peer disconnection | direction=inbound,outbound<br>reason=timeout,remote_close,local_close,error | ✅ |
|`lean_gossip_block_size_bytes`| Histogram | Bytes size of a gossip block message (raw SSZ or snappy on-wire) | On gossip block send/receive | compression=raw,snappy | ✅ |
|`lean_gossip_attestation_size_bytes`| Histogram | Bytes size of a gossip attestation message (raw SSZ or snappy on-wire) | On gossip attestation send/receive | compression=raw,snappy | ✅ |
|`lean_gossip_aggregation_size_bytes`| Histogram | Bytes size of a gossip aggregated attestation message (raw SSZ or snappy on-wire) | On gossip aggregation send/receive | compression=raw,snappy | ✅ |
|`lean_reqresp_request_size_bytes`| Histogram | Bytes size of a req/resp request (raw SSZ or snappy on-wire) | On req/resp request send/receive | protocol=status,blocks_by_root<br>compression=raw,snappy | ✅ |
|`lean_reqresp_response_chunk_size_bytes`| Histogram | Bytes size of a single req/resp response chunk (raw SSZ or snappy on-wire) | On req/resp response chunk send/receive | protocol=status,blocks_by_root<br>compression=raw,snappy | ✅ |

---

✅(*) **Partial support**: These metrics are implemented but not collected "on scrape" as the spec requires. They are updated on specific events (e.g., on tick, on block processing) rather than being computed fresh on each Prometheus scrape.

## Troubleshooting

### Docker Desktop on MacOS

lean-quickstart uses the host network mode for Docker containers, which is a problem on MacOS.
To work around this, enable the ["Enable host networking" option](https://docs.docker.com/enterprise/security/hardened-desktop/settings-management/settings-reference/#enable-host-networking) in Docker Desktop settings under Resources > Network.
