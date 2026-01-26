# Metrics

We collect various metrics and serve them via a Prometheus-compatible HTTP endpoint at `http://<metrics_address>:<metrics_port>/metrics` (default: `http://127.0.0.1:5054/metrics`).

We provide a ready-to-use Grafana + Prometheus monitoring stack in the [`metrics/`](../metrics/) directory. It includes pre-configured dashboards from the [leanMetrics](https://github.com/leanEthereum/leanMetrics) repository for visualizing the metrics described below. See the [metrics README](../metrics/README.md) for setup instructions.

The exposed metrics follow [the leanMetrics specification](https://github.com/leanEthereum/leanMetrics/blob/3b32b300cca5ed7a7a2b3f142273fae9dbc171bf/metrics.md), with some metrics not yet implemented. We have a full list of implemented metrics below, with a checkbox indicating whether each metric is currently supported or not.

## Node Info Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Supported     |
|--------|-------|-------|-------------------------|--------|---------------|
| `lean_node_info` | Gauge | Node information (always 1) | On node start | name, version | ✅ |
| `lean_node_start_time_seconds` | Gauge | Start timestamp | On node start | | ✅ |


## PQ Signature Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_pq_sig_attestation_signing_time_seconds` | Histogram | Time taken to sign an attestation | On each attestation signing | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_pq_sig_attestation_verification_time_seconds` | Histogram | Time taken to verify an attestation signature | On each `signature.verify()` on an attestation | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_pq_sig_aggregated_signatures_total` | Counter | Total number of aggregated signatures | On `build_attestation_signatures()` | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_pq_sig_attestations_in_aggregated_signatures_total` | Counter | Total number of attestations included into aggregated signatures | On `build_attestation_signatures()` | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_pq_sig_attestation_signatures_building_time_seconds` | Histogram | Time taken to verify an aggregated attestation signature | On `build_attestation_signatures()` | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_pq_sig_aggregated_signatures_verification_time_seconds` | Histogram | Time taken to verify an aggregated attestation signature | On validate aggregated signature | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_pq_sig_aggregated_signatures_valid_total`| Counter | Total number of valid aggregated signatures | On validate aggregated signature | | | □ |
| `lean_pq_sig_aggregated_signatures_invalid_total`| Counter | Total number of invalid aggregated signatures | On validate aggregated signature | | | □ |

## Fork-Choice Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_head_slot` | Gauge | Latest slot of the lean chain | On get fork choice head | | | ✅ |
| `lean_current_slot` | Gauge | Current slot of the lean chain | On scrape | | | ✅(*) |
| `lean_safe_target_slot` | Gauge | Safe target slot | On safe target update | | | ✅ |
|`lean_fork_choice_block_processing_time_seconds`| Histogram | Time taken to process block | On fork choice process block | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
|`lean_attestations_valid_total`| Counter | Total number of valid attestations | On validate attestation | source=block,gossip | | □ |
|`lean_attestations_invalid_total`| Counter | Total number of invalid attestations | On validate attestation | source=block,gossip | | □ |
|`lean_attestation_validation_time_seconds`| Histogram | Time taken to validate attestation | On validate attestation | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
| `lean_fork_choice_reorgs_total` | Counter | Total number of fork choice reorgs | On fork choice reorg | | | □ |
| `lean_fork_choice_reorg_depth` | Histogram | Depth of fork choice reorgs (in blocks) | On fork choice reorg | | 1, 2, 3, 5, 7, 10, 20, 30, 50, 100 | □ |

## State Transition Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Buckets | Supported |
|--------|-------|-------|-------------------------|--------|---------|-----------|
| `lean_latest_justified_slot` | Gauge | Latest justified slot | On state transition | | | ✅ |
| `lean_latest_finalized_slot` | Gauge | Latest finalized slot | On state transition | | | ✅ |
| `lean_finalizations_total` | Counter | Total number of finalization attempts | On finalization attempt | result=success,error | | ✅ |
|`lean_state_transition_time_seconds`| Histogram | Time to process state transition | On state transition | | 0.25, 0.5, 0.75, 1, 1.25, 1.5, 2, 2.5, 3, 4 | □ |
|`lean_state_transition_slots_processed_total`| Counter | Total number of processed slots | On state transition process slots | | | ✅ |
|`lean_state_transition_slots_processing_time_seconds`| Histogram | Time taken to process slots | On state transition process slots | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
|`lean_state_transition_block_processing_time_seconds`| Histogram | Time taken to process block | On state transition process block | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |
|`lean_state_transition_attestations_processed_total`| Counter | Total number of processed attestations | On state transition process attestations | | | ✅ |
|`lean_state_transition_attestations_processing_time_seconds`| Histogram | Time taken to process attestations | On state transition process attestations | | 0.005, 0.01, 0.025, 0.05, 0.1, 1 | □ |

## Validator Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Supported |
|--------|-------|-------|-------------------------|--------|-----------|
|`lean_validators_count`| Gauge | Number of validators managed by a node | On scrape |  | ✅(*) |

## Network Metrics

| Name   | Type  | Usage | Sample collection event | Labels | Supported |
|--------|-------|-------|-------------------------|--------|-----------|
|`lean_connected_peers`| Gauge | Number of connected peers | On scrape | client=lantern,qlean,ream,zeam | ✅(*) |
|`lean_peer_connection_events_total`| Counter | Total number of peer connection events | On peer connection | direction=inbound,outbound<br>result=success,timeout,error | ✅ |
|`lean_peer_disconnection_events_total`| Counter | Total number of peer disconnection events | On peer disconnection | direction=inbound,outbound<br>reason=timeout,remote_close,local_close,error | ✅ |

---

✅(*) **Partial support**: These metrics are implemented but not collected "on scrape" as the spec requires. They are updated on specific events (e.g., on tick, on block processing) rather than being computed fresh on each Prometheus scrape.
