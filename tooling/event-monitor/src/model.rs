//! Wire shapes for upstream ethlambda SSE payloads (CONTRACT.md §2) and the
//! `NormalizedEvent` re-served to the browser (CONTRACT.md §3).

use serde::{Deserialize, Serialize};

use crate::timing::Timing;

/// A `Checkpoint` (`head`/`target`/`source`): `{ "root": "0x...", "slot": N }`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Checkpoint {
    pub root: String,
    pub slot: u64,
}

/// Shared attestation-vote payload embedded in both `attestation` and
/// `aggregate` topics.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestationData {
    pub slot: u64,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

/// `block`, `safe_target`, `block_gossip`: `{ "slot": N, "block": "0x..." }`.
#[derive(Debug, Clone, Deserialize)]
struct SlotBlockPayload {
    slot: u64,
    block: String,
}

/// `head`, `justified_checkpoint`, `finalized_checkpoint`:
/// `{ "slot": N, "block": "0x...", "state": "0x..." }`.
#[derive(Debug, Clone, Deserialize)]
struct CheckpointEventPayload {
    slot: u64,
    block: String,
    #[allow(dead_code)] // part of the wire shape; not surfaced on NormalizedEvent
    state: String,
}

/// `attestation`: `{ "validator_id": N, "data": {...} }`.
#[derive(Debug, Clone, Deserialize)]
struct AttestationPayload {
    validator_id: u64,
    data: AttestationData,
}

/// `aggregate`: `{ "participants": [...], "data": {...} }`.
#[derive(Debug, Clone, Deserialize)]
struct AggregatePayload {
    participants: Vec<u64>,
    data: AttestationData,
}

/// `chain_reorg`:
/// `{ "slot":N, "depth":N, "old_head_block":"0x...", "old_head_state":"0x...",
///    "new_head_block":"0x...", "new_head_state":"0x..." }`.
#[derive(Debug, Clone, Deserialize)]
struct ReorgPayload {
    slot: u64,
    #[allow(dead_code)]
    depth: u64,
    #[allow(dead_code)]
    old_head_block: String,
    #[allow(dead_code)]
    old_head_state: String,
    new_head_block: String,
    #[allow(dead_code)]
    new_head_state: String,
}

/// Collector -> browser payload (CONTRACT.md §3). Field names and shape are
/// frozen; do not rename without updating CONTRACT.md and `web/`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NormalizedEvent {
    pub node: String,
    pub topic: String,
    pub slot: u64,
    pub arrival_ms: i64,
    pub offset_ms: i64,
    pub id: Option<String>,
    pub validator_id: Option<u64>,
    pub participants: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum NormalizeError {
    #[error("unknown topic: {0}")]
    UnknownTopic(String),
    #[error("failed to parse payload for topic {topic}: {source}")]
    Json {
        topic: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Canonical struct hashed to derive the aggregate `id`: `{data, participants}`
/// with `participants` sorted ascending, serialized deterministically via our
/// own field order (never via an arbitrary `serde_json::Value`).
#[derive(Serialize)]
struct AggregateIdInput<'a> {
    data: &'a AttestationData,
    participants: Vec<u64>,
}

/// Session-stable FNV-1a hash of the canonical JSON of `{data, sorted
/// participants}`, rendered as `0x` + 16 lowercase hex digits. Only needs to
/// be stable within one collector process (CONTRACT.md §3).
fn aggregate_id(data: &AttestationData, participants: &[u64]) -> String {
    let mut sorted = participants.to_vec();
    sorted.sort_unstable();
    let input = AggregateIdInput {
        data,
        participants: sorted,
    };
    // Infallible: AggregateIdInput contains only plain data, no maps/floats.
    let canonical = serde_json::to_string(&input).expect("aggregate id input is always valid JSON");
    format!("0x{:016x}", fnv1a_64(canonical.as_bytes()))
}

fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Maps one upstream SSE frame (`event:` topic + `data:` JSON) into a
/// [`NormalizedEvent`]. Never panics: an unknown topic or unparsable payload
/// yields `Err`, which callers log and skip (CONTRACT.md §2).
pub fn normalize(
    node: &str,
    topic: &str,
    data: &str,
    arrival_ms: i64,
    timing: &Timing,
) -> Result<NormalizedEvent, NormalizeError> {
    let to_json_err = |source: serde_json::Error| NormalizeError::Json {
        topic: topic.to_string(),
        source,
    };

    let (slot, id, validator_id, participants) = match topic {
        "block" | "safe_target" | "block_gossip" => {
            let payload: SlotBlockPayload = serde_json::from_str(data).map_err(to_json_err)?;
            (payload.slot, Some(payload.block), None, None)
        }
        "head" | "justified_checkpoint" | "finalized_checkpoint" => {
            let payload: CheckpointEventPayload =
                serde_json::from_str(data).map_err(to_json_err)?;
            (payload.slot, Some(payload.block), None, None)
        }
        "chain_reorg" => {
            let payload: ReorgPayload = serde_json::from_str(data).map_err(to_json_err)?;
            (payload.slot, Some(payload.new_head_block), None, None)
        }
        "attestation" => {
            let payload: AttestationPayload = serde_json::from_str(data).map_err(to_json_err)?;
            (payload.data.slot, None, Some(payload.validator_id), None)
        }
        "aggregate" => {
            let payload: AggregatePayload = serde_json::from_str(data).map_err(to_json_err)?;
            let id = aggregate_id(&payload.data, &payload.participants);
            let count = u32::try_from(payload.participants.len()).unwrap_or(u32::MAX);
            (payload.data.slot, Some(id), None, Some(count))
        }
        other => return Err(NormalizeError::UnknownTopic(other.to_string())),
    };

    Ok(NormalizedEvent {
        node: node.to_string(),
        topic: topic.to_string(),
        slot,
        arrival_ms,
        offset_ms: timing.offset_ms(slot, arrival_ms),
        id,
        validator_id,
        participants,
    })
}

/// Live status of one node's collector connection (CONTRACT.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Connected,
    Reconnecting,
    Down,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node: String,
    pub state: NodeState,
    pub events_per_sec: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timing() -> Timing {
        Timing {
            genesis_time: 0,
            ms_per_slot: 4_000,
            intervals_per_slot: 5,
        }
    }

    #[test]
    fn block_topic_maps_id_to_block_root() {
        let data = r#"{ "slot": 128, "block": "0xabc123" }"#;
        let ev = normalize("node-2", "block", data, 1_000, &timing()).unwrap();
        assert_eq!(ev.topic, "block");
        assert_eq!(ev.slot, 128);
        assert_eq!(ev.id, Some("0xabc123".to_string()));
        assert_eq!(ev.validator_id, None);
        assert_eq!(ev.participants, None);
        assert_eq!(ev.offset_ms, 1_000 - 128 * 4_000);
    }

    #[test]
    fn safe_target_topic_maps_id_to_block_root() {
        let data = r#"{ "slot": 127, "block": "0xdeadbeef" }"#;
        let ev = normalize("node-2", "safe_target", data, 500, &timing()).unwrap();
        assert_eq!(ev.topic, "safe_target");
        assert_eq!(ev.slot, 127);
        assert_eq!(ev.id, Some("0xdeadbeef".to_string()));
    }

    #[test]
    fn block_gossip_topic_maps_id_to_block_root() {
        let data = r#"{ "slot": 128, "block": "0xabc123" }"#;
        let ev = normalize("node-2", "block_gossip", data, 1_000, &timing()).unwrap();
        assert_eq!(ev.topic, "block_gossip");
        assert_eq!(ev.id, Some("0xabc123".to_string()));
    }

    #[test]
    fn head_topic_maps_id_to_block_root_ignoring_state() {
        let data = r#"{ "slot": 128, "block": "0x1a2b", "state": "0x3c4d" }"#;
        let ev = normalize("node-2", "head", data, 2_000, &timing()).unwrap();
        assert_eq!(ev.topic, "head");
        assert_eq!(ev.slot, 128);
        assert_eq!(ev.id, Some("0x1a2b".to_string()));
    }

    #[test]
    fn justified_checkpoint_maps_id_to_block_root() {
        let data = r#"{ "slot": 120, "block": "0xaaaa", "state": "0xbbbb" }"#;
        let ev = normalize("node-2", "justified_checkpoint", data, 0, &timing()).unwrap();
        assert_eq!(ev.id, Some("0xaaaa".to_string()));
    }

    #[test]
    fn finalized_checkpoint_maps_id_to_block_root() {
        let data = r#"{ "slot": 96, "block": "0xcccc", "state": "0xdddd" }"#;
        let ev = normalize("node-2", "finalized_checkpoint", data, 0, &timing()).unwrap();
        assert_eq!(ev.id, Some("0xcccc".to_string()));
    }

    #[test]
    fn chain_reorg_maps_id_to_new_head_block() {
        let data = r#"{
            "slot": 128, "depth": 2,
            "old_head_block": "0xold1", "old_head_state": "0xold2",
            "new_head_block": "0xnew1", "new_head_state": "0xnew2"
        }"#;
        let ev = normalize("node-2", "chain_reorg", data, 0, &timing()).unwrap();
        assert_eq!(ev.slot, 128);
        assert_eq!(ev.id, Some("0xnew1".to_string()));
    }

    #[test]
    fn attestation_topic_has_null_id_and_validator_id_set() {
        let data = r#"{
            "validator_id": 7,
            "data": {
                "slot": 12,
                "head": {"root": "0xh", "slot": 12},
                "target": {"root": "0xt", "slot": 8},
                "source": {"root": "0xs", "slot": 4}
            }
        }"#;
        let ev = normalize("node-2", "attestation", data, 0, &timing()).unwrap();
        assert_eq!(ev.topic, "attestation");
        assert_eq!(ev.slot, 12);
        assert_eq!(ev.id, None);
        assert_eq!(ev.validator_id, Some(7));
        assert_eq!(ev.participants, None);
    }

    #[test]
    fn aggregate_topic_sets_participant_count_and_hash_id() {
        let data = r#"{
            "participants": [0, 1, 2],
            "data": {
                "slot": 12,
                "head": {"root": "0xh", "slot": 12},
                "target": {"root": "0xt", "slot": 8},
                "source": {"root": "0xs", "slot": 4}
            }
        }"#;
        let ev = normalize("node-2", "aggregate", data, 0, &timing()).unwrap();
        assert_eq!(ev.topic, "aggregate");
        assert_eq!(ev.slot, 12);
        assert_eq!(ev.validator_id, None);
        assert_eq!(ev.participants, Some(3));
        let id = ev.id.expect("aggregate must set an id");
        assert!(id.starts_with("0x"));
        assert_eq!(id.len(), 2 + 16);
    }

    #[test]
    fn aggregate_id_is_stable_regardless_of_participant_order() {
        let data_a = r#"{
            "participants": [0, 1, 2],
            "data": {
                "slot": 12,
                "head": {"root": "0xh", "slot": 12},
                "target": {"root": "0xt", "slot": 8},
                "source": {"root": "0xs", "slot": 4}
            }
        }"#;
        let data_b = r#"{
            "participants": [2, 0, 1],
            "data": {
                "slot": 12,
                "head": {"root": "0xh", "slot": 12},
                "target": {"root": "0xt", "slot": 8},
                "source": {"root": "0xs", "slot": 4}
            }
        }"#;
        let ev_a = normalize("node-2", "aggregate", data_a, 0, &timing()).unwrap();
        let ev_b = normalize("node-3", "aggregate", data_b, 999, &timing()).unwrap();
        assert_eq!(ev_a.id, ev_b.id);
    }

    #[test]
    fn aggregate_id_differs_for_different_participants() {
        let base = |participants: &str| {
            format!(
                r#"{{
                "participants": {participants},
                "data": {{
                    "slot": 12,
                    "head": {{"root": "0xh", "slot": 12}},
                    "target": {{"root": "0xt", "slot": 8}},
                    "source": {{"root": "0xs", "slot": 4}}
                }}
            }}"#
            )
        };
        let ev_a = normalize("node-2", "aggregate", &base("[0,1,2]"), 0, &timing()).unwrap();
        let ev_b = normalize("node-2", "aggregate", &base("[0,1,3]"), 0, &timing()).unwrap();
        assert_ne!(ev_a.id, ev_b.id);
    }

    #[test]
    fn aggregate_id_differs_for_different_data() {
        let data_a = r#"{
            "participants": [0, 1, 2],
            "data": {
                "slot": 12,
                "head": {"root": "0xh", "slot": 12},
                "target": {"root": "0xt", "slot": 8},
                "source": {"root": "0xs", "slot": 4}
            }
        }"#;
        let data_b = r#"{
            "participants": [0, 1, 2],
            "data": {
                "slot": 13,
                "head": {"root": "0xh2", "slot": 13},
                "target": {"root": "0xt", "slot": 8},
                "source": {"root": "0xs", "slot": 4}
            }
        }"#;
        let ev_a = normalize("node-2", "aggregate", data_a, 0, &timing()).unwrap();
        let ev_b = normalize("node-2", "aggregate", data_b, 0, &timing()).unwrap();
        assert_ne!(ev_a.id, ev_b.id);
    }

    #[test]
    fn unknown_topic_is_an_error_not_a_panic() {
        let err = normalize("node-2", "mystery", "{}", 0, &timing()).unwrap_err();
        assert!(matches!(err, NormalizeError::UnknownTopic(_)));
    }

    #[test]
    fn malformed_payload_is_an_error_not_a_panic() {
        let err = normalize("node-2", "block", "{not json", 0, &timing()).unwrap_err();
        assert!(matches!(err, NormalizeError::Json { .. }));
    }
}
