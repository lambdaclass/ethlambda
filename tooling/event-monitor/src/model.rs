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

/// `block`, `block_gossip`: `{ "slot": N, "block": "0x..." }`.
///
/// Also used for `head` / `justified_checkpoint` / `finalized_checkpoint`, whose
/// wire shape adds a `state: "0x..."` field; serde ignores it, since only `slot`
/// and `block` are surfaced on the [`NormalizedEvent`].
#[derive(Debug, Clone, Deserialize)]
struct SlotBlockPayload {
    slot: u64,
    block: String,
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

/// How far ahead of the collector's own clock an event's slot may be before we
/// treat it as bogus. A node slightly ahead of us is normal (clock skew, an
/// event emitted just before its slot boundary), but a slot far in the future
/// means the node is on a different genesis or the payload is corrupt. Such an
/// event must not be accepted: both the collector's history ring and the
/// dashboard's rolling window key their retention off the highest slot seen,
/// which only ever moves up, so one bogus slot would age out every real event
/// and blank the view until a restart.
///
/// Only the future side is bounded. Old slots are legitimate and common
/// (`finalized_checkpoint` trails head, a syncing node replays history) and
/// cannot move the watermark.
const MAX_FUTURE_SLOTS: u64 = 8;

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
    #[error(
        "topic {topic} reports slot {slot}, more than {MAX_FUTURE_SLOTS} slots ahead of the collector's own slot {collector_slot}"
    )]
    ImplausibleSlot {
        topic: String,
        slot: u64,
        collector_slot: u64,
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
        "block" | "block_gossip" | "head" | "justified_checkpoint" | "finalized_checkpoint" => {
            let payload: SlotBlockPayload = serde_json::from_str(data).map_err(to_json_err)?;
            (payload.slot, Some(payload.block), None, None)
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

    let collector_slot = timing.slot_at(arrival_ms);
    if slot > collector_slot.saturating_add(MAX_FUTURE_SLOTS) {
        return Err(NormalizeError::ImplausibleSlot {
            topic: topic.to_string(),
            slot,
            collector_slot,
        });
    }

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

    /// Collector-clock arrival `offset_ms` into `slot`, so fixtures place the
    /// arrival inside a plausible slot the way real events do (see
    /// [`MAX_FUTURE_SLOTS`]).
    fn arrival_for(slot: u64, offset_ms: i64) -> i64 {
        slot as i64 * 4_000 + offset_ms
    }

    #[test]
    fn block_topic_maps_id_to_block_root() {
        let data = r#"{ "slot": 128, "block": "0xabc123" }"#;
        let arrival = arrival_for(128, 123);
        let ev = normalize("node-2", "block", data, arrival, &timing()).unwrap();
        assert_eq!(ev.topic, "block");
        assert_eq!(ev.slot, 128);
        assert_eq!(ev.id, Some("0xabc123".to_string()));
        assert_eq!(ev.validator_id, None);
        assert_eq!(ev.participants, None);
        assert_eq!(ev.offset_ms, 123);
    }

    #[test]
    fn block_gossip_topic_maps_id_to_block_root() {
        let data = r#"{ "slot": 128, "block": "0xabc123" }"#;
        let arrival = arrival_for(128, 1_000);
        let ev = normalize("node-2", "block_gossip", data, arrival, &timing()).unwrap();
        assert_eq!(ev.topic, "block_gossip");
        assert_eq!(ev.id, Some("0xabc123".to_string()));
    }

    #[test]
    fn head_topic_maps_id_to_block_root_ignoring_state() {
        let data = r#"{ "slot": 128, "block": "0x1a2b", "state": "0x3c4d" }"#;
        let arrival = arrival_for(128, 2_000);
        let ev = normalize("node-2", "head", data, arrival, &timing()).unwrap();
        assert_eq!(ev.topic, "head");
        assert_eq!(ev.slot, 128);
        assert_eq!(ev.id, Some("0x1a2b".to_string()));
    }

    #[test]
    fn justified_checkpoint_maps_id_to_block_root() {
        // Checkpoints trail head, so the arrival sits well past their own slot.
        let data = r#"{ "slot": 120, "block": "0xaaaa", "state": "0xbbbb" }"#;
        let arrival = arrival_for(128, 0);
        let ev = normalize("node-2", "justified_checkpoint", data, arrival, &timing()).unwrap();
        assert_eq!(ev.id, Some("0xaaaa".to_string()));
    }

    #[test]
    fn finalized_checkpoint_maps_id_to_block_root() {
        let data = r#"{ "slot": 96, "block": "0xcccc", "state": "0xdddd" }"#;
        let arrival = arrival_for(128, 0);
        let ev = normalize("node-2", "finalized_checkpoint", data, arrival, &timing()).unwrap();
        assert_eq!(ev.id, Some("0xcccc".to_string()));
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
        let arrival = arrival_for(12, 800);
        let ev = normalize("node-2", "attestation", data, arrival, &timing()).unwrap();
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
        let arrival = arrival_for(12, 1_600);
        let ev = normalize("node-2", "aggregate", data, arrival, &timing()).unwrap();
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
        let ev_a = normalize("node-2", "aggregate", data_a, arrival_for(12, 0), &timing()).unwrap();
        let ev_b = normalize(
            "node-3",
            "aggregate",
            data_b,
            arrival_for(12, 999),
            &timing(),
        )
        .unwrap();
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
        let arrival = arrival_for(12, 1_600);
        let ev_a = normalize("node-2", "aggregate", &base("[0,1,2]"), arrival, &timing()).unwrap();
        let ev_b = normalize("node-2", "aggregate", &base("[0,1,3]"), arrival, &timing()).unwrap();
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
        let arrival = arrival_for(13, 1_600);
        let ev_a = normalize("node-2", "aggregate", data_a, arrival, &timing()).unwrap();
        let ev_b = normalize("node-2", "aggregate", data_b, arrival, &timing()).unwrap();
        assert_ne!(ev_a.id, ev_b.id);
    }

    #[test]
    fn slot_far_ahead_of_the_collector_clock_is_rejected() {
        // A node on a different genesis reports slots wildly ahead of ours.
        // Accepting one would ratchet the history/window watermark past every
        // real event and blank the dashboard, so it must be dropped.
        let data = r#"{ "slot": 900000, "block": "0xdead" }"#;
        let err = normalize("node-2", "block", data, arrival_for(128, 0), &timing()).unwrap_err();
        assert!(matches!(
            err,
            NormalizeError::ImplausibleSlot { slot: 900000, .. }
        ));
    }

    #[test]
    fn slot_slightly_ahead_of_the_collector_clock_is_accepted() {
        // Modest clock skew, or an event emitted just before its slot boundary,
        // is normal and must still get through.
        let t = timing();
        let collector_slot = 128;
        for ahead in 0..=MAX_FUTURE_SLOTS {
            let data = format!(
                r#"{{ "slot": {}, "block": "0xabc" }}"#,
                collector_slot + ahead
            );
            let arrival = arrival_for(collector_slot, 0);
            let ev = normalize("node-2", "block", &data, arrival, &t)
                .unwrap_or_else(|err| panic!("{ahead} slots ahead should be accepted: {err}"));
            assert_eq!(ev.slot, collector_slot + ahead);
        }

        let data = format!(
            r#"{{ "slot": {}, "block": "0xabc" }}"#,
            collector_slot + MAX_FUTURE_SLOTS + 1
        );
        let arrival = arrival_for(collector_slot, 0);
        let err = normalize("node-2", "block", &data, arrival, &t).unwrap_err();
        assert!(matches!(err, NormalizeError::ImplausibleSlot { .. }));
    }

    #[test]
    fn old_slots_are_always_accepted() {
        // Past slots are legitimate and common: finalized/justified checkpoints
        // trail head, and a syncing node replays history. They also cannot move
        // the watermark, so there is no reason to bound them.
        let data = r#"{ "slot": 1, "block": "0xold", "state": "0xstate" }"#;
        let arrival = arrival_for(500_000, 0);
        let ev = normalize("node-2", "finalized_checkpoint", data, arrival, &timing()).unwrap();
        assert_eq!(ev.slot, 1);
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
