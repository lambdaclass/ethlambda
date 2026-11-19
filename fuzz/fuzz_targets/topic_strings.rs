#![no_main]

//! Gossip topic names are peer-chosen strings.
//!
//! Every parser that reads a topic or a topic kind must answer `None` rather
//! than panic on any string, and the kind helpers must accept whatever
//! `topic_kind` hands them.

use ethlambda_p2p::{beacon::topics, lean_topic_kind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|topic: &str| {
    let _ = lean_topic_kind(topic);
    let _ = topics::topic_digest(topic);

    if let Some(kind) = topics::topic_kind(topic) {
        let _ = topics::metric_kind(kind);
        let _ = topics::attestation_subnet(kind);
        let _ = topics::data_column_subnet(kind);
        let _ = topics::sync_committee_subnet(kind);
    }

    // The kind helpers are also reached with strings that never went through
    // `topic_kind` (the spec's gossip vectors name a family directly).
    let _ = topics::metric_kind(topic);
    let _ = topics::attestation_subnet(topic);
    let _ = topics::data_column_subnet(topic);
    let _ = topics::sync_committee_subnet(topic);
});
