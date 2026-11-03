#![no_main]

//! The gossipsub message id: a 20-byte truncated SHA-256 over a domain (valid
//! or invalid snappy), the topic and the (decompressed) data.
//!
//! The id is what dedups a message across the mesh, so it must be a pure
//! function of topic and data: never panic, always 20 bytes, the same on a
//! second call, and different for a different topic.

use ethlambda_fuzz::split;
use ethlambda_p2p::gossip_message_id;
use libfuzzer_sys::fuzz_target;
use libp2p::gossipsub::{Message, TopicHash};

fn message(topic: &str, data: &[u8]) -> Message {
    Message {
        source: None,
        data: data.to_vec(),
        sequence_number: None,
        topic: TopicHash::from_raw(topic),
    }
}

fuzz_target!(|data: &[u8]| {
    let (topic_len, rest) = split(data);
    let topic_len = usize::from(topic_len).min(rest.len());
    let topic = String::from_utf8_lossy(&rest[..topic_len]).into_owned();
    let payload = &rest[topic_len..];

    let id = gossip_message_id(&message(&topic, payload));
    assert_eq!(id.0.len(), 20, "message id is not 20 bytes");
    assert_eq!(
        gossip_message_id(&message(&topic, payload)),
        id,
        "message id is not deterministic"
    );

    let other_topic = format!("{topic}/other");
    assert_ne!(
        gossip_message_id(&message(&other_topic, payload)),
        id,
        "message id ignores the topic"
    );
});
