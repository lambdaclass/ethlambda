#![no_main]

//! The beacon wire's global gossip topics through `decode_gossip`, the one
//! dispatch every subscribed global topic goes through.
//!
//! The selector picks the topic kind, including one the node never
//! subscribed to. Under the mainnet schedule the slot read off the payload
//! selects the fork, and so the container, so the fuzzer is choosing the
//! fork too.

use ethlambda_fuzz::{mainnet_config, split};
use ethlambda_p2p::beacon::{
    decode::{DecodeError, decode_gossip},
    topics::SUBSCRIBED_TOPIC_KINDS,
};
use libfuzzer_sys::fuzz_target;

const UNKNOWN_KIND: &str = "not_a_topic";

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    let kind = SUBSCRIBED_TOPIC_KINDS
        .get(usize::from(selector))
        .copied()
        .unwrap_or(UNKNOWN_KIND);

    let result = decode_gossip(mainnet_config(), kind, bytes);
    if kind == UNKNOWN_KIND {
        assert!(
            matches!(result, Err(DecodeError::UnknownTopic)),
            "an unsubscribed topic kind decoded"
        );
    }
});
