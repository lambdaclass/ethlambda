//! Coverage for the arena path of [`init_leanvm`].
//!
//! leanVM's arena engages process-wide and cannot be disengaged, so this cannot live in
//! the lib test binary: it would change the allocator under every other test. An
//! integration test gets its own process.

mod common;

use common::keypair_and_signature;
use ethlambda_crypto::{aggregate_signatures, init_leanvm, verify_aggregated_signature};
use ethlambda_types::primitives::H256;

#[test]
#[ignore = "too slow"]
fn aggregates_on_the_arena_when_enabled() {
    init_leanvm(true);

    let message = H256::from([7u8; 32]);
    let slot = 10u32;
    let (pk, sig) = keypair_and_signature(1, 5, slot, &message);

    // Proves on the arena: the same round trip the lib tests run on the system allocator.
    let proof = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot)
        .expect("aggregation on the arena");
    verify_aggregated_signature(&proof, vec![pk], &message, slot).expect("verification");
}
