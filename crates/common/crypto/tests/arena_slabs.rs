//! The arena's memory bound under ethlambda's threading.
//!
//! leanVM's arena gives each thread that allocates during a proof its own slab and keeps
//! it for the life of the process; the slab that fills is the one of the thread driving
//! the proof. ethlambda asks for proofs from threads that come and go (tokio's blocking
//! pool, the actors), so proving on the asking thread would pin one slab per thread ever
//! used, which is how aggregators on `--prover-arena` were OOM-killed.
//!
//! Its own test binary, and so its own process: the arena engages process-wide and the
//! slab count is process-wide, so another test proving alongside would move it.

mod common;

use std::thread;

use common::keypair_and_signature;
use ethlambda_crypto::{aggregate_signatures, init_leanvm};
use ethlambda_types::primitives::H256;

#[test]
#[ignore = "too slow"]
fn proving_from_fresh_threads_claims_no_new_slabs() {
    init_leanvm(true);

    let message = H256::from([7u8; 32]);
    let slot = 10u32;
    let (pk, sig) = keypair_and_signature(1, 5, slot, &message);
    let prove_from_a_fresh_thread = || {
        let (pk, sig) = (pk.clone(), sig.clone());
        thread::spawn(move || aggregate_signatures(vec![pk], vec![sig], &message, slot))
            .join()
            .expect("asking thread")
            .expect("aggregation on the arena");
    };

    prove_from_a_fresh_thread();
    let slabs = zk_alloc::stats().threads;
    // Zero would mean this test reads another copy of the arena than leanvm's.
    assert!(slabs > 0, "the first proof claimed no slab");

    for _ in 0..4 {
        prove_from_a_fresh_thread();
    }
    assert_eq!(
        zk_alloc::stats().threads,
        slabs,
        "proving from new threads claimed new slabs"
    );
}
