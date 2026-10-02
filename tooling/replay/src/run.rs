//! Backend dispatch + timing report (ethrex-replay style).
//!
//! Each transition is run through the host `exec` baseline (default) or the SP1
//! prover (`--features sp1`), and one line is logged per block with its
//! execution / proving / verification time, followed by a run summary with the
//! total and a throughput figure. 

use std::time::Duration;

use ethlambda_types::ShortRoot;

use crate::Action;
use crate::fetcher::ReplayInput;

/// Human-readable duration, e.g. `1.23s` / `45.67ms`.
fn fmt_dur(d: Duration) -> String {
    format!("{d:.2?}")
}

/// Run throughput: transitions per second. 
fn throughput(count: usize, total: Duration) -> String {
    let secs = total.as_secs_f64();
    if secs > 0.0 {
        format!("{:.2} transitions/s", count as f64 / secs)
    } else {
        "n/a".to_string()
    }
}

/// Host baseline: run `state_transition` directly, no zkVM. `--action` is
/// irrelevant here (there is no proof to generate).
#[cfg(not(feature = "sp1"))]
pub async fn run(_action: Action, transitions: &[ReplayInput]) -> eyre::Result<()> {
    use ethlambda_state_transition::state_transition;
    use ethlambda_types::primitives::HashTreeRoot as _;
    use std::time::Instant;

    println!("[replay] backend=exec (host state_transition, no zkVM)");
    let mut total = Duration::ZERO;
    for t in transitions {
        let mut state = t.input.state();
        let block = t.input.block();

        let start = Instant::now();
        state_transition(&mut state, &block)
            .map_err(|e| eyre::eyre!("state_transition failed for {}: {e:?}", t.id))?;
        let elapsed = start.elapsed();
        total += elapsed;

        assert_eq!(
            state.hash_tree_root(),
            t.expected.post_state_root,
            "post_state_root mismatch at {}",
            t.id
        );
        println!(
            "[replay] Block: {} (slot {}, attestations {}), post {} | Execution Time: {}",
            t.id,
            t.slot,
            t.attestations,
            ShortRoot(&t.expected.post_state_root.0),
            fmt_dur(elapsed),
        );
    }
    println!(
        "[replay] Executed {} transition(s) in {} ({})",
        transitions.len(),
        fmt_dur(total),
        throughput(transitions.len(), total),
    );
    Ok(())
}

/// SP1 backend: run each transition through the guest via `execute` or
/// `prove` + `verify`, timing each step with the trait's `*_timed` wrappers and
/// checking committed roots against the host expectation.
#[cfg(feature = "sp1")]
pub async fn run(action: Action, transitions: &[ReplayInput]) -> eyre::Result<()> {
    use ethlambda_prover_core::StfProver;
    use ethlambda_prover_sp1::Sp1Prover;

    println!("[replay] backend=sp1 (MockProver)");
    let prover = Sp1Prover::new().await;
    let mut total = Duration::ZERO;
    for t in transitions {
        match action {
            Action::Execute => {
                let (pv, elapsed) = prover
                    .execute_timed(&t.input)
                    .await
                    .map_err(|e| eyre::eyre!("execute {}: {e}", t.id))?;
                total += elapsed;
                check(&pv, &t.expected, &t.id);
                println!(
                    "[replay] Block: {} (slot {}, attestations {}), post {} | Execution Time: {}",
                    t.id,
                    t.slot,
                    t.attestations,
                    ShortRoot(&t.expected.post_state_root.0),
                    fmt_dur(elapsed),
                );
            }
            Action::Prove => {
                let (proof, prove_dur) = prover
                    .prove_timed(&t.input)
                    .await
                    .map_err(|e| eyre::eyre!("prove {}: {e}", t.id))?;
                let (pv, verify_dur) = prover
                    .verify_timed(&proof)
                    .await
                    .map_err(|e| eyre::eyre!("verify {}: {e}", t.id))?;
                total += prove_dur + verify_dur;
                check(&pv, &t.expected, &t.id);
                println!(
                    "[replay] Block: {} (slot {}, attestations {}), post {}, proof {} bytes | Proving Time: {}, Verification Time: {}",
                    t.id,
                    t.slot,
                    t.attestations,
                    ShortRoot(&t.expected.post_state_root.0),
                    proof.as_bytes().len(),
                    fmt_dur(prove_dur),
                    fmt_dur(verify_dur),
                );
            }
        }
    }
    let verb = match action {
        Action::Execute => "Executed",
        Action::Prove => "Proved",
    };
    println!(
        "[replay] {verb} {} transition(s) in {} ({})",
        transitions.len(),
        fmt_dur(total),
        throughput(transitions.len(), total),
    );
    Ok(())
}

#[cfg(feature = "sp1")]
fn check(
    pv: &ethlambda_prover_core::StfPublicValues,
    expected: &ethlambda_prover_core::StfPublicValues,
    id: &str,
) {
    assert_eq!(
        pv.pre_state_root, expected.pre_state_root,
        "pre_state_root at {id}"
    );
    assert_eq!(pv.block_root, expected.block_root, "block_root at {id}");
    assert_eq!(
        pv.post_state_root, expected.post_state_root,
        "post_state_root at {id}"
    );
}
