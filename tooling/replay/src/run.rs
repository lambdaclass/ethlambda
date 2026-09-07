use ethlambda_types::ShortRoot;

use crate::Action;
use crate::fetcher::ReplayInput;

fn print_header(t: &ReplayInput) {
    println!("\n-- block {} --", t.id);
    println!(
        "  pre_state_root  : {}",
        ShortRoot(&t.expected.pre_state_root.0)
    );
    println!(
        "  block_root      : {}",
        ShortRoot(&t.expected.block_root.0)
    );
    println!(
        "  post_state_root : {}",
        ShortRoot(&t.expected.post_state_root.0)
    );
}

/// Host baseline: run `state_transition` directly, no zkVM. `--action` is
/// irrelevant here (there is no proof to generate).
#[cfg(not(feature = "sp1"))]
pub async fn run(_action: Action, transitions: &[ReplayInput]) -> eyre::Result<()> {
    use ethlambda_state_transition::state_transition;
    use ethlambda_types::primitives::HashTreeRoot as _;

    println!("Backend: exec (host state_transition, no zkVM)");
    for t in transitions {
        print_header(t);
        let mut state = t.input.state();
        let block = t.input.block();
        state_transition(&mut state, &block)
            .map_err(|e| eyre::eyre!("state_transition failed for {}: {e:?}", t.id))?;
        assert_eq!(
            state.hash_tree_root(),
            t.expected.post_state_root,
            "post_state_root mismatch at {}",
            t.id
        );
        println!("Execution Completed");
    }
    println!("\nExecuted {} transition(s) on the host", transitions.len());
    Ok(())
}

/// SP1 backend: run each transition through the guest via `execute` or
/// `prove` + `verify`, checking committed roots against the host expectation.
#[cfg(feature = "sp1")]
pub async fn run(action: Action, transitions: &[ReplayInput]) -> eyre::Result<()> {
    use ethlambda_prover_core::StfProver;
    use ethlambda_prover_sp1::Sp1Prover;

    println!("Backend: sp1 (MockProver)");
    let prover = Sp1Prover::new().await;
    for t in transitions {
        print_header(t);
        match action {
            Action::Execute => {
                let pv = prover
                    .execute(&t.input)
                    .await
                    .map_err(|e| eyre::eyre!("execute {}: {e}", t.id))?;
                check(&pv, &t.expected, &t.id);
                println!("Execution Completed");
            }
            Action::Prove => {
                let proof = prover
                    .prove(&t.input)
                    .await
                    .map_err(|e| eyre::eyre!("prove {}: {e}", t.id))?;
                let pv = prover
                    .verify(&proof)
                    .await
                    .map_err(|e| eyre::eyre!("verify {}: {e}", t.id))?;
                check(&pv, &t.expected, &t.id);
                println!("Proof bytes ({})", proof.as_bytes().len());
            }
        }
    }
    let verb = match action {
        Action::Execute => "Executed",
        Action::Prove => "Proved",
    };
    println!("\n{verb} {} transition(s) via SP1", transitions.len());
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
