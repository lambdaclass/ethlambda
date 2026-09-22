//! Mock-chain proving driver for the SP1 state-transition backend.
//!
//! Generates a mock chain and, depending on `--mode`, runs the guest over each
//! transition either via `execute` (no proof) or via `prove` + `verify`,
//! Each block carries attestations that advance the justification/finalization,
//! so the runs exercise the full state transition.

use clap::{Parser, ValueEnum};
use ethlambda_prover_core::{
    StfProver,
    mock_chain::{MockTransition, gen_mock_chain},
};
use ethlambda_prover_sp1::Sp1Prover;
use ethlambda_types::ShortRoot;

/// Run STF transitions over a mock chain. 
#[derive(Parser)]
#[command(name = "prove")]
struct Args {
    /// Number of blocks (transitions) in the mock chain.
    #[arg(short, long, default_value_t = 4)]
    blocks: u64,
    /// Number of validators in the genesis set.
    #[arg(short = 'n', long, default_value_t = 4)]
    validators: u64,
    /// Which guest path to run over the chain.
    #[arg(long, value_enum, default_value_t = Mode::Prove)]
    mode: Mode,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    /// Run the guest via `execute` only (no proof generated).
    Execute,
    /// Generate and verify a proof for each transition.
    Prove,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!(
        "Generating mock chain: {} blocks, {} validators",
        args.blocks, args.validators
    );
    let chain = gen_mock_chain(args.blocks, args.validators);

    println!("Setting up the SP1 prover");
    let prover = Sp1Prover::new().await;

    match args.mode {
        Mode::Execute => run_execute(&prover, &chain).await,
        Mode::Prove => run_prove(&prover, &chain).await,
    }
}

/// Execute path: run the guest without proving, per transition.
async fn run_execute(
    prover: &Sp1Prover,
    chain: &[MockTransition],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut prev_post = None;
    for (i, t) in chain.iter().enumerate() {
        print_transition_header(i + 1, chain.len(), t);
        check_chaining(prev_post, t, i + 1);

        print!("Execution started");
        let ev = prover.execute(&t.input).await?;
        assert_eq!(ev.pre_state_root, t.pre_state_root);
        assert_eq!(ev.block_root, t.block_root);
        assert_eq!(ev.post_state_root, t.post_state_root);
        println!("Execution completed");

        prev_post = Some(t.post_state_root);
    }
    println!("\nExecuted {} transitions over the mock chain", chain.len());
    Ok(())
}

/// Proving path: generate and verify a proof, per transition.
async fn run_prove(
    prover: &Sp1Prover,
    chain: &[MockTransition],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut prev_post = None;
    for (i, t) in chain.iter().enumerate() {
        print_transition_header(i + 1, chain.len(), t);
        check_chaining(prev_post, t, i + 1);


        let proof = prover.prove(&t.input).await?;
        println!("Generated Proof ({} bytes)", proof.as_bytes().len());

        let pv = prover.verify(&proof).await?;
        assert_eq!(pv.pre_state_root, t.pre_state_root);
        assert_eq!(pv.block_root, t.block_root);
        assert_eq!(pv.post_state_root, t.post_state_root);
        println!("Proof verified and the post_state_root is {}", ShortRoot(&pv.post_state_root.0));

        prev_post = Some(pv.post_state_root);
    }
    println!(
        "\nProved + verified {} transitions over the mock chain",
        chain.len()
    );
    Ok(())
}

fn print_transition_header(n: usize, total: usize, t: &MockTransition) {
    println!("\n-- transition {n}/{total} --");
    println!("  pre_state_root  : {}", ShortRoot(&t.pre_state_root.0));
    println!("  block_root      : {}", ShortRoot(&t.block_root.0));
    println!(
        "justified slot ={} finalized slot ={}",
        t.justified_slot, t.finalized_slot
    );
}

/// The previous transition's post-state root must equal this one's pre-state root.
fn check_chaining(
    prev_post: Option<ethlambda_types::primitives::H256>,
    t: &MockTransition,
    n: usize,
) {
    if let Some(prev) = prev_post {
        assert_eq!(prev, t.pre_state_root, "chain broken before transition {n}");
    }
}
