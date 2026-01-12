use std::path::Path;

use ethlambda_types::state::State;

mod types;

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = types::StateTransitionTestVector::from_file(path)?;
    for (name, test) in tests.tests {
        println!("Running test: {}", name);

        let pre_state: State = test.pre.into();
    }
    return Ok(());
}

datatest_stable::harness!({test = run, root = "../../../leanSpec/fixtures/consensus/state_transition", pattern = r".*\.json"});
