use ethlambda_types::{block::Block, state::State};

pub enum Error {}

pub struct StateChanges {}

pub fn state_transition(state: &State, block: &Block) -> Result<StateChanges, Error> {
    Ok(StateChanges {})
}
