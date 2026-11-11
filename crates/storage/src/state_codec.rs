//! The tagged state codecs shared by [`crate::store`] and [`crate::state_writer`].
//!
//! `store.rs` and `state_writer.rs` had begun importing from each other, and
//! the read path landing next would have added several more edges in one
//! direction. These three functions are what both sides actually share, and
//! they depend on nothing in either: [`BeaconState`], [`ForkName`], and SSZ.
//!
//! The equivalent tagged codec for signed beacon blocks,
//! `encode_beacon_block_value`/`decode_beacon_block_value`, stayed in
//! `store.rs`: it was the import cycle that forced this split, and nothing
//! outside `store.rs` reads or writes a block value, so there was no cycle to
//! break there.

use ethlambda_types::{
    beacon::{containers::BeaconState, fork::ForkName},
    state::State,
};

/// Encodes a `States` value: the state's fork selector, then the variant's own
/// SSZ.
///
/// The tag is what lets one table hold both a lean `State` and a beacon
/// `BeaconState` without the reader having to already know which it is. Note
/// [`ForkName::Lean`]'s selector is not a variant index, so the byte must go
/// back through [`ForkName::from_selector`] rather than being cast.
pub(crate) fn encode_state_value(state: &BeaconState) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(state.fork_name().selector());
    bytes.extend_from_slice(&state.to_ssz());
    bytes
}

/// The inverse of [`encode_state_value`].
///
/// `Err` names what is wrong with a value this build cannot tag-decode.
/// [`Store::from_db_state`](crate::store::Store::from_db_state) has already
/// rejected a directory of the wrong format version, so anything failing
/// here is corruption rather than an old database. The caller knows which
/// root it was reading and turns this into
/// [`Error::CorruptState`](crate::error::Error::CorruptState).
pub(crate) fn decode_state_value(bytes: &[u8]) -> Result<BeaconState, String> {
    let (tag, ssz) = bytes.split_first().ok_or("the value is empty")?;
    let fork =
        ForkName::from_selector(*tag).ok_or_else(|| format!("unknown fork selector {tag}"))?;
    BeaconState::from_ssz(fork, ssz).map_err(|err| format!("not a valid {fork} state: {err}"))
}

/// [`decode_state_value`] for the lean reader, which has no beacon shape to do
/// anything with: a beacon value in a lean directory is as corrupt as one
/// that does not decode, since a data directory holds one chain.
pub(crate) fn decode_lean_state_value(bytes: &[u8]) -> Result<State, String> {
    match decode_state_value(bytes)? {
        BeaconState::Lean(state) => Ok(state),
        beacon => Err(format!(
            "a {} state in a lean directory",
            beacon.fork_name()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_state_value_round_trips() {
        let state = BeaconState::Lean(State::from_genesis(7, vec![]));
        let bytes = encode_state_value(&state);
        assert_eq!(decode_state_value(&bytes), Ok(state));
    }

    #[test]
    fn the_selector_is_not_a_dense_index() {
        // ForkName::Lean is 255 so that beacon forks after fulu keep taking the
        // next free value. A reader that treated the tag as a variant index
        // would decode a lean state as phase0-shaped, so this pins the round
        // trip through from_selector rather than the raw byte.
        assert_eq!(ForkName::Lean.selector(), 255);
        assert_eq!(
            ForkName::from_selector(ForkName::Lean.selector()),
            Some(ForkName::Lean)
        );
    }
}
