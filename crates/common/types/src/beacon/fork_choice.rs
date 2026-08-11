//! The two fork-choice containers that are neither a block nor a state.
//!
//! They live here rather than in `ethlambda-beacon`'s `fork_choice` module
//! because the DB-backed `ethlambda_storage::Store` holds them, and
//! `ethlambda-storage` cannot depend on `ethlambda-beacon`: the dependency runs
//! the other way. `ethlambda_beacon::fork_choice` re-exports both at their old
//! paths, so every use site inside that crate is unchanged.

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};

use crate::beacon::primitives::{Epoch, Root, Uint256};

/// One validator's most recent attestation: the epoch it targeted, and the
/// block it attested to (the LMD GHOST vote).
///
/// `Copy`, matching the specification's `@dataclass(eq=True, frozen=True)`:
/// there is nothing here worth borrowing rather than copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestMessage {
    pub epoch: Epoch,
    pub root: Root,
}

/// The execution chain's own block header, as far as bellatrix's merge
/// transition check needs it: `specs/bellatrix/fork-choice.md`'s `PowBlock`.
///
/// The specification's own `get_pow_block(hash) -> Optional[PowBlock]` is
/// "implementation and context dependent": a real client would ask its
/// execution engine. The fork choice store's own record of these, populated by
/// the fixture suites' `on_merge_block` step, is what stands in for that.
///
/// Defined at the top level here, unlike in its former home: this module has no
/// `Result` alias of its own for the `SszDecode` derive's generated code to
/// collide with, so the nested module that used to shield it is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct PowBlock {
    pub block_hash: Root,
    pub parent_hash: Root,
    /// The total work behind `block_hash`, compared against
    /// [`crate::beacon::config::Config::terminal_total_difficulty`] to decide
    /// whether this is the one PoW block the merge transitioned at.
    pub total_difficulty: Uint256,
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn a_pow_block_round_trips_through_ssz() {
        // The store persists these, so the derive has to survive the move out
        // of `ethlambda-beacon` intact.
        let block = PowBlock {
            block_hash: Root::repeat_byte(1),
            parent_hash: Root::repeat_byte(2),
            total_difficulty: Uint256::from(3u64),
        };
        let bytes = block.to_ssz();
        assert_eq!(
            PowBlock::from_ssz_bytes(&bytes).expect("valid pow block"),
            block
        );
    }
}
