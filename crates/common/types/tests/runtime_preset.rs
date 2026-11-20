//! The preset is chosen when a process starts, not when it is compiled.
//!
//! This binary is built like any other (mainnet is the default), selects the
//! minimal preset at runtime, and checks that the containers bounded by a
//! value the presets disagree on take minimal's shapes. It holds a single test
//! on purpose: the preset is process-wide and frozen by its first read, so a
//! second test in this binary could read it first and decide the outcome.
//! The spec suites' `ssz_static` cases check the same thing exhaustively
//! (`BEACON_SPEC_PRESET=minimal`); this is the version that needs no fixtures.

use ethlambda_types::beacon::containers::altair::SyncCommitteeBits;
use ethlambda_types::beacon::containers::electra::CommitteeBits;
use ethlambda_types::beacon::containers::fulu::ProposerLookahead;
use ethlambda_types::beacon::containers::shared::BlockRoots;
use ethlambda_types::beacon::preset::{self, Preset, PresetAlreadyActive};
use libssz::{SszDecode as _, SszEncode as _};

#[test]
fn a_process_that_selects_minimal_builds_minimal_containers() {
    assert_eq!(Preset::require_unread(), Ok(()));
    Preset::select(Preset::Minimal).expect("nothing in this process read a preset before");
    // Selected, not frozen by a read: reads after the select change nothing.
    assert_eq!(Preset::active(), Preset::Minimal);
    assert_eq!(Preset::require_unread(), Ok(()));

    assert_eq!(Preset::active(), Preset::Minimal);
    assert_eq!(preset::slots_per_epoch(), preset::minimal::SLOTS_PER_EPOCH);
    assert_eq!(
        Preset::select(Preset::Mainnet),
        Err(PresetAlreadyActive {
            active: Preset::Minimal,
            requested: Preset::Mainnet,
        })
    );

    // Bitvectors: minimal's 32-member sync committee is 4 bytes on the wire,
    // and its 4 committees per slot fit in one.
    let sync_bits = SyncCommitteeBits::new();
    assert_eq!(sync_bits.len(), 32);
    assert_eq!(sync_bits.to_ssz().len(), 4);
    assert_eq!(CommitteeBits::new().to_ssz().len(), 1);
    // Mainnet's 64-byte sync bits are the wrong length for this process.
    assert!(SyncCommitteeBits::from_ssz_bytes(&[0; 64]).is_err());

    // A tree-backed state vector: 64 roots rather than mainnet's 8192.
    let block_roots = BlockRoots::default();
    assert_eq!(
        block_roots.len(),
        preset::minimal::SLOTS_PER_HISTORICAL_ROOT
    );
    assert_eq!(block_roots.to_ssz().len(), 64 * 32);

    // A flat vector: two epochs of eight slots.
    let lookahead = ProposerLookahead::try_from(vec![0; 16]).expect("minimal's length");
    assert_eq!(lookahead.to_ssz().len(), 16 * 8);
    assert!(ProposerLookahead::try_from(vec![0; 64]).is_err());
}
