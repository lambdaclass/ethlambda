//! Shared plumbing for the differential fuzz targets in `fuzz_targets/`.
//!
//! Every target decodes the same bytes twice, once through `ethlambda_beacon`
//! and once through lighthouse's `types` and `state_processing`, and asserts
//! that the two agree. This module holds what every target would otherwise
//! have to repeat: the corpus's byte framing, the mapping between the two
//! crates' independently-named forks, and construction of a matching
//! `Config`/`ChainSpec` pair for a given preset.
//!
//! See `README.md` for the corpus layout, how to run each target, and what a
//! disagreement means.

use ethlambda_beacon::ForkName;

// ---------------------------------------------------------------------------
// Fork and preset mapping
// ---------------------------------------------------------------------------

/// The forks this crate's state transition actually implements today.
///
/// `ethlambda_beacon::containers::BeaconState` only has `Phase0` and `Altair`
/// variants so far, and altair's own state transition is not written yet (see
/// the beacon crate's status notes in the repository root `CLAUDE.md`), so
/// phase0 is the only fork either side of the comparison can usefully run. A
/// fuzz input naming a fork outside this list is discarded before either
/// implementation sees it: a rejection there would come from
/// `Error::UnsupportedForFork`, which says nothing about whether the two
/// implementations agree, and comparing it against lighthouse (which
/// implements every fork) would only ever manufacture disagreements out of
/// this crate's incomplete coverage rather than a real one.
///
/// Extend this list fork by fork as `ethlambda_beacon` grows a state
/// transition for each one; nothing else in this module needs to change to
/// pick that fork up.
pub const IMPLEMENTED_FORKS: &[ForkName] = &[ForkName::Phase0];

/// Whether `fork` is one this crate's comparisons can run.
pub fn is_implemented(fork: ForkName) -> bool {
    IMPLEMENTED_FORKS.contains(&fork)
}

/// Picks a fork deterministically from a fuzz-provided byte.
///
/// Taken modulo the length of `ForkName::ALL` so every byte value maps to some
/// fork; callers still need [`is_implemented`] before running a comparison, so
/// that growing `ForkName::ALL` upstream (it will not: this repository
/// implements phase0 through fulu and stops there) could not silently expand
/// what a fixed corpus entry means.
pub fn fork_from_byte(byte: u8) -> ForkName {
    ForkName::ALL[byte as usize % ForkName::ALL.len()]
}

/// lighthouse's `types::ForkName` variant matching an `ethlambda_beacon` one.
///
/// The two crates disagree on phase0's name: lighthouse calls it `Base`
/// (`consensus/types/src/fork/fork_name.rs` in lighthouse's own tree),
/// everything from altair on shares a name with this crate's `ForkName`.
/// Written out as an explicit match rather than derived from discriminant
/// order, so a fork added to one enum before the other fails to compile
/// instead of silently comparing the wrong fork's rules.
pub fn to_lighthouse_fork(fork: ForkName) -> types::ForkName {
    match fork {
        ForkName::Phase0 => types::ForkName::Base,
        ForkName::Altair => types::ForkName::Altair,
        ForkName::Bellatrix => types::ForkName::Bellatrix,
        ForkName::Capella => types::ForkName::Capella,
        ForkName::Deneb => types::ForkName::Deneb,
        ForkName::Electra => types::ForkName::Electra,
        ForkName::Fulu => types::ForkName::Fulu,
    }
}

/// lighthouse's `EthSpec` matching this build's compiled-in preset.
///
/// `ethlambda_beacon` selects a preset with the `preset-minimal` Cargo
/// feature, since its container bounds are compile-time SSZ constants.
/// lighthouse selects one with a generic type parameter instead, since its
/// bounds are typenum constants and both `MainnetEthSpec` and
/// `MinimalEthSpec` can live in the same binary at once. There is nothing to
/// enable on lighthouse's side to match, only a type to name; this crate's own
/// `preset-minimal` feature (forwarded to `ethlambda-beacon/preset-minimal` in
/// `Cargo.toml`) drives which one that is, so a fuzz binary only ever compares
/// one preset against itself.
#[cfg(not(feature = "preset-minimal"))]
pub type LhSpec = types::MainnetEthSpec;
#[cfg(feature = "preset-minimal")]
pub type LhSpec = types::MinimalEthSpec;

/// The `ethlambda_beacon` configuration matching this build's preset.
pub fn our_config() -> ethlambda_beacon::config::Config {
    ethlambda_beacon::config::Config::active()
}

/// The lighthouse `ChainSpec` matching this build's preset.
///
/// Deliberately `LhSpec::default_spec()` with no fork-epoch override, the same
/// way `crates/beacon/tests/spec/sanity.rs` runs its fixtures against
/// `Config::active()` unmodified. That is sound while [`IMPLEMENTED_FORKS`] is
/// only phase0: phase0 is active from genesis in both `Config::mainnet`'s real
/// fork history and `Config::minimal`'s fixture-oriented one (and identically
/// in lighthouse's `ChainSpec::mainnet`/`ChainSpec::minimal`), so nothing in a
/// fixture-sized state's slot range ever crosses into a later fork's rules. A
/// fork added later whose real mainnet activation epoch a fixture-sized state
/// could not otherwise reach would need `ForkName::make_genesis_spec` here
/// instead, mirroring `Config::with_fork_epoch`.
pub fn lighthouse_spec() -> types::ChainSpec {
    <LhSpec as types::EthSpec>::default_spec()
}

// ---------------------------------------------------------------------------
// Corpus framing
// ---------------------------------------------------------------------------
//
// libFuzzer hands every target one flat `&[u8]`; splitting it into the fork
// selector and one or two SSZ blobs is this crate's own choice, documented
// here and in `README.md`, not a `cargo-fuzz` convention. Blobs are
// *decompressed* SSZ, not the `.ssz_snappy` fixtures' raw snappy bytes: a
// single bit flip in a snappy stream almost always just fails decompression
// rather than reaching the decode logic either implementation actually needs
// exercised, so `seed_corpus.sh` decompresses once, up front, and the corpus
// files on disk are already in this framing.

/// Splits a fuzz input into a fork selector, a length-prefixed first blob, and
/// a second blob running to the end.
///
/// Layout: `[fork: 1 byte][len: 4 bytes, little-endian][blob 1: len
/// bytes][blob 2: remaining bytes]`. Used by `state_transition`, where blob 1
/// is a pre-state and blob 2 is a signed block. The length prefix exists
/// because SSZ has no end-of-container marker of its own; recording blob 1's
/// length up front, rather than splitting the input some other way (in half,
/// say), means a mutator that only grows or shrinks the block leaves the
/// state bytes untouched, which keeps mutations closer to the single thing
/// they changed.
///
/// Returns `None` for inputs too short to hold the header, or whose declared
/// length overruns the input. Both are uninteresting inputs for a target to
/// discard, not malformed ones to report: nothing about a random byte string
/// satisfying this framing implies anything about either state transition.
pub fn split_two(data: &[u8]) -> Option<(ForkName, &[u8], &[u8])> {
    let (&fork_byte, rest) = data.split_first()?;
    let (len_bytes, rest) = rest.split_at_checked(4)?;
    let len = u32::from_le_bytes(len_bytes.try_into().expect("checked len 4")) as usize;
    let (first, second) = rest.split_at_checked(len)?;
    Some((fork_from_byte(fork_byte), first, second))
}

/// Splits a fuzz input into a fork selector and a single blob running to the
/// end.
///
/// Layout: `[fork: 1 byte][state: remaining bytes]`. Used by
/// `epoch_processing` and `ssz_roundtrip`, which each decode exactly one
/// container, so there is nothing after it to delimit.
pub fn split_one(data: &[u8]) -> Option<(ForkName, &[u8])> {
    let (&fork_byte, rest) = data.split_first()?;
    Some((fork_from_byte(fork_byte), rest))
}

// ---------------------------------------------------------------------------
// lighthouse-side state transition
// ---------------------------------------------------------------------------

/// lighthouse's equivalent of `ethlambda_beacon::stf::state_transition`.
///
/// lighthouse splits what this crate's `state_transition` does into two
/// public functions, plus cache bookkeeping that lighthouse's own `ef_tests`
/// (`testing/ef_tests/src/cases/sanity_blocks.rs`) always does around them:
/// advance one slot at a time with `per_slot_processing` (which runs epoch
/// processing itself at each boundary, same as this crate's `process_slots`),
/// then apply the block with `per_block_processing`.
/// `BlockSignatureStrategy::VerifyIndividual` plus `VerifyBlockRoot::True` is
/// the closest match to this crate's `validate_result: true`: both check the
/// proposer's signature, and both compare the block's own committed
/// `state_root` against the state that results from applying it (lighthouse
/// inside `per_block_processing`'s header check; `ethlambda_beacon` just after
/// `state_transition` returns).
///
/// The upfront slot check mirrors `process_slots`' own `verify(state.slot() <
/// slot, ...)`. lighthouse does not need the same check internally, because
/// every real caller already guarantees a strictly later slot by construction
/// (a proposer never builds on a slot at or before the chain's current head);
/// a fuzzed pre-state and block are not bound by that guarantee, so without
/// this check a stale block could take a different rejection path on
/// lighthouse's side than on this crate's, which would be this harness
/// manufacturing a disagreement rather than finding one.
pub fn lighthouse_state_transition<E: types::EthSpec>(
    state: &mut types::BeaconState<E>,
    signed_block: &types::SignedBeaconBlock<E>,
    spec: &types::ChainSpec,
) -> Result<(), String> {
    use state_processing::{BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot};

    let target_slot = signed_block.slot();
    if target_slot <= state.slot() {
        return Err("target slot is not after the current slot".to_string());
    }

    while state.slot() < target_slot {
        state_processing::per_slot_processing(state, None, spec)
            .map_err(|err| format!("per_slot_processing: {err:?}"))?;
    }

    state
        .build_committee_cache(types::RelativeEpoch::Current, spec)
        .map_err(|err| format!("build_committee_cache: {err:?}"))?;

    let mut ctxt = ConsensusContext::new(state.slot());
    state_processing::per_block_processing(
        state,
        signed_block,
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        spec,
    )
    .map_err(|err| format!("per_block_processing: {err:?}"))
}
