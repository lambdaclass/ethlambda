//! The `transition` runner.
//!
//! Every other suite in this harness exercises one fork's rules against a
//! `pre` state already shaped for that fork. This one is the exception: its
//! block sequence starts on one fork and, partway through, crosses into the
//! next one, so the state itself has to change shape mid-run. It is the only
//! suite that drives [`upgrade::upgrade_state`] the way a real chain does,
//! from the middle of applying a chain of blocks rather than as a
//! self-contained fixture of its own, which is also why [`Config`] carries
//! fork activation epochs as runtime fields at all: see its own module doc.
//!
//! See `tests/formats/transition/README.md` in the pinned specification
//! checkout for the format in full. In outline: `meta.yaml` names
//! [`Meta::post_fork`], the fork the case ends on, and [`Meta::fork_epoch`],
//! the epoch that fork activates at (overriding [`Config`]'s own schedule for
//! that one boundary, per [`Config::with_fork_epoch`]'s own doc). The fork the
//! case *starts* on is never written down explicitly: the README states that
//! forks activate strictly in sequence, so it is always [`ForkName::previous`]
//! of `post_fork`. `pre.ssz_snappy` and `post.ssz_snappy` are a
//! [`BeaconState`] of the starting and ending fork respectively; the numbered
//! `blocks_<index>.ssz_snappy` files are [`SignedBeaconBlock`]s, of the
//! starting fork's shape up through [`Meta::fork_block`] and the ending
//! fork's shape from the next index on, or entirely the ending fork's shape
//! if `fork_block` is absent. No released case carries an `execution.yaml`, so
//! [`ExecutionEngine::valid`] is the right default for the same reason
//! `sanity.rs` gives it one: these cases test consensus-layer rules, not
//! execution-payload rejection.
//!
//! The case directory this suite's cases live under is itself named after
//! `post_fork`, which is how [`super::collect`] assigns [`Case::fork`] and
//! therefore how [`Case::in_scope`] gates them: a case whose chain ends on a
//! fork this crate does not implement is skipped whole, without inspecting
//! its `meta.yaml` at all, matching how every other runner uses that gate.
//! [`transition`] still parses `post_fork` back out of `meta.yaml` and checks
//! it against the directory rather than trusting the directory alone, since
//! the directory-encodes-`post_fork` convention is this suite's own layout,
//! not something the format's README commits to.
//!
//! # The upgrade belongs to `process_slots`, so this runner drives blocks only
//!
//! Every fork past phase0 documents the same rule in its own `fork.md`
//! (altair's is representative): once `process_slots` advances `state.slot` to
//! exactly the first slot of that fork's activation epoch, the state's shape
//! must change there and then, inside the loop, before slot processing
//! continues. Altair's `fork.md` also says why it has to live inside the loop
//! rather than around it in the outer `state_transition`: a caller normally
//! only invokes `process_slots` for whatever slot the next block sits at, so
//! with empty slots at the boundary nothing outside `process_slots` ever
//! learns the exact slot the fork activated at in order to upgrade there.
//!
//! [`ethlambda_beacon::stf::process_slots`] does this itself, which is what
//! lets this suite call [`stf::state_transition`] for every block exactly as
//! the other suites do, with no fork handling of its own beyond decoding each
//! block at the right shape. An earlier version of this runner drove the
//! upgrade from the outside, because `process_slots` had not yet grown the
//! check; doing that now would upgrade twice and fail, so the workaround is
//! gone rather than merely unused.
//!
//! One thing does remain this runner's own responsibility. A case whose blocks
//! all sit before the boundary still ends on `post_fork`'s shape, since that is
//! what `post.ssz_snappy` is encoded as, and with no post-boundary block to
//! carry `state_transition` across, nothing would advance `state.slot` far
//! enough to trigger the upgrade. [`apply_blocks`] finishes by advancing to the
//! boundary slot for that case, which is the same thing a real chain does when
//! it produces no block for the epoch a fork activates in.

use std::sync::Arc;

use ethlambda_beacon::ForkName;
use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_beacon::helpers::misc::compute_start_slot_at_epoch;
use ethlambda_beacon::primitives::Epoch;
use ethlambda_beacon::stf::{self, ExecutionEngine};
use libtest_mimic::Trial;

use super::{Case, PRESET, collect};

/// One case's `meta.yaml`.
///
/// See the module documentation for how [`Self::post_fork`] alone fixes the
/// starting fork too, and for what a missing [`Self::fork_block`] means.
#[derive(serde::Deserialize)]
struct Meta {
    /// The fork the chain has finished upgrading to by the last block. Named
    /// as a `String` here, rather than parsed straight into a [`ForkName`] by
    /// a custom `Deserialize`, because a case whose fork this crate does not
    /// recognize still has to produce a readable failure message rather than
    /// a serde error pointing at the wrong layer.
    post_fork: String,
    /// The epoch [`Self::post_fork`] activates at, overriding [`Config`]'s own
    /// schedule for this one boundary via [`Config::with_fork_epoch`].
    fork_epoch: Epoch,
    /// The index of the last `blocks_<index>.ssz_snappy` file still shaped
    /// like the fork before [`Self::post_fork`]. Every later index, up to
    /// [`Self::blocks_count`], is shaped like `post_fork` itself. Absent when
    /// every block in the case already belongs to `post_fork`, per the
    /// format's README.
    #[serde(default)]
    fork_block: Option<usize>,
    /// How many `blocks_<index>.ssz_snappy` files the case carries.
    blocks_count: usize,
}

/// Applies every block in the case, letting [`stf::process_slots`] perform the
/// shape upgrade as it advances into the fork's activation epoch.
///
/// Each block is decoded at its own fork's shape, which is the one thing the
/// case's `meta.yaml` has to be consulted for; from there
/// [`stf::state_transition`] handles a pre-fork and a post-fork block
/// identically. See the module documentation for why the trailing
/// [`stf::process_slots`] call is still needed for a case that never gets a
/// post-boundary block.
fn apply_blocks(
    case: &Case,
    meta: &Meta,
    pre_fork: ForkName,
    post_fork: ForkName,
    state: &mut BeaconState,
    config: &Config,
) -> Result<(), String> {
    let config = config.clone().with_fork_epoch(post_fork, meta.fork_epoch);
    // A missing `fork_block` means every block already belongs to `post_fork`
    // (index 0 included); otherwise `fork_block` is the *last* pre-fork
    // index, so the first post-fork one is the index right after it.
    let first_post_fork_index = meta.fork_block.map_or(0, |last_pre_fork_index| {
        last_pre_fork_index.saturating_add(1)
    });

    let engine = ExecutionEngine::valid();

    for index in 0..meta.blocks_count {
        let fork = if index < first_post_fork_index {
            pre_fork
        } else {
            post_fork
        };

        let bytes = case.ssz_bytes_indexed("blocks", index);
        let block = SignedBeaconBlock::from_ssz(fork, &bytes)
            .map_err(|err| format!("block {index} does not decode as {fork}: {err:?}"))?;

        stf::state_transition(state, &block, true, &config, &engine)
            .map_err(|err| format!("block {index} rejected: {err:?}"))?;
    }

    let boundary_slot = compute_start_slot_at_epoch(meta.fork_epoch);
    if state.slot() < boundary_slot {
        stf::process_slots(state, boundary_slot, &config)
            .map_err(|err| format!("advancing to the fork boundary: {err:?}"))?;
    }

    Ok(())
}

pub fn trials() -> Vec<Trial> {
    let config = Arc::new(Config::active());
    let cases = collect(PRESET, "transition", "core");
    let mut trials = vec![super::discovery_trial("transition", cases.len())];

    for case in cases {
        let config = Arc::clone(&config);
        trials.push(super::case_trial("transition", case, move |case| {
            let meta: Meta = case.yaml("meta");
            let post_fork = ForkName::parse(&meta.post_fork).unwrap_or_else(|| {
                panic!(
                    "{}: meta.yaml's post_fork ({}) is not a fork this crate recognizes",
                    case.id(),
                    meta.post_fork
                )
            });
            // The case directory encodes `post_fork` too (see the module doc), so
            // this checks the harness's own assumption about the fixture layout
            // rather than anything about this crate's state transition. A panic
            // here fails this one case, same as everywhere else in this closure.
            assert_eq!(
                post_fork,
                case.fork,
                "{}: meta.yaml's post_fork does not match the case's own directory",
                case.id()
            );
            let pre_fork = post_fork
                .previous()
                .unwrap_or_else(|| panic!("{}: post_fork can never be phase0", case.id()));

            let mut state = BeaconState::from_ssz(pre_fork, &case.ssz_bytes("pre"))
                .map_err(|err| format!("the fixture's pre-state does not decode: {err:?}"))?;

            let outcome = apply_blocks(case, &meta, pre_fork, post_fork, &mut state, &config);
            super::check_transition(case, outcome, &state)
        }));
    }

    trials
}
