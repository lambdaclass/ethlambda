//! `replay-era --hashing-trace`: recording what each step of a replay wrote to
//! the state's five validator-indexed lists, for `tooling/state-hashing-bench`.
//!
//! The replay runs `process_slots` one epoch boundary at a time and then
//! `apply_block`, which together are exactly `state_transition`, and diffs the
//! lists around each call. Every block still has its signatures and its
//! `state_root` checked, so the roots the trace records are the ones mainnet
//! committed to, not merely the ones this node computes. The format is in
//! [`super::hashing_trace`].

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use ethlambda_state_transition::beacon::stf;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{
    Balances, BeaconState, EpochParticipation, InactivityScores, Validator, Validators,
};
use ethlambda_types::beacon::preset;
use ethlambda_types::primitives::HashTreeRoot as _;
use eyre::{WrapErr as _, bail, ensure};
use libssz::SszEncode as _;
use tracing::info;

use super::hashing_trace::{
    Header, Lists, Roots, Step, StepKind, TraceWriter, VALIDATOR_LEN, ValidatorBytes, Writes,
};

pub(super) struct HashingRecorder {
    path: PathBuf,
    writer: TraceWriter<BufWriter<File>>,
    epoch_steps: u64,
    block_steps: u64,
    /// Elements written per list, over every block step.
    block_writes: [u64; 5],
}

impl HashingRecorder {
    /// Starts a trace at `state`, writing its lists in full.
    pub(super) fn start(path: &Path, network: &str, state: &BeaconState) -> eyre::Result<Self> {
        let lists = view(state)?;
        let header = Header {
            network: network.to_string(),
            fork: format!("{:?}", state.fork_name()),
            slot: state.slot(),
        };
        let file = File::create(path).wrap_err_with(|| format!("creating {}", path.display()))?;
        let writer = TraceWriter::new(BufWriter::new(file), &header, &lists.full(), &lists.roots())
            .wrap_err_with(|| format!("writing {}", path.display()))?;
        info!(
            path = %path.display(),
            slot = header.slot,
            validators = lists.validators.len(),
            "Hashing trace started"
        );
        Ok(Self {
            path: path.to_path_buf(),
            writer,
            epoch_steps: 0,
            block_steps: 0,
            block_writes: [0; 5],
        })
    }

    /// `process_slots` up to `slot`, one epoch boundary at a time, recording
    /// each boundary's epoch processing as its own step.
    ///
    /// The slots in between run `process_slot` alone, which writes none of
    /// the five lists, so they record nothing.
    pub(super) fn advance(
        &mut self,
        state: &mut BeaconState,
        slot: u64,
        config: &Config,
    ) -> eyre::Result<()> {
        let slots_per_epoch = preset::slots_per_epoch();
        while state.slot() < slot {
            let boundary = (state.slot() / slots_per_epoch + 1) * slots_per_epoch;
            if slot < boundary {
                stf::process_slots(state, slot, config)?;
                break;
            }
            let parent = state.clone();
            stf::process_slots(state, boundary, config)?;
            self.record(StepKind::Epoch, &parent, state)?;
        }
        Ok(())
    }

    /// Records the block that took `parent` to `state`.
    pub(super) fn block(&mut self, parent: &BeaconState, state: &BeaconState) -> eyre::Result<()> {
        self.record(StepKind::Block, parent, state)
    }

    fn record(
        &mut self,
        kind: StepKind,
        parent: &BeaconState,
        state: &BeaconState,
    ) -> eyre::Result<()> {
        let before = view(parent)?;
        let after = view(state)?;
        // The lists only ever grow, so `after` is `before`'s elements, changed
        // or not, then the appended ones.
        macro_rules! diff {
            ($list:ident, $encode:expr) => {{
                ensure!(
                    after.$list.len() >= before.$list.len(),
                    "{} shrank from {} to {} elements",
                    stringify!($list),
                    before.$list.len(),
                    after.$list.len()
                );
                diff_from(
                    before.$list.iter(),
                    after.$list.iter(),
                    after.$list.len(),
                    $encode,
                )?
            }};
        }
        let step = match kind {
            StepKind::Block => Step {
                kind,
                slot: state.slot(),
                rotation: None,
                validators: diff!(validators, validator_bytes),
                balances: diff!(balances, |&b| b),
                previous_participation: diff!(previous, |&f| f),
                current_participation: diff!(current, |&f| f),
                inactivity_scores: diff!(inactivity, |&s| s),
                roots: after.roots(),
            },
            StepKind::Epoch => {
                // Epoch processing ends by rotating participation (see
                // `Step::rotation`): previous is the old current, extended with
                // the zero flags of any validator added this epoch, and current
                // is all zeros. Only what differs from that is a write.
                let len = after.current.len();
                let rotated_previous = before.current.iter().chain(std::iter::repeat(&0));
                Step {
                    kind,
                    slot: state.slot(),
                    rotation: Some(u32::try_from(len)?),
                    validators: diff!(validators, validator_bytes),
                    balances: diff!(balances, |&b| b),
                    previous_participation: diff_from(
                        rotated_previous,
                        after.previous.iter(),
                        after.previous.len(),
                        |&f| f,
                    )?,
                    current_participation: diff_from(
                        std::iter::repeat(&0),
                        after.current.iter(),
                        len,
                        |&f| f,
                    )?,
                    inactivity_scores: diff!(inactivity, |&s| s),
                    roots: after.roots(),
                }
            }
        };
        match kind {
            StepKind::Epoch => self.epoch_steps += 1,
            StepKind::Block => {
                self.block_steps += 1;
                let counts = [
                    step.validators.count(),
                    step.balances.count(),
                    step.previous_participation.count(),
                    step.current_participation.count(),
                    step.inactivity_scores.count(),
                ];
                for (total, count) in self.block_writes.iter_mut().zip(counts) {
                    *total += count as u64;
                }
            }
        }
        self.writer
            .step(&step)
            .wrap_err_with(|| format!("writing {}", self.path.display()))
    }

    /// Marks the trace complete. A trace never finished (the replay failed
    /// part way) has no end marker, and the bench refuses it.
    pub(super) fn finish(self) -> eyre::Result<()> {
        self.writer
            .finish()
            .and_then(|mut file| std::io::Write::flush(&mut file))
            .wrap_err_with(|| format!("finishing {}", self.path.display()))?;
        let per_block = |total: u64| total.checked_div(self.block_steps).unwrap_or(0);
        info!(
            path = %self.path.display(),
            epoch_steps = self.epoch_steps,
            block_steps = self.block_steps,
            validators_per_block = per_block(self.block_writes[0]),
            balances_per_block = per_block(self.block_writes[1]),
            previous_participation_per_block = per_block(self.block_writes[2]),
            current_participation_per_block = per_block(self.block_writes[3]),
            inactivity_scores_per_block = per_block(self.block_writes[4]),
            "Hashing trace written"
        );
        Ok(())
    }
}

/// The five lists of one state.
struct View<'a> {
    validators: &'a Validators,
    balances: &'a Balances,
    previous: &'a EpochParticipation,
    current: &'a EpochParticipation,
    inactivity: &'a InactivityScores,
}

fn view(state: &BeaconState) -> eyre::Result<View<'_>> {
    macro_rules! view {
        ($state:expr) => {
            View {
                validators: &$state.validators,
                balances: &$state.balances,
                previous: &$state.previous_epoch_participation,
                current: &$state.current_epoch_participation,
                inactivity: &$state.inactivity_scores,
            }
        };
    }
    Ok(match state {
        BeaconState::Altair(state) => view!(state),
        BeaconState::Bellatrix(state) => view!(state),
        BeaconState::Capella(state) => view!(state),
        BeaconState::Deneb(state) => view!(state),
        BeaconState::Electra(state) => view!(state),
        BeaconState::Fulu(state) => view!(state),
        other => bail!(
            "--hashing-trace covers altair through fulu, not {:?}: phase0 has no participation \
             lists, and gloas's lists are progressive",
            other.fork_name()
        ),
    })
}

impl View<'_> {
    fn full(&self) -> Lists {
        Lists {
            validators: self.validators.iter().map(validator_bytes).collect(),
            balances: self.balances.iter().copied().collect(),
            previous_participation: self.previous.iter().copied().collect(),
            current_participation: self.current.iter().copied().collect(),
            inactivity_scores: self.inactivity.iter().copied().collect(),
        }
    }

    fn roots(&self) -> Roots {
        Roots {
            validators: self.validators.hash_tree_root().0,
            balances: self.balances.hash_tree_root().0,
            previous_participation: self.previous.hash_tree_root().0,
            current_participation: self.current.hash_tree_root().0,
            inactivity_scores: self.inactivity.hash_tree_root().0,
        }
    }
}

fn validator_bytes(validator: &Validator) -> ValidatorBytes {
    let bytes = validator.to_ssz();
    debug_assert_eq!(bytes.len(), VALIDATOR_LEN);
    bytes.try_into().expect("a validator encodes to 121 bytes")
}

/// Every element of `after` that differs from the element of `before` at its
/// index, where a `before` that has run out differs from everything.
fn diff_from<'a, T: PartialEq + 'a, V>(
    mut before: impl Iterator<Item = &'a T>,
    after: impl Iterator<Item = &'a T>,
    len: usize,
    encode: impl Fn(&T) -> V,
) -> eyre::Result<Writes<V>> {
    let mut writes = Writes {
        len: u32::try_from(len)?,
        indices: Vec::new(),
        values: Vec::new(),
    };
    for (index, value) in after.enumerate() {
        if before.next() != Some(value) {
            writes.indices.push(u32::try_from(index)?);
            writes.values.push(encode(value));
        }
    }
    Ok(writes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_diff_holds_the_changed_and_the_appended_elements() {
        let before = [1u64, 2, 3];
        let after = [1u64, 5, 3, 0, 7];
        let writes = diff_from(before.iter(), after.iter(), after.len(), |&v| v).unwrap();
        assert_eq!(writes.len, 5);
        assert_eq!(writes.indices, [1, 3, 4]);
        assert_eq!(writes.values, [5, 0, 7]);
    }

    #[test]
    fn a_rotation_diff_records_only_what_departs_from_zeros() {
        let after = [0u8, 0, 7, 0];
        let writes = diff_from(std::iter::repeat(&0), after.iter(), 4, |&v| v).unwrap();
        assert_eq!(writes.indices, [2]);
        assert_eq!(writes.values, [7]);
    }
}
