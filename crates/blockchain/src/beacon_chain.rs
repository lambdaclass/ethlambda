//! The beacon arm of each [`crate::BlockChainServer`] handler.
//!
//! Nothing here is shared with `crate::store`, by decision: lean's fork-choice
//! weight is one vote per validator over an unfiltered tree, beacon's is summed
//! effective balances with proposer boost and equivocation exclusion over an
//! FFG-filtered tree, and only the descent loop itself coincides.
//!
//! `on_block` and `on_attestation` have no caller until plan 4 hands decoded
//! beacon objects to the actor. They are here, and tested, because the dispatch
//! they sit behind is what makes `BeaconState::Lean`'s `unreachable!()` arms
//! sound: the boundary has to exist before anything crosses it.

use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{SignedBeaconBlock, phase0};
use ethlambda_beacon::error::Result;
use ethlambda_beacon::fork_choice::{self, Attestation, AttesterSlashing, DataAvailability};
use ethlambda_beacon::primitives::Root;
use ethlambda_storage::Store;

/// Advances the store's clock to `timestamp_ms`.
///
/// The beacon clock is Unix **seconds**, so this is where the actor's
/// millisecond tick is truncated. That is not a loss of resolution the handler
/// cares about: `fork_choice`'s only sub-slot comparisons recompute
/// milliseconds from this value on demand (see its module documentation).
pub fn on_tick(store: &mut Store, timestamp_ms: u64, config: &Config) {
    fork_choice::on_tick(store, timestamp_ms / 1000, config);
}

/// Imports `block`, then replays every attestation and attester slashing its
/// body carries, matching what the reference test generator's `add_block` does.
///
/// `DataAvailability::NotRequired` unconditionally: no column subnet is
/// subscribed, so no sampling evidence exists to pass. Sub-project D is what
/// makes post-fulu data availability enforceable; until then this is logged once
/// at startup rather than silently implied.
pub fn on_block(store: &mut Store, block: SignedBeaconBlock, config: &Config) -> Result<()> {
    let (attestations, slashings) = block_operations(&block);
    fork_choice::on_block(store, block, config, &DataAvailability::NotRequired)?;

    for attestation in &attestations {
        fork_choice::on_attestation(store, attestation, true, config)?;
    }
    for slashing in &slashings {
        fork_choice::on_attester_slashing(store, slashing, config)?;
    }
    Ok(())
}

/// Applies a gossiped aggregate's attestation to fork choice.
pub fn on_attestation(store: &mut Store, attestation: &Attestation, config: &Config) -> Result<()> {
    fork_choice::on_attestation(store, attestation, false, config)
}

/// Records every validator common to both halves of `slashing` as equivocating.
pub fn on_attester_slashing(
    store: &mut Store,
    slashing: &AttesterSlashing,
    config: &Config,
) -> Result<()> {
    fork_choice::on_attester_slashing(store, slashing, config)
}

/// The LMD GHOST head.
pub fn head(store: &Store, config: &Config) -> Result<Root> {
    fork_choice::get_head(store, config)
}

/// The attestations and attester slashings carried in `block`'s body, in the
/// fork-generic shapes the handlers take.
fn block_operations(block: &SignedBeaconBlock) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    match block {
        SignedBeaconBlock::Electra(block) | SignedBeaconBlock::Fulu(block) => (
            block
                .message
                .body
                .attestations
                .iter()
                .cloned()
                .map(Attestation::Electra)
                .collect(),
            block
                .message
                .body
                .attester_slashings
                .iter()
                .cloned()
                .map(AttesterSlashing::Electra)
                .collect(),
        ),
        SignedBeaconBlock::Phase0(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Altair(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Bellatrix(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Capella(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
        SignedBeaconBlock::Deneb(block) => phase0_operations(
            block.message.body.attestations.iter(),
            block.message.body.attester_slashings.iter(),
        ),
    }
}

/// Phase0 through deneb share one attestation and slashing shape, so their five
/// arms above share one body.
///
/// Takes iterators rather than the lists themselves: each fork's body names its
/// own `SszList` bound, so a parameter typed on the list would need one generic
/// per bound, and `.iter()` erases exactly that difference.
fn phase0_operations<'a>(
    attestations: impl Iterator<Item = &'a phase0::Attestation>,
    slashings: impl Iterator<Item = &'a phase0::AttesterSlashing>,
) -> (Vec<Attestation>, Vec<AttesterSlashing>) {
    (
        attestations.cloned().map(Attestation::Phase0).collect(),
        slashings.cloned().map(AttesterSlashing::Phase0).collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_beacon::containers::Checkpoint;
    use ethlambda_storage::backend::InMemoryBackend;

    use super::*;

    #[test]
    fn the_beacon_tick_advances_the_store_in_seconds() {
        // The actor's clock is milliseconds and the beacon store's is seconds,
        // so this pins the one conversion the dispatch is responsible for.
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);

        on_tick(&mut store, 3 * config.seconds_per_slot * 1000, &config);

        assert_eq!(store.beacon_time(), 3 * config.seconds_per_slot);
    }

    #[test]
    fn the_beacon_tick_resets_the_proposer_boost_at_a_slot_boundary() {
        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        store.set_proposer_boost_root(Root::repeat_byte(1));

        on_tick(&mut store, config.seconds_per_slot * 1000, &config);

        assert_eq!(store.proposer_boost_root(), Root::zero());
    }

    #[test]
    fn the_beacon_tick_pulls_up_justification_at_an_epoch_boundary() {
        use ethlambda_beacon::preset;

        let config = Config::active();
        let mut store = Store::init_beacon(Arc::new(InMemoryBackend::new()), 0);
        let unrealized = Checkpoint {
            epoch: 1,
            root: Root::repeat_byte(5),
        };
        store.set_beacon_unrealized_justified_checkpoint(unrealized);

        let epoch_start_seconds = preset::SLOTS_PER_EPOCH * config.seconds_per_slot;
        on_tick(&mut store, epoch_start_seconds * 1000, &config);

        assert_eq!(store.beacon_justified_checkpoint(), unrealized);
    }
}
