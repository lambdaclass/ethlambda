//! Gossip validation for the gloas `proposer_preferences` topic: a proposer's
//! `SignedProposerPreferences` (fee recipient and gas target) for a slot, which
//! bids on that slot are judged against.
//!
//! The rules are the specification's `validate_proposer_preferences_gossip`
//! (`specs/gloas/p2p-interface.md`), split like [`super::envelope`]:
//! [`cheap_checks`] inline in the p2p actor, [`stateful_checks`] on a blocking
//! thread, reading cached states only. The caller records the preferences in
//! the [`BuilderMarket`] on `Accept`.
//!
//! Deliberate departures from the specification (`docs/spec_deviations.md`):
//!
//! - Never queues: an unseen dependent block is IGNORE, and a state that is
//!   not cached is IGNORE, not rebuilt from disk.
//! - The lookahead comes from the cached head state when the head shares the
//!   dependent root (the whole canonical case, and a dependent block about an
//!   epoch old is usually evicted from the state cache), else from the cached
//!   checkpoint state of the epoch before the proposal's.
//! - The signature verifies under any of three domains, since clients disagree
//!   at the fork boundary: see [`proposer_preferences_domains`].

use ethlambda_storage::CacheKey;

use super::execution_payload_bid::cached_checkpoint_state;
use super::{
    IgnoreReason, Outcome, RejectReason, ancestor_at, is_future_slot, is_gloas_slot, slot_start_ms,
};
use crate::beacon::bls;
use crate::beacon::builder_market::BuilderMarket;
use crate::beacon::config::Config;
use crate::beacon::constants::{DOMAIN_PROPOSER_PREFERENCES, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use crate::beacon::containers::{BeaconState, gloas};
use crate::beacon::fork_choice::{
    Store, compute_shuffling_dependent_slot, compute_shuffling_lookahead_start_slot,
};
use crate::beacon::helpers::accessors::get_domain;
use crate::beacon::helpers::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::beacon::precheck::fixed_proposer;
use crate::beacon::preset;
use crate::beacon::primitives::{Domain, Epoch, HashTreeRoot as _, Root, Slot};

/// The rules that read only the message, the market's seen state and the
/// clock.
pub fn cheap_checks(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedProposerPreferences,
    now_ms: u64,
) -> Result<(), Outcome> {
    let preferences = &signed.message;
    let config = store.config();
    // [IGNORE] The first valid preferences for this dependent root and slot.
    if market
        .preferences(preferences.proposal_slot, preferences.dependent_root)
        .is_some()
    {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The proposal epoch is after the gloas upgrade.
    if !is_gloas_slot(&config, preferences.proposal_slot) {
        return Err(Outcome::Ignore(IgnoreReason::PreGloasSlot));
    }
    // [IGNORE] The proposal slot has not started yet.
    if is_past_slot(&config, preferences.proposal_slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::SlotStarted));
    }
    // [IGNORE] The proposer for the proposal slot is known.
    let proposal_epoch = compute_epoch_at_slot(preferences.proposal_slot);
    let lookahead_start_slot = compute_shuffling_lookahead_start_slot(proposal_epoch);
    if is_future_slot(&config, lookahead_start_slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::BeyondLookahead));
    }
    Ok(())
}

/// The rules that need the dependent block and a state, then the signature.
/// Runs on a blocking thread.
pub fn stateful_checks(store: &Store, signed: &gloas::SignedProposerPreferences) -> Outcome {
    match stateful_rules(store, signed) {
        Ok(()) => Outcome::Accept,
        Err(outcome) => outcome,
    }
}

fn stateful_rules(store: &Store, signed: &gloas::SignedProposerPreferences) -> Result<(), Outcome> {
    let preferences = &signed.message;
    let config = store.config();
    let proposal_epoch = compute_epoch_at_slot(preferences.proposal_slot);
    let dependent_slot = compute_shuffling_dependent_slot(proposal_epoch);

    // [IGNORE] The dependent block has been seen (never queued).
    if !store.has_block(&preferences.dependent_root) {
        return Err(Outcome::Ignore(IgnoreReason::UnknownBlock));
    }
    // [IGNORE] The dependent block passes validation, i.e. has a post-state.
    if !store
        .has_state(&preferences.dependent_root)
        .unwrap_or(false)
    {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    }
    // [REJECT] The dependent block is not after the shuffling dependent slot.
    let (block_slot, _) = store
        .block_entry(&preferences.dependent_root)
        .ok_or(Outcome::Ignore(IgnoreReason::UnknownBlock))?;
    if block_slot > dependent_slot {
        return Err(Outcome::Reject(RejectReason::DependentRootTooLate));
    }
    // [IGNORE] The dependent block is a possible dependent block.
    if !is_valid_dependent_root(store, preferences.dependent_root, dependent_slot) {
        return Err(Outcome::Ignore(IgnoreReason::ImpossibleDependentRoot));
    }

    let state = lookahead_state(store, preferences, proposal_epoch)
        .ok_or(Outcome::Ignore(IgnoreReason::StateUnavailable))?;

    // [REJECT] The validator is the proposer for the slot in the lookahead.
    if fixed_proposer(&state, preferences.proposal_slot) != Some(preferences.validator_index) {
        return Err(Outcome::Reject(RejectReason::WrongProposer));
    }
    // [REJECT] The signature is valid, under any candidate domain.
    let pubkey = state
        .validator(preferences.validator_index)
        .map_err(|_| Outcome::Reject(RejectReason::WrongProposer))?
        .pubkey;
    let message_root = preferences.hash_tree_root();
    let valid = proposer_preferences_domains(&state, &config, proposal_epoch)
        .into_iter()
        .any(|domain| {
            bls::verify(
                &pubkey,
                compute_signing_root(message_root, domain),
                &signed.signature,
            )
        });
    if !valid {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(())
}

/// A cached state whose proposer lookahead answers for `preferences`: the
/// head's when the head shares the dependent root, else the dependent block's
/// state advanced to the epoch before the proposal's.
fn lookahead_state(
    store: &Store,
    preferences: &gloas::ProposerPreferences,
    proposal_epoch: Epoch,
) -> Option<std::sync::Arc<BeaconState>> {
    if let Ok(head_root) = store.head()
        && let Some(head_state) = store.cached_state(CacheKey::BlockState(head_root))
    {
        // A state in the epoch before the proposal's, or in the proposal's
        // own, holds the proposal slot in its two-epoch window.
        let state_epoch = compute_epoch_at_slot(head_state.slot());
        let covers = state_epoch == proposal_epoch
            || state_epoch + preset::MIN_SEED_LOOKAHEAD == proposal_epoch;
        if covers
            && dependent_root_at(&head_state, head_root, preferences.proposal_slot)
                == Some(preferences.dependent_root)
        {
            return Some(head_state);
        }
    }
    cached_checkpoint_state(
        store,
        proposal_epoch.saturating_sub(preset::MIN_SEED_LOOKAHEAD),
        preferences.dependent_root,
    )
}

/// Both halves. The caller records the preferences on `Accept`: the
/// specification's `validate_proposer_preferences_gossip`.
pub fn validate(
    market: &BuilderMarket,
    store: &Store,
    signed: &gloas::SignedProposerPreferences,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(market, store, signed, now_ms) {
        return outcome;
    }
    stateful_checks(store, signed)
}

/// The spec's `is_valid_dependent_root`: `root == store.head()`, or some block
/// in the index has `parent_root == root` and `slot > dependent_slot`.
pub fn is_valid_dependent_root(store: &Store, root: Root, dependent_slot: Slot) -> bool {
    if store.head().is_ok_and(|head| head == root) {
        return true;
    }
    store
        .block_index()
        .values()
        .any(|&(slot, parent_root)| parent_root == root && slot > dependent_slot)
}

/// `ancestor_at(state, state_block_root, compute_shuffling_dependent_slot(
/// epoch(proposal_slot)))`: the block that fixed the proposal slot's proposer
/// shuffling on the chain `state` is the post-state of. Used by `produceBlockV4`
/// and the validator client.
pub fn dependent_root_at(
    state: &BeaconState,
    state_block_root: Root,
    proposal_slot: Slot,
) -> Option<Root> {
    let dependent_slot = compute_shuffling_dependent_slot(compute_epoch_at_slot(proposal_slot));
    ancestor_at(state, state_block_root, dependent_slot)
}

/// The distinct candidate signing domains, tried in order: `get_domain(
/// lookahead_state, DOMAIN_PROPOSER_PREFERENCES, Some(P))` (the specification's);
/// the schedule's fork version at `P - MIN_SEED_LOOKAHEAD` (saturating); and the
/// schedule's at `P`.
///
/// Outside the first epoch of a fork the three coincide. Across a boundary
/// the specification's gives the version of the epoch before the proposal's,
/// while lighthouse signs with the proposal epoch's, so accepting both avoids
/// rejecting an honest client's messages around the gloas upgrade.
pub fn proposer_preferences_domains(
    lookahead_state: &BeaconState,
    config: &Config,
    proposal_epoch: Epoch,
) -> Vec<Domain> {
    let genesis_validators_root = lookahead_state.genesis_validators_root();
    let at = |epoch: Epoch| {
        compute_domain(
            DOMAIN_PROPOSER_PREFERENCES,
            config.fork_version(config.fork_at_epoch(epoch)),
            genesis_validators_root,
        )
    };
    let domains = [
        get_domain(
            lookahead_state,
            DOMAIN_PROPOSER_PREFERENCES,
            Some(proposal_epoch),
        ),
        at(proposal_epoch.saturating_sub(preset::MIN_SEED_LOOKAHEAD)),
        at(proposal_epoch),
    ];
    let mut distinct: Vec<Domain> = Vec::with_capacity(domains.len());
    for domain in domains {
        if !distinct.contains(&domain) {
            distinct.push(domain);
        }
    }
    distinct
}

/// `now > slot_start + MAXIMUM_GOSSIP_CLOCK_DISPARITY`: the specification's
/// `is_past_slot`.
pub(crate) fn is_past_slot(config: &Config, slot: Slot, now_ms: u64) -> bool {
    now_ms > slot_start_ms(config, slot).saturating_add(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
}

#[cfg(test)]
mod tests {
    use ethlambda_storage::ForkCheckpoints;
    use ethlambda_types::beacon::containers::Fork;

    use super::*;
    use crate::beacon::builder_market::test_support::sign_preferences;
    use crate::beacon::fork::ForkName;
    use crate::beacon::gossip::test_support::builder_scene::*;
    use crate::beacon::gossip::test_support::{slot_start_ms, store};
    use crate::beacon::helpers::test_state::{secret_key_for, with_signing_validators_at};
    use crate::beacon::preset::SLOTS_PER_EPOCH;
    use crate::beacon::primitives::ValidatorIndex;
    use crate::beacon::stf;

    /// The epoch-2 slot the scene's proposer preferences name, and the block
    /// that fixed its proposer: the genesis-slot block, an ancestor of the
    /// head (`PARENT_SLOT`) whose `block_roots` entry covers `DEPENDENT_SLOT`.
    const PROPOSAL_SLOT: Slot = 2 * SLOTS_PER_EPOCH;
    const DEPENDENT: Root = Root::repeat_byte(0x31);
    /// `PROPOSAL_SLOT`'s shuffling dependent slot: the last of epoch 0.
    const DEPENDENT_SLOT: Slot = PARENT_SLOT - 1;

    fn ignore(reason: IgnoreReason) -> Outcome {
        Outcome::Ignore(reason)
    }

    fn reject(reason: RejectReason) -> Outcome {
        Outcome::Reject(reason)
    }

    /// The builder scene, with the parent's `block_roots` naming `DEPENDENT` at
    /// `DEPENDENT_SLOT`, and `DEPENDENT` stored (block and state) as the head's parent.
    fn dependent_scene() -> Scene {
        let mut scene = scene_with(|state| state.block_roots[DEPENDENT_SLOT as usize] = DEPENDENT);
        scene
            .store
            .insert_pending_block(DEPENDENT, block_at(0))
            .expect("insert the dependent block");
        // The head, as a live-chain child of the dependent block: the rule
        // that a dependent block is possible reads the live chain.
        scene
            .store
            .insert_signed_block(PARENT, block_with_parent(PARENT_SLOT, DEPENDENT))
            .expect("link the head to the dependent block");
        let mut dependent_state = scene.state.clone();
        *dependent_state.slot_mut() = 0;
        scene
            .store
            .insert_state(DEPENDENT, dependent_state)
            .expect("insert the dependent state");
        scene
    }

    fn preferences_for(
        scene: &Scene,
        dependent_root: Root,
        proposer: ValidatorIndex,
    ) -> gloas::SignedProposerPreferences {
        sign_preferences(
            &scene.state,
            gloas::ProposerPreferences {
                dependent_root,
                proposal_slot: PROPOSAL_SLOT,
                validator_index: proposer,
                fee_recipient: fee_recipient(),
                target_gas_limit: 30_000_000,
            },
        )
    }

    /// Valid preferences from the head's lookahead.
    fn valid_preferences(scene: &Scene) -> gloas::SignedProposerPreferences {
        let proposer =
            crate::beacon::precheck::fixed_proposer(&scene.state, PROPOSAL_SLOT).expect("window");
        preferences_for(scene, DEPENDENT, proposer)
    }

    fn now_ms(scene: &Scene) -> u64 {
        scene.now_ms()
    }

    #[test]
    fn valid_preferences_are_accepted_from_the_head_state() {
        let scene = dependent_scene();
        let preferences = valid_preferences(&scene);
        let outcome = validate(&scene.market, &scene.store, &preferences, now_ms(&scene));
        assert_eq!(outcome, Outcome::Accept);
        // The head's own lookahead answered: nothing was advanced and cached.
        let key = CacheKey::CheckpointState {
            epoch: 1,
            root: DEPENDENT,
        };
        assert!(scene.store.cached_state(key).is_none());
    }

    // ---- cheap rules ----

    #[test]
    fn a_second_message_for_a_key_is_already_seen() {
        let scene = dependent_scene();
        let preferences = valid_preferences(&scene);
        assert!(
            scene
                .market
                .record_preferences(preferences.clone(), PARENT_SLOT + 1)
        );
        assert_eq!(
            cheap_checks(&scene.market, &scene.store, &preferences, now_ms(&scene)),
            Err(ignore(IgnoreReason::AlreadySeen))
        );
    }

    #[test]
    fn preferences_before_the_fork_are_ignored() {
        let scene = dependent_scene();
        let fulu = store(0);
        let preferences = valid_preferences(&scene);
        assert_eq!(
            cheap_checks(&scene.market, &fulu, &preferences, now_ms(&scene)),
            Err(ignore(IgnoreReason::PreGloasSlot))
        );
    }

    #[test]
    fn preferences_are_late_once_the_slot_began_by_more_than_the_disparity() {
        let scene = dependent_scene();
        let preferences = valid_preferences(&scene);
        let started = slot_start_ms(&scene.store, PROPOSAL_SLOT);
        let check = |now| cheap_checks(&scene.market, &scene.store, &preferences, now);
        assert_eq!(check(started + 500), Ok(()));
        assert_eq!(check(started + 501), Err(ignore(IgnoreReason::SlotStarted)));
    }

    #[test]
    fn preferences_are_early_before_the_lookahead_opens() {
        let scene = dependent_scene();
        let mut preferences = valid_preferences(&scene);
        // Epoch 3's lookahead opens with epoch 2's first slot.
        preferences.message.proposal_slot = 3 * SLOTS_PER_EPOCH;
        let opens = slot_start_ms(&scene.store, 2 * SLOTS_PER_EPOCH);
        let check = |now| cheap_checks(&scene.market, &scene.store, &preferences, now);
        assert_eq!(check(opens - 500), Ok(()));
        assert_eq!(
            check(opens - 501),
            Err(ignore(IgnoreReason::BeyondLookahead))
        );
    }

    // ---- stateful rules ----

    #[test]
    fn preferences_naming_an_unseen_dependent_block_are_ignored() {
        let scene = dependent_scene();
        let preferences = preferences_for(&scene, Root::repeat_byte(0x99), 0);
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            ignore(IgnoreReason::UnknownBlock)
        );
    }

    #[test]
    fn a_dependent_block_without_a_state_is_ignored() {
        let mut scene = dependent_scene();
        let stateless = Root::repeat_byte(0x62);
        scene
            .store
            .insert_pending_block(stateless, block_at(DEPENDENT_SLOT - 1))
            .expect("insert the block");
        let preferences = preferences_for(&scene, stateless, 0);
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            ignore(IgnoreReason::StateUnavailable)
        );
    }

    #[test]
    fn a_dependent_block_after_the_dependent_slot_is_rejected() {
        let scene = dependent_scene();
        // The head itself is at `PARENT_SLOT`, after `DEPENDENT_SLOT`.
        let preferences = preferences_for(&scene, PARENT, 0);
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            reject(RejectReason::DependentRootTooLate)
        );
    }

    #[test]
    fn a_dependent_block_no_chain_can_use_is_ignored() {
        let mut scene = dependent_scene();
        let stray = Root::repeat_byte(0x63);
        scene
            .store
            .insert_pending_block(stray, block_at(DEPENDENT_SLOT - 1))
            .expect("insert the block");
        scene
            .store
            .insert_state(stray, scene.state.clone())
            .expect("insert the state");
        let preferences = preferences_for(&scene, stray, 0);
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            ignore(IgnoreReason::ImpossibleDependentRoot)
        );
        assert!(!is_valid_dependent_root(
            &scene.store,
            stray,
            DEPENDENT_SLOT
        ));
        assert!(is_valid_dependent_root(
            &scene.store,
            PARENT,
            DEPENDENT_SLOT
        ));
    }

    #[test]
    fn a_validator_that_is_not_the_proposer_is_rejected() {
        let scene = dependent_scene();
        let proposer =
            crate::beacon::precheck::fixed_proposer(&scene.state, PROPOSAL_SLOT).expect("window");
        let other = (proposer + 1) % 8;
        let preferences = preferences_for(&scene, DEPENDENT, other);
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            reject(RejectReason::WrongProposer)
        );
    }

    #[test]
    fn a_bad_signature_is_rejected() {
        let scene = dependent_scene();
        let mut preferences = valid_preferences(&scene);
        preferences.signature.0[5] ^= 1;
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            reject(RejectReason::BadSignature)
        );
    }

    #[test]
    fn a_dependent_block_off_the_head_uses_the_cached_checkpoint_state() {
        let mut scene = dependent_scene();
        // The dependent block is the head, whose own state is epoch 0, so the
        // lookahead has to come from its state advanced to epoch 1.
        scene
            .store
            .update_checkpoints(ForkCheckpoints::head_only(DEPENDENT))
            .expect("move the head");
        let mut advanced = scene
            .store
            .cached_state(CacheKey::BlockState(DEPENDENT))
            .expect("stored");
        let mut owned = (*advanced).clone();
        stf::process_slots(&mut owned, PARENT_SLOT, &scene.store.config()).expect("advance");
        advanced = std::sync::Arc::new(owned);
        let proposer =
            crate::beacon::precheck::fixed_proposer(&advanced, PROPOSAL_SLOT).expect("window");
        let preferences = preferences_for(&scene, DEPENDENT, proposer);
        let key = CacheKey::CheckpointState {
            epoch: 1,
            root: DEPENDENT,
        };
        assert!(scene.store.cached_state(key).is_none());
        assert_eq!(stateful_checks(&scene.store, &preferences), Outcome::Accept);
        assert!(scene.store.cached_state(key).is_some());
    }

    #[test]
    fn a_dependent_state_evicted_from_the_cache_is_ignored_not_rebuilt() {
        let mut scene = dependent_scene();
        scene
            .store
            .update_checkpoints(ForkCheckpoints::head_only(DEPENDENT))
            .expect("move the head");
        let preferences = valid_preferences(&scene);
        // Fill the bounded state cache with other blocks' states until the
        // dependent block's is pushed out. The state still exists (`has_state`),
        // but reading it would mean a rebuild from disk.
        for byte in 0..64u8 {
            let mut root = Root::repeat_byte(0xA0);
            root.0[1] = byte;
            scene
                .store
                .insert_state(root, scene.state.clone())
                .expect("insert a filler state");
        }
        assert!(
            scene
                .store
                .cached_state(CacheKey::BlockState(DEPENDENT))
                .is_none()
        );
        assert!(scene.store.has_state(&DEPENDENT).expect("has_state"));
        assert_eq!(
            stateful_checks(&scene.store, &preferences),
            ignore(IgnoreReason::StateUnavailable)
        );
    }

    // ---- dependent roots and domains ----

    #[test]
    fn the_dependent_root_is_the_ancestor_at_the_shuffling_dependent_slot() {
        let scene = dependent_scene();
        assert_eq!(
            dependent_root_at(&scene.state, PARENT, PROPOSAL_SLOT),
            Some(DEPENDENT)
        );
        // At genesis the slot saturates to the state's own block.
        let mut genesis = scene.state.clone();
        *genesis.slot_mut() = 0;
        assert_eq!(dependent_root_at(&genesis, PARENT, 5), Some(PARENT));
    }

    fn boundary_config() -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Fulu, 0)
            .with_fork_epoch(ForkName::Gloas, 2)
    }

    fn fulu_state_with_fork(config: &Config) -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, 8);
        *state.fork_mut() = Fork {
            previous_version: config.fork_version(ForkName::Electra),
            current_version: config.fork_version(ForkName::Fulu),
            epoch: 0,
        };
        state
    }

    #[test]
    fn across_the_fork_both_neighbouring_versions_are_candidates() {
        let config = boundary_config();
        let state = fulu_state_with_fork(&config);
        let root = state.genesis_validators_root();
        let at =
            |fork| compute_domain(DOMAIN_PROPOSER_PREFERENCES, config.fork_version(fork), root);
        // Proposal epoch 2 is gloas's first: the lookahead state's fork (fulu)
        // and the epoch before the proposal's agree, the proposal epoch's is gloas.
        let domains = proposer_preferences_domains(&state, &config, 2);
        assert_eq!(domains, vec![at(ForkName::Fulu), at(ForkName::Gloas)]);

        // A signature under either verifies; one under neither does not.
        let preferences = gloas::ProposerPreferences {
            proposal_slot: 2 * SLOTS_PER_EPOCH,
            ..Default::default()
        };
        let message_root = preferences.hash_tree_root();
        let sign = |domain| {
            let signature = secret_key_for(0).sign(
                compute_signing_root(message_root, domain).as_slice(),
                crate::beacon::bls::DST,
                &[],
            );
            crate::beacon::primitives::BlsSignature(signature.to_bytes())
        };
        let pubkey = state.validator(0).expect("validator 0").pubkey;
        let accepted = |signature| {
            domains.iter().any(|domain| {
                bls::verify(
                    &pubkey,
                    compute_signing_root(message_root, *domain),
                    &signature,
                )
            })
        };
        assert!(accepted(sign(at(ForkName::Fulu))));
        assert!(accepted(sign(at(ForkName::Gloas))));
        assert!(!accepted(sign(at(ForkName::Electra))));
    }

    #[test]
    fn away_from_a_fork_there_is_one_candidate_domain() {
        let config = boundary_config();
        let mut state = fulu_state_with_fork(&config);
        *state.fork_mut() = Fork {
            previous_version: config.fork_version(ForkName::Fulu),
            current_version: config.fork_version(ForkName::Gloas),
            epoch: 2,
        };
        assert_eq!(proposer_preferences_domains(&state, &config, 5).len(), 1);
        // And at epoch 0 the saturating subtraction does not wrap.
        assert!(!proposer_preferences_domains(&state, &config, 0).is_empty());
    }
}
