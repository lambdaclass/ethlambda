//! Sync committee messages and contributions, held until a proposer packs them.
//!
//! Altair `validator.md` ("Sync committee"): the proposer of slot `N` builds
//! its `SyncAggregate` from what the committee signed at slot `N - 1` over its
//! parent block's root. Members gossip a `SyncCommitteeMessage` per subnet;
//! aggregators combine a subcommittee's worth into a
//! `SyncCommitteeContribution`. This pool keeps both, keyed by
//! `(slot, beacon_block_root, subcommittee_index)`.
//!
//! Only objects that already passed validation go in (gossip's verdicts, or the
//! Beacon API's endpoints after the same checks). That is what makes combining
//! their signatures safe: one bad share fails the whole aggregate, and with it
//! the block that carries it.
//!
//! Block production reads [`SyncCommitteePool::sync_aggregate`] and verifies
//! its answer again (`block_production::verified_sync_aggregate`) before use.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use ethlambda_types::beacon::{
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
    containers::altair::{
        SYNC_SUBCOMMITTEE_SIZE, SyncAggregate, SyncCommitteeContribution, SyncCommitteeMessage,
    },
    primitives::{BlsSignature, Root, Slot},
};

use super::bls;

/// The pool, shared between whatever fills it (the sync committee gossip
/// verdicts, the Beacon API's endpoints) and what reads it (block production,
/// `GET /eth/v1/validator/sync_committee_contribution`). There must be exactly
/// one per node.
pub type SharedSyncCommitteePool = Arc<Mutex<SyncCommitteePool>>;

/// How many slots before the newest one the pool still holds. A block at slot
/// `N` reads slot `N - 1`, so only a little slack for clock skew is needed.
pub const RETAINED_SLOTS: u64 = 4;

/// `(beacon_block_root, subcommittee_index)`: what one contribution covers
/// within a slot.
type Key = (Root, u64);

#[derive(Debug, Default)]
pub struct SyncCommitteePool {
    /// slot -> key -> a signature slot per position of the subcommittee.
    messages: BTreeMap<Slot, HashMap<Key, Vec<Option<BlsSignature>>>>,
    /// slot -> key -> the held contribution with the most participants.
    contributions: BTreeMap<Slot, HashMap<Key, SyncCommitteeContribution>>,
}

impl SyncCommitteePool {
    /// Record a validated message at each of its `seats` (`(subcommittee,
    /// position)` pairs). A validator with several seats fills each one, so
    /// its signature is aggregated once per bit, as `validator.md` ("Signature")
    /// requires. Keeps the first signature per position, and drops every slot
    /// more than [`RETAINED_SLOTS`] before the message's own. Returns `true`
    /// when any position was new.
    pub fn insert_message(
        &mut self,
        message: &SyncCommitteeMessage,
        seats: &[(u64, usize)],
    ) -> bool {
        self.prune_before(message.slot.saturating_sub(RETAINED_SLOTS));
        let by_key = self.messages.entry(message.slot).or_default();
        let mut inserted = false;
        for &(subcommittee, position) in seats {
            if subcommittee >= SYNC_COMMITTEE_SUBNET_COUNT as u64
                || position >= SYNC_SUBCOMMITTEE_SIZE
            {
                continue;
            }
            let signatures = by_key
                .entry((message.beacon_block_root, subcommittee))
                .or_insert_with(|| vec![None; SYNC_SUBCOMMITTEE_SIZE]);
            if signatures[position].is_none() {
                signatures[position] = Some(message.signature);
                inserted = true;
            }
        }
        inserted
    }

    /// Record a validated contribution. Replaces the held one for its key only
    /// when it has strictly more participants. Returns whether it was kept.
    pub fn insert_contribution(&mut self, contribution: SyncCommitteeContribution) -> bool {
        self.prune_before(contribution.slot.saturating_sub(RETAINED_SLOTS));
        if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
            return false;
        }
        let by_key = self.contributions.entry(contribution.slot).or_default();
        let key = (
            contribution.beacon_block_root,
            contribution.subcommittee_index,
        );
        match by_key.get(&key) {
            Some(held)
                if held.aggregation_bits.count_ones()
                    >= contribution.aggregation_bits.count_ones() =>
            {
                false
            }
            _ => {
                by_key.insert(key, contribution);
                true
            }
        }
    }

    /// The best contribution for `(slot, beacon_block_root, subcommittee_index)`:
    /// the held one extended by every pooled message at a position it does not
    /// set, or the messages alone when no contribution is held. `None` when
    /// neither exists. When the signatures cannot be combined, the held
    /// contribution alone.
    pub fn contribution(
        &self,
        slot: Slot,
        beacon_block_root: Root,
        subcommittee_index: u64,
    ) -> Option<SyncCommitteeContribution> {
        let key = (beacon_block_root, subcommittee_index);
        let held = self
            .contributions
            .get(&slot)
            .and_then(|by_key| by_key.get(&key));
        let messages = self.messages.get(&slot).and_then(|by_key| by_key.get(&key));

        let mut contribution = held.cloned().unwrap_or_else(|| SyncCommitteeContribution {
            slot,
            beacon_block_root,
            subcommittee_index,
            aggregation_bits: Default::default(),
            signature: BlsSignature::default(),
        });
        let mut signatures: Vec<BlsSignature> =
            held.map(|held| held.signature).into_iter().collect();
        let held_signatures = signatures.len();
        for (position, signature) in messages.into_iter().flatten().enumerate() {
            let Some(signature) = signature else { continue };
            if contribution.aggregation_bits.get(position).unwrap_or(true) {
                continue;
            }
            contribution
                .aggregation_bits
                .set(position, true)
                .expect("the position is below the subcommittee size");
            signatures.push(*signature);
        }
        if signatures.is_empty() {
            return None;
        }
        if signatures.len() > held_signatures {
            match bls::aggregate(&signatures) {
                Ok(signature) => contribution.signature = signature,
                // A pooled signature that fails to combine is not expected, since
                // everything pooled was verified. Fall back to what was held.
                Err(_) => return held.cloned(),
            }
        }
        Some(contribution)
    }

    /// The aggregate for a block at `slot + 1` whose parent is
    /// `beacon_block_root`: per subcommittee, [`Self::contribution`]'s bits at
    /// `subcommittee * SYNC_SUBCOMMITTEE_SIZE + i`, the signatures combined.
    /// `None` when no bit is set, or when the signatures cannot be combined.
    pub fn sync_aggregate(&self, slot: Slot, beacon_block_root: Root) -> Option<SyncAggregate> {
        let mut bits = <SyncAggregate as Default>::default().sync_committee_bits;
        let mut signatures = Vec::new();
        for subcommittee in 0..SYNC_COMMITTEE_SUBNET_COUNT as u64 {
            let Some(contribution) = self.contribution(slot, beacon_block_root, subcommittee)
            else {
                continue;
            };
            let mut any = false;
            for position in 0..SYNC_SUBCOMMITTEE_SIZE {
                if contribution.aggregation_bits.get(position).unwrap_or(false) {
                    bits.set(
                        subcommittee as usize * SYNC_SUBCOMMITTEE_SIZE + position,
                        true,
                    )
                    .expect("the position is below the committee size");
                    any = true;
                }
            }
            if any {
                signatures.push(contribution.signature);
            }
        }
        if signatures.is_empty() {
            return None;
        }
        let sync_committee_signature = bls::aggregate(&signatures).ok()?;
        Some(SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature,
        })
    }

    /// Drop every slot before `slot`.
    pub fn prune_before(&mut self, slot: Slot) {
        self.messages = self.messages.split_off(&slot);
        self.contributions = self.contributions.split_off(&slot);
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::primitives::{BlsPubkey, ValidatorIndex};

    use super::*;
    use crate::beacon::bls::eth_fast_aggregate_verify;
    use crate::beacon::config::Config;
    use crate::beacon::helpers::sync_committee::tests::state_with_committees;
    use crate::beacon::helpers::sync_committee::{
        sync_committee_for_slot, sync_committee_message_signing_root, sync_committee_seats,
    };
    use crate::beacon::helpers::test_state::sign_for;

    const SLOT: Slot = 5;

    fn root() -> Root {
        Root::repeat_byte(9)
    }

    /// Validator `index`'s message for `SLOT` over `beacon_block_root`, with the
    /// seats it holds in the state's committee.
    fn message_for(
        state: &ethlambda_types::beacon::containers::BeaconState,
        index: ValidatorIndex,
        beacon_block_root: Root,
    ) -> (SyncCommitteeMessage, Vec<(u64, usize)>) {
        let signing_root = sync_committee_message_signing_root(
            &Config::mainnet(),
            state.genesis_validators_root(),
            SLOT,
            beacon_block_root,
        );
        let message = SyncCommitteeMessage {
            slot: SLOT,
            beacon_block_root,
            validator_index: index,
            signature: sign_for(index as usize, signing_root),
        };
        let pubkey = state.validator(index).unwrap().pubkey;
        let seats = sync_committee_seats(sync_committee_for_slot(state, SLOT).unwrap(), &pubkey);
        (message, seats)
    }

    fn pubkeys_of(
        state: &ethlambda_types::beacon::containers::BeaconState,
        subcommittee: u64,
        bits: &ethlambda_types::beacon::containers::altair::SyncSubcommitteeBits,
    ) -> Vec<BlsPubkey> {
        let committee = sync_committee_for_slot(state, SLOT).unwrap();
        (0..SYNC_SUBCOMMITTEE_SIZE)
            .filter(|&i| bits.get(i).unwrap())
            .map(|i| committee.pubkeys[subcommittee as usize * SYNC_SUBCOMMITTEE_SIZE + i])
            .collect()
    }

    #[test]
    fn a_position_keeps_its_first_signature() {
        let state = state_with_committees(SYNC_COMMITTEE_SIZE_FOR_TESTS);
        let mut pool = SyncCommitteePool::default();
        let (message, seats) = message_for(&state, 3, root());
        assert!(pool.insert_message(&message, &seats));
        assert!(!pool.insert_message(&message, &seats));
        let mut later = message.clone();
        later.signature = sign_for(4, Root::ZERO);
        assert!(!pool.insert_message(&later, &seats));
        let contribution = pool.contribution(SLOT, root(), seats[0].0).unwrap();
        assert_eq!(contribution.signature, message.signature);
    }

    #[test]
    fn a_validator_with_several_seats_fills_each_and_signs_once_per_bit() {
        let state = state_with_committees(2);
        let mut pool = SyncCommitteePool::default();
        let (message, seats) = message_for(&state, 0, root());
        assert!(seats.len() > 1);
        assert!(pool.insert_message(&message, &seats));
        let mut total_bits = 0;
        for subcommittee in 0..SYNC_COMMITTEE_SUBNET_COUNT as u64 {
            let contribution = pool.contribution(SLOT, root(), subcommittee).unwrap();
            let pubkeys = pubkeys_of(&state, subcommittee, &contribution.aggregation_bits);
            total_bits += pubkeys.len();
            let signing_root = sync_committee_message_signing_root(
                &Config::mainnet(),
                state.genesis_validators_root(),
                SLOT,
                root(),
            );
            assert!(eth_fast_aggregate_verify(
                &pubkeys,
                signing_root,
                &contribution.signature
            ));
        }
        assert_eq!(total_bits, seats.len());
    }

    #[test]
    fn the_contribution_with_more_participants_is_kept() {
        let state = state_with_committees(SYNC_COMMITTEE_SIZE_FOR_TESTS);
        let (first, seats_first) = message_for(&state, 0, root());
        let (second, seats_second) = message_for(&state, 1, root());
        let subcommittee = seats_first[0].0;
        let one = pool_contribution(&[(&first, &seats_first)], subcommittee);
        let two = pool_contribution(
            &[(&first, &seats_first), (&second, &seats_second)],
            subcommittee,
        );
        let mut pool = SyncCommitteePool::default();
        assert!(pool.insert_contribution(one.clone()));
        assert!(!pool.insert_contribution(one.clone()));
        assert!(pool.insert_contribution(two.clone()));
        assert!(!pool.insert_contribution(one));
        assert_eq!(pool.contribution(SLOT, root(), subcommittee), Some(two));
    }

    /// The contribution a pool holding only `messages` would offer.
    fn pool_contribution(
        messages: &[(&SyncCommitteeMessage, &Vec<(u64, usize)>)],
        subcommittee: u64,
    ) -> SyncCommitteeContribution {
        let mut pool = SyncCommitteePool::default();
        for (message, seats) in messages {
            pool.insert_message(message, seats);
        }
        pool.contribution(SLOT, messages[0].0.beacon_block_root, subcommittee)
            .unwrap()
    }

    #[test]
    fn a_contribution_is_extended_by_messages_at_uncovered_positions() {
        // Committee of 512 seats drawn from 512 validators: validator v holds
        // position v, so subcommittee 0 holds validators 0..128.
        let state = state_with_committees(SYNC_COMMITTEE_SIZE_FOR_TESTS);
        let (a, seats_a) = message_for(&state, 0, root());
        let (b, seats_b) = message_for(&state, 1, root());
        let (c, seats_c) = message_for(&state, 2, root());
        assert_eq!(seats_a[0].0, seats_b[0].0);
        let subcommittee = seats_a[0].0;

        // The held contribution covers `a` and `b`; `c` arrives as a message.
        let held = {
            let mut helper = SyncCommitteePool::default();
            helper.insert_message(&a, &seats_a);
            helper.insert_message(&b, &seats_b);
            helper.contribution(SLOT, root(), subcommittee).unwrap()
        };
        let mut pool = SyncCommitteePool::default();
        assert!(pool.insert_contribution(held));
        // `a` is already covered by the contribution: a duplicate position.
        pool.insert_message(&a, &seats_a);
        pool.insert_message(&c, &seats_c);

        let best = pool.contribution(SLOT, root(), subcommittee).unwrap();
        assert_eq!(best.aggregation_bits.count_ones(), 3);
        let pubkeys = pubkeys_of(&state, subcommittee, &best.aggregation_bits);
        let signing_root = sync_committee_message_signing_root(
            &Config::mainnet(),
            state.genesis_validators_root(),
            SLOT,
            root(),
        );
        assert!(eth_fast_aggregate_verify(
            &pubkeys,
            signing_root,
            &best.signature
        ));
    }

    /// The committee size of the preset the tests build, as a validator count.
    const SYNC_COMMITTEE_SIZE_FOR_TESTS: usize =
        ethlambda_types::beacon::preset::SYNC_COMMITTEE_SIZE;

    #[test]
    fn the_aggregate_offsets_bits_per_subcommittee_and_verifies() {
        let state = state_with_committees(SYNC_COMMITTEE_SIZE_FOR_TESTS);
        let mut pool = SyncCommitteePool::default();
        // One member of each subcommittee: validator `s * SIZE` sits at the
        // subcommittee's first position.
        for subcommittee in 0..SYNC_COMMITTEE_SUBNET_COUNT {
            let (message, seats) = message_for(
                &state,
                (subcommittee * SYNC_SUBCOMMITTEE_SIZE) as u64,
                root(),
            );
            assert!(pool.insert_message(&message, &seats));
        }
        let aggregate = pool.sync_aggregate(SLOT, root()).unwrap();
        assert_eq!(
            aggregate.sync_committee_bits.count_ones(),
            SYNC_COMMITTEE_SUBNET_COUNT
        );
        let committee = sync_committee_for_slot(&state, SLOT).unwrap();
        let mut pubkeys = Vec::new();
        for subcommittee in 0..SYNC_COMMITTEE_SUBNET_COUNT {
            let position = subcommittee * SYNC_SUBCOMMITTEE_SIZE;
            assert!(aggregate.sync_committee_bits.get(position).unwrap());
            pubkeys.push(committee.pubkeys[position]);
        }
        let signing_root = sync_committee_message_signing_root(
            &Config::mainnet(),
            state.genesis_validators_root(),
            SLOT,
            root(),
        );
        assert!(eth_fast_aggregate_verify(
            &pubkeys,
            signing_root,
            &aggregate.sync_committee_signature
        ));
    }

    #[test]
    fn different_roots_stay_separate_and_an_empty_pool_has_no_aggregate() {
        let state = state_with_committees(SYNC_COMMITTEE_SIZE_FOR_TESTS);
        let mut pool = SyncCommitteePool::default();
        assert!(pool.sync_aggregate(SLOT, root()).is_none());
        let (message, seats) = message_for(&state, 0, root());
        pool.insert_message(&message, &seats);
        assert!(pool.sync_aggregate(SLOT, Root::repeat_byte(1)).is_none());
        assert!(pool.sync_aggregate(SLOT + 1, root()).is_none());
        assert!(pool.contribution(SLOT, root(), 1).is_none());
        assert!(pool.sync_aggregate(SLOT, root()).is_some());
    }

    #[test]
    fn pruning_drops_older_slots_and_inserts_prune_themselves() {
        let state = state_with_committees(SYNC_COMMITTEE_SIZE_FOR_TESTS);
        let mut pool = SyncCommitteePool::default();
        let (message, seats) = message_for(&state, 0, root());
        pool.insert_message(&message, &seats);
        pool.prune_before(SLOT);
        assert!(pool.sync_aggregate(SLOT, root()).is_some());
        pool.prune_before(SLOT + 1);
        assert!(pool.sync_aggregate(SLOT, root()).is_none());

        pool.insert_message(&message, &seats);
        let mut newer = message.clone();
        newer.slot = SLOT + RETAINED_SLOTS + 1;
        pool.insert_message(&newer, &seats);
        assert!(pool.sync_aggregate(SLOT, root()).is_none());
        assert!(pool.sync_aggregate(newer.slot, root()).is_some());
    }
}
