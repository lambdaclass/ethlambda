//! The shared state behind the gloas builder market: bids seen on
//! `execution_payload_bid` (or posted to the Beacon API) and pooled for block
//! production, the proposer preferences those bids are judged against, and the
//! execution payloads gossip has revealed.
//!
//! One [`SharedBuilderMarket`] exists per node. p2p validates against it and
//! the Beacon API reads it, like [`super::payload_attestation_pool`]. Gossip's
//! stateful checks run on blocking threads, so none of this can be owned by the
//! chain actor.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::{Arc, Mutex, MutexGuard},
};

use lru::LruCache;

use super::containers::gloas;
use super::gossip::IgnoreReason;
use super::primitives::{BlsPubkey, ExecutionAddress, ExecutionBlockHash, Root, Slot};

/// Exactly one per node.
pub type SharedBuilderMarket = Arc<BuilderMarket>;

/// Bids pooled per `(slot, parent hash, parent root)`, top values kept.
pub const MAX_BIDS_PER_PARENT: usize = 16;
/// A full slot refuses new keys: `record_bid` answers `false`.
pub const MAX_SEEN_BID_KEYS_PER_SLOT: usize = 4096;
/// Over the cap, the lowest `proposal_slot` is dropped first.
pub const MAX_PREFERENCES: usize = 1024;
/// Known payloads, evicted least recently used first, by block hash.
pub const KNOWN_PAYLOADS_CAPACITY: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// What gossip learned about an execution payload from its envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPayload {
    pub gas_limit: u64,
    /// The block whose envelope revealed it.
    pub beacon_block_root: Root,
    /// `(pubkey, source_address)` of every builder exit request it carries.
    pub builder_exits: Vec<(BlsPubkey, ExecutionAddress)>,
}

/// Bids for one `(parent_block_hash, parent_block_root)` of a slot.
#[derive(Debug, Default)]
struct ParentBids {
    /// The highest value recorded, which a later bid must strictly beat. Kept
    /// apart from `bids` because the pool is truncated and the bar is not.
    best_value: Option<u64>,
    /// Value descending, then builder index ascending.
    bids: Vec<gloas::SignedExecutionPayloadBid>,
}

type ParentKey = (ExecutionBlockHash, Root);

#[derive(Debug, Default)]
struct SlotBids {
    /// The spec's `seen.execution_payload_bids`: one bid per builder per
    /// `(slot, parent_hash, parent_root)`.
    seen: BTreeSet<(ParentKey, u64)>,
    parents: BTreeMap<ParentKey, ParentBids>,
}

#[derive(Debug, Default)]
struct BidPool {
    slots: BTreeMap<Slot, SlotBids>,
}

impl BidPool {
    fn check(&self, bid: &gloas::ExecutionPayloadBid) -> Result<(), IgnoreReason> {
        let Some(slot) = self.slots.get(&bid.slot) else {
            return Ok(());
        };
        let parent = (bid.parent_block_hash, bid.parent_block_root);
        if slot.seen.contains(&(parent, bid.builder_index)) {
            return Err(IgnoreReason::AlreadySeen);
        }
        if let Some(best) = slot.parents.get(&parent).and_then(|p| p.best_value)
            && bid.value <= best
        {
            return Err(IgnoreReason::NotHighestBid);
        }
        Ok(())
    }
}

/// Preferences by `(proposal_slot, dependent_root)`: the first valid one wins.
type PreferencesCache = BTreeMap<(Slot, Root), gloas::SignedProposerPreferences>;

#[derive(Debug)]
pub struct BuilderMarket {
    bids: Mutex<BidPool>,
    preferences: Mutex<PreferencesCache>,
    payloads: Mutex<LruCache<ExecutionBlockHash, KnownPayload>>,
}

impl Default for BuilderMarket {
    fn default() -> Self {
        Self {
            bids: Mutex::default(),
            preferences: Mutex::default(),
            payloads: Mutex::new(LruCache::new(KNOWN_PAYLOADS_CAPACITY)),
        }
    }
}

/// A poisoned lock means a panic elsewhere interrupted an update, but every
/// mutation here is a single insert or remove, so the data is still consistent
/// and gossip should keep working.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl BuilderMarket {
    // Bids: seen.execution_payload_bids + seen.best_execution_payload_bid + pool.

    /// The spec's two seen rules, in order: `(slot, parent_hash, parent_root,
    /// builder)` recorded -> `AlreadySeen`; value <= best for `(slot,
    /// parent_hash, parent_root)` -> `NotHighestBid`.
    pub fn check_bid_seen(&self, bid: &gloas::ExecutionPayloadBid) -> Result<(), IgnoreReason> {
        lock(&self.bids).check(bid)
    }

    /// Re-runs [`Self::check_bid_seen`] under the lock. If it passes, records
    /// both seen keys and pools the bid. `false` = not recorded (race, or the
    /// per-slot key cap). Prunes slots below `bid.slot - 1`.
    pub fn record_bid(&self, signed: gloas::SignedExecutionPayloadBid) -> bool {
        let mut pool = lock(&self.bids);
        if pool.check(&signed.message).is_err() {
            return false;
        }
        let bid_slot = signed.message.slot;
        let slot = pool.slots.entry(bid_slot).or_default();
        if slot.seen.len() >= MAX_SEEN_BID_KEYS_PER_SLOT {
            return false;
        }
        let parent = (
            signed.message.parent_block_hash,
            signed.message.parent_block_root,
        );
        slot.seen.insert((parent, signed.message.builder_index));
        let entry = slot.parents.entry(parent).or_default();
        entry.best_value = Some(signed.message.value);
        entry.bids.push(signed);
        entry.bids.sort_by(|a, b| {
            b.message
                .value
                .cmp(&a.message.value)
                .then(a.message.builder_index.cmp(&b.message.builder_index))
        });
        entry.bids.truncate(MAX_BIDS_PER_PARENT);
        let keep_from = bid_slot.saturating_sub(1);
        pool.slots = pool.slots.split_off(&keep_from);
        true
    }

    /// The identical message and signature is pooled (API idempotency).
    pub fn contains_bid(&self, signed: &gloas::SignedExecutionPayloadBid) -> bool {
        let pool = lock(&self.bids);
        pool.slots
            .get(&signed.message.slot)
            .and_then(|slot| {
                slot.parents.get(&(
                    signed.message.parent_block_hash,
                    signed.message.parent_block_root,
                ))
            })
            .is_some_and(|parent| parent.bids.contains(signed))
    }

    /// Pooled bids for the key: value descending, then builder index ascending.
    pub fn bids_for(
        &self,
        slot: Slot,
        parent_block_root: Root,
        parent_block_hash: ExecutionBlockHash,
    ) -> Vec<gloas::SignedExecutionPayloadBid> {
        lock(&self.bids)
            .slots
            .get(&slot)
            .and_then(|s| s.parents.get(&(parent_block_hash, parent_block_root)))
            .map(|p| p.bids.clone())
            .unwrap_or_default()
    }

    pub fn has_bids_for_slot(&self, slot: Slot) -> bool {
        lock(&self.bids)
            .slots
            .get(&slot)
            .is_some_and(|s| s.parents.values().any(|p| !p.bids.is_empty()))
    }

    pub fn prune_bids_before(&self, slot: Slot) {
        let mut pool = lock(&self.bids);
        pool.slots = pool.slots.split_off(&slot);
    }

    // Proposer preferences: seen.proposer_preferences.

    pub fn preferences(
        &self,
        proposal_slot: Slot,
        dependent_root: Root,
    ) -> Option<gloas::SignedProposerPreferences> {
        lock(&self.preferences)
            .get(&(proposal_slot, dependent_root))
            .cloned()
    }

    /// The first valid preferences per key win. `false` if one is held. Prunes
    /// `proposal_slot < current_slot`.
    pub fn record_preferences(
        &self,
        signed: gloas::SignedProposerPreferences,
        current_slot: Slot,
    ) -> bool {
        let mut cache = lock(&self.preferences);
        let key = (signed.message.proposal_slot, signed.message.dependent_root);
        if cache.contains_key(&key) {
            return false;
        }
        *cache = cache.split_off(&(current_slot, Root::ZERO));
        cache.insert(key, signed);
        while cache.len() > MAX_PREFERENCES {
            cache.pop_first();
        }
        cache.contains_key(&key)
    }

    pub fn prune_preferences_before(&self, slot: Slot) {
        let mut cache = lock(&self.preferences);
        *cache = cache.split_off(&(slot, Root::ZERO));
    }

    // Known payloads: seen.execution_payloads.

    pub fn record_execution_payload(&self, envelope: &gloas::ExecutionPayloadEnvelope) {
        let builder_exits = envelope
            .execution_requests
            .builder_exits
            .iter()
            .map(|exit| (exit.pubkey, exit.source_address))
            .collect();
        let known = KnownPayload {
            gas_limit: envelope.payload.gas_limit,
            beacon_block_root: envelope.beacon_block_root,
            builder_exits,
        };
        lock(&self.payloads).put(envelope.payload.block_hash, known);
    }

    pub fn known_payload(&self, block_hash: ExecutionBlockHash) -> Option<KnownPayload> {
        lock(&self.payloads).get(&block_hash).cloned()
    }
}

/// Builder-market fixtures shared by this module's tests, the gossip rules'
/// and (`test-utils` feature) the Beacon API's and p2p's: a gloas state with a
/// registered builder, and signatures that state verifies.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_support {
    use ethlambda_types::beacon::containers::bellatrix::{ExtraData, LogsBloom};
    use ethlambda_types::beacon::primitives::{BlsSignature, Bytes32, Uint256};

    use super::*;
    use crate::beacon::containers::BeaconState;
    use crate::beacon::gloas_block_production::test_support::parent_state;
    use crate::beacon::helpers::accessors::get_domain;
    use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
    use crate::beacon::helpers::test_state::{secret_key_for, sign_for};
    use crate::beacon::primitives::HashTreeRoot as _;
    use crate::beacon::{constants, preset};

    /// The secret key behind builder `index`'s registered pubkey. Offset from
    /// the validators' keys so the two never collide.
    pub fn builder_secret(index: usize) -> blst::min_pk::SecretKey {
        secret_key_for(1000 + index)
    }

    /// `gloas_block_production::test_support::parent_state` with builders
    /// `0..=builder_index` registered (each funded with `balance`, deposited at
    /// `deposit_epoch`), and the finalized checkpoint one epoch past
    /// `deposit_epoch` so they are active.
    pub fn gloas_state_with_builder(
        builder_index: u64,
        balance: u64,
        deposit_epoch: u64,
    ) -> BeaconState {
        let mut state = parent_state();
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        for index in 0..=builder_index {
            let builder = gloas::Builder {
                pubkey: BlsPubkey(builder_secret(index as usize).sk_to_pk().to_bytes()),
                version: constants::PAYLOAD_BUILDER_VERSION,
                execution_address: ExecutionAddress::repeat_byte(index as u8 + 1),
                balance,
                deposit_epoch,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
            };
            inner.builders.push(builder);
        }
        inner.finalized_checkpoint.epoch = deposit_epoch + 1;
        state
    }

    /// `bid` signed by builder `builder_index` under `state`'s builder domain.
    pub fn sign_bid(
        state: &BeaconState,
        bid: gloas::ExecutionPayloadBid,
        builder_index: u64,
    ) -> gloas::SignedExecutionPayloadBid {
        let domain = get_domain(state, constants::DOMAIN_BEACON_BUILDER, None);
        let root = compute_signing_root(bid.hash_tree_root(), domain);
        let signature = builder_secret(builder_index as usize).sign(
            root.as_slice(),
            crate::beacon::bls::DST,
            &[],
        );
        gloas::SignedExecutionPayloadBid {
            message: bid,
            signature: BlsSignature(signature.to_bytes()),
        }
    }

    /// `prefs` signed by its own `validator_index` under `state`'s preferences
    /// domain at the proposal slot's epoch (the spec's).
    pub fn sign_preferences(
        state: &BeaconState,
        prefs: gloas::ProposerPreferences,
    ) -> gloas::SignedProposerPreferences {
        let epoch = compute_epoch_at_slot(prefs.proposal_slot);
        let domain = get_domain(state, constants::DOMAIN_PROPOSER_PREFERENCES, Some(epoch));
        let root = compute_signing_root(prefs.hash_tree_root(), domain);
        let signature = sign_for(prefs.validator_index as usize, root);
        gloas::SignedProposerPreferences {
            message: prefs,
            signature,
        }
    }

    /// An envelope revealing payload `block_hash` with `gas_limit`, for the
    /// block `beacon_block_root`, carrying one exit request per `exits` entry.
    pub fn envelope_with_gas_limit(
        block_hash: ExecutionBlockHash,
        gas_limit: u64,
        beacon_block_root: Root,
        exits: Vec<(BlsPubkey, ExecutionAddress)>,
    ) -> gloas::ExecutionPayloadEnvelope {
        let payload = gloas::ExecutionPayload {
            parent_hash: ExecutionBlockHash::ZERO,
            fee_recipient: Default::default(),
            state_root: Bytes32::repeat_byte(1),
            receipts_root: Bytes32::repeat_byte(2),
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM]).unwrap(),
            prev_randao: Default::default(),
            block_number: 7,
            gas_limit,
            gas_used: 0,
            timestamp: 0,
            extra_data: ExtraData::default(),
            base_fee_per_gas: Uint256::from_u128(7),
            block_hash,
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: 0,
        };
        let builder_exits: Vec<_> = exits
            .into_iter()
            .map(|(pubkey, source_address)| gloas::BuilderExitRequest {
                source_address,
                pubkey,
            })
            .collect();
        let execution_requests = gloas::ExecutionRequests {
            builder_exits: builder_exits.into(),
            ..Default::default()
        };
        gloas::ExecutionPayloadEnvelope {
            payload,
            execution_requests,
            builder_index: 0,
            beacon_block_root,
            parent_beacon_block_root: Root::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::envelope_with_gas_limit;
    use super::*;

    fn hash(byte: u8) -> ExecutionBlockHash {
        ExecutionBlockHash::repeat_byte(byte)
    }

    fn bid(slot: Slot, builder: u64, value: u64) -> gloas::SignedExecutionPayloadBid {
        gloas::SignedExecutionPayloadBid {
            message: gloas::ExecutionPayloadBid {
                slot,
                builder_index: builder,
                value,
                parent_block_hash: hash(1),
                parent_block_root: Root::repeat_byte(2),
                block_hash: hash(3),
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    fn prefs(slot: Slot, dependent: u8, validator: u64) -> gloas::SignedProposerPreferences {
        gloas::SignedProposerPreferences {
            message: gloas::ProposerPreferences {
                dependent_root: Root::repeat_byte(dependent),
                proposal_slot: slot,
                validator_index: validator,
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    #[test]
    fn a_builder_bids_once_per_parent() {
        let market = BuilderMarket::default();
        assert!(market.record_bid(bid(10, 1, 5)));
        assert_eq!(
            market.check_bid_seen(&bid(10, 1, 9).message),
            Err(IgnoreReason::AlreadySeen)
        );
        assert!(!market.record_bid(bid(10, 1, 9)));
        // Another parent hash is another key.
        let mut other = bid(10, 1, 9);
        other.message.parent_block_hash = hash(9);
        assert!(market.record_bid(other));
    }

    #[test]
    fn a_bid_must_strictly_beat_the_best() {
        let market = BuilderMarket::default();
        assert!(market.record_bid(bid(10, 1, 5)));
        assert_eq!(
            market.check_bid_seen(&bid(10, 2, 5).message),
            Err(IgnoreReason::NotHighestBid)
        );
        assert_eq!(
            market.check_bid_seen(&bid(10, 2, 4).message),
            Err(IgnoreReason::NotHighestBid)
        );
        assert_eq!(market.check_bid_seen(&bid(10, 2, 6).message), Ok(()));
        assert!(market.record_bid(bid(10, 2, 6)));
        // A lower bid never reached the pool, the bar stays at the best.
        assert!(!market.record_bid(bid(10, 3, 6)));
    }

    #[test]
    fn a_stale_check_fails_the_record() {
        let market = BuilderMarket::default();
        let racing = bid(10, 2, 7);
        assert_eq!(market.check_bid_seen(&racing.message), Ok(()));
        assert!(market.record_bid(bid(10, 1, 8)));
        assert!(!market.record_bid(racing));
    }

    #[test]
    fn a_full_slot_refuses_new_keys() {
        let market = BuilderMarket::default();
        for builder in 0..MAX_SEEN_BID_KEYS_PER_SLOT as u64 {
            assert!(market.record_bid(bid(10, builder, builder + 1)));
        }
        let next = MAX_SEEN_BID_KEYS_PER_SLOT as u64;
        assert!(!market.record_bid(bid(10, next, next + 1)));
        // Other slots are unaffected.
        assert!(market.record_bid(bid(11, next, 1)));
    }

    #[test]
    fn bids_for_orders_by_value_and_keeps_the_top() {
        let market = BuilderMarket::default();
        let total = MAX_BIDS_PER_PARENT as u64 + 4;
        for builder in 0..total {
            assert!(market.record_bid(bid(10, builder, builder + 1)));
        }
        let pooled = market.bids_for(10, Root::repeat_byte(2), hash(1));
        assert_eq!(pooled.len(), MAX_BIDS_PER_PARENT);
        let values: Vec<u64> = pooled.iter().map(|b| b.message.value).collect();
        let expected: Vec<u64> = (5..=total).rev().collect();
        assert_eq!(values, expected);
        // The truncated bar still holds: the best value is the latest.
        assert_eq!(
            market.check_bid_seen(&bid(10, 99, total).message),
            Err(IgnoreReason::NotHighestBid)
        );
        assert!(market.bids_for(10, Root::ZERO, hash(1)).is_empty());
    }

    #[test]
    fn contains_bid_matches_the_exact_message() {
        let market = BuilderMarket::default();
        let signed = bid(10, 1, 5);
        assert!(!market.contains_bid(&signed));
        assert!(market.record_bid(signed.clone()));
        assert!(market.contains_bid(&signed));
        let mut other = signed.clone();
        other.signature.0[0] = 1;
        assert!(!market.contains_bid(&other));
        assert!(market.has_bids_for_slot(10));
        assert!(!market.has_bids_for_slot(11));
    }

    #[test]
    fn bids_prune_below_the_previous_slot() {
        let market = BuilderMarket::default();
        assert!(market.record_bid(bid(10, 1, 5)));
        assert!(market.record_bid(bid(11, 1, 5)));
        assert!(market.has_bids_for_slot(10));
        assert!(market.record_bid(bid(12, 1, 5)));
        assert!(!market.has_bids_for_slot(10));
        assert!(market.has_bids_for_slot(11));
        market.prune_bids_before(12);
        assert!(!market.has_bids_for_slot(11));
        assert!(market.has_bids_for_slot(12));
    }

    #[test]
    fn the_first_preferences_win() {
        let market = BuilderMarket::default();
        let first = prefs(40, 1, 3);
        assert!(market.record_preferences(first.clone(), 38));
        assert!(!market.record_preferences(prefs(40, 1, 4), 38));
        assert_eq!(market.preferences(40, Root::repeat_byte(1)), Some(first));
        // Another dependent root is another key.
        assert!(market.record_preferences(prefs(40, 2, 3), 38));
        assert_eq!(market.preferences(41, Root::repeat_byte(1)), None);
    }

    #[test]
    fn preferences_prune_by_proposal_slot() {
        let market = BuilderMarket::default();
        assert!(market.record_preferences(prefs(40, 1, 3), 38));
        assert!(market.record_preferences(prefs(41, 1, 3), 41));
        assert!(market.preferences(40, Root::repeat_byte(1)).is_none());
        assert!(market.preferences(41, Root::repeat_byte(1)).is_some());
        market.prune_preferences_before(42);
        assert!(market.preferences(41, Root::repeat_byte(1)).is_none());
    }

    #[test]
    fn preferences_over_the_cap_evict_the_lowest_slot() {
        let market = BuilderMarket::default();
        for slot in 0..MAX_PREFERENCES as u64 {
            assert!(market.record_preferences(prefs(100 + slot, 1, 3), 0));
        }
        let high = 100 + MAX_PREFERENCES as u64;
        assert!(market.record_preferences(prefs(high, 1, 3), 0));
        assert!(market.preferences(100, Root::repeat_byte(1)).is_none());
        assert!(market.preferences(101, Root::repeat_byte(1)).is_some());
        // A message below everything held is itself the one dropped.
        assert!(!market.record_preferences(prefs(50, 1, 3), 0));
    }

    #[test]
    fn a_revealed_payload_is_known_with_its_exits() {
        let market = BuilderMarket::default();
        let pubkey = BlsPubkey([7; 48]);
        let source = ExecutionAddress::repeat_byte(9);
        let envelope = envelope_with_gas_limit(
            hash(5),
            36_000_000,
            Root::repeat_byte(4),
            vec![(pubkey, source)],
        );
        assert!(market.known_payload(hash(5)).is_none());
        market.record_execution_payload(&envelope);
        assert_eq!(
            market.known_payload(hash(5)),
            Some(KnownPayload {
                gas_limit: 36_000_000,
                beacon_block_root: Root::repeat_byte(4),
                builder_exits: vec![(pubkey, source)],
            })
        );
    }

    #[test]
    fn known_payloads_are_a_bounded_lru() {
        let market = BuilderMarket::default();
        let capacity = KNOWN_PAYLOADS_CAPACITY.get();
        for index in 0..capacity {
            let mut block_hash = ExecutionBlockHash::ZERO;
            block_hash.0[..8].copy_from_slice(&(index as u64).to_le_bytes());
            market.record_execution_payload(&envelope_with_gas_limit(
                block_hash,
                1,
                Root::ZERO,
                vec![],
            ));
        }
        let mut first = ExecutionBlockHash::ZERO;
        first.0[..8].copy_from_slice(&0u64.to_le_bytes());
        // Touch the oldest so the second becomes the least recently used.
        assert!(market.known_payload(first).is_some());
        market.record_execution_payload(&envelope_with_gas_limit(
            hash(0xff),
            1,
            Root::ZERO,
            vec![],
        ));
        let mut second = ExecutionBlockHash::ZERO;
        second.0[..8].copy_from_slice(&1u64.to_le_bytes());
        assert!(market.known_payload(first).is_some());
        assert!(market.known_payload(second).is_none());
    }
}
