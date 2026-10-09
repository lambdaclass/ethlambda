//! Publishing inclusion lists: the inclusion list committee duty heze adds
//! (EIP-7805, fork-choice enforced inclusion lists).
//!
//! Sixteen members are drawn each slot from that slot's beacon committees.
//! Each asks its execution client, through the beacon node, for transactions
//! from the public mempool, and publishes them as a signed `InclusionList`;
//! the next slot's payload must then include them for fork choice to extend
//! it. The beacon node supplies the transactions, so this client does not
//! choose them: it builds the list around them, names the shuffling its
//! committee seat came from (the duties' `dependent_root`), signs and
//! submits, which is the same division of labour the attestation duty has.
//!
//! # Timing
//!
//! Sent at [`crate::slot_clock::SlotClock::inclusion_list_time`] and bounded
//! by [`crate::slot_clock::SlotClock::inclusion_list_deadline`]
//! (`INCLUSION_LIST_DUE_BPS`): a list that arrives later is stored by the
//! network but no longer counts towards the payload's constraints.
//!
//! # Nothing to list, nothing to sign
//!
//! An empty mempool answers an empty list, which gossip ignores, so nothing
//! is signed or published for it.
//!
//! # Duplicates
//!
//! A second, different list from one member for one slot makes it an
//! equivocator, whose lists then stop counting for the slot. So the slot is
//! recorded per validator at signing time, as the PTC duty does, and a duty
//! abandoned between signing and submission is lost rather than re-signed.
//! In memory only, like the PTC record.

use std::collections::HashSet;
use std::sync::Arc;

use ethlambda_types::beacon::containers::gloas::{Transaction, Transactions};
use ethlambda_types::beacon::containers::heze::{InclusionList, SignedInclusionList};
use ethlambda_types::beacon::primitives::{Root, Slot, ValidatorIndex};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{InclusionListDutyDto, parse_pubkey};
use crate::error::Result;
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// How many slots of dedup history are kept, as for the PTC record.
const HISTORY_SLOTS: u64 = 64;

pub struct InclusionListService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Which (validator, slot) pairs already produced a signature.
    done: std::sync::Mutex<HashSet<(ValidatorIndex, Slot)>>,
}

impl<B: BeaconNodeApi> InclusionListService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            done: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// Build, sign and publish this client's inclusion lists for `slot`, one
    /// per committee member in `duties`, all naming `dependent_root`.
    ///
    /// Returns how many lists the node accepted: zero when the execution
    /// client has nothing to list, or when every member was already served.
    ///
    /// # Do not retry this call within a slot
    ///
    /// A second call asks for the transactions again, and a mempool that moved
    /// in between would give a different list from the same member: an
    /// equivocation. The dedup refuses it, so a retry is merely useless.
    pub async fn publish(
        &self,
        slot: Slot,
        dependent_root: Root,
        duties: &[InclusionListDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        // Cheap pre-check, so a slot already served costs the node no request.
        let pending: Vec<&InclusionListDutyDto> = {
            let done = self.lock();
            duties
                .iter()
                .filter(|duty| duty.slot == slot && !done.contains(&(duty.validator_index, slot)))
                .collect()
        };
        if pending.is_empty() {
            return Ok(0);
        }

        let fetched = self.beacon_node.inclusion_list_transactions(slot).await?;
        let transactions = self.bounded(fetched);
        if transactions.is_empty() {
            debug!(%slot, "The execution client has nothing to list; publishing no inclusion list");
            return Ok(0);
        }
        let transaction_count = transactions.len();
        let transactions: Transactions = transactions.into();

        let mut lists = Vec::with_capacity(pending.len());
        {
            let _timing = crate::metrics::time_signing();
            let store = store.read().await;
            for duty in pending {
                let pubkey = match parse_pubkey(&duty.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                        continue;
                    }
                };

                // Recorded before signing, so a signature that exists is one
                // the record already knows about.
                if !self.record(duty.validator_index, slot) {
                    continue;
                }

                let inclusion_list = InclusionList {
                    slot,
                    validator_index: duty.validator_index,
                    dependent_root,
                    transactions: transactions.clone(),
                };
                match self
                    .context
                    .sign_inclusion_list(&store, &pubkey, &inclusion_list)
                {
                    Ok(signature) => lists.push(SignedInclusionList {
                        message: inclusion_list,
                        signature,
                    }),
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Failed to sign inclusion list");
                        crate::metrics::inc_signing_failures();
                    }
                }
            }
        }

        // One request per list: the endpoint takes a single list.
        let mut published = 0;
        for signed in &lists {
            match self.beacon_node.publish_inclusion_list(signed).await {
                Ok(()) => published += 1,
                Err(err) => warn!(
                    %slot,
                    validator = signed.message.validator_index,
                    %err,
                    "The beacon node refused an inclusion list"
                ),
            }
        }
        if published > 0 {
            info!(
                %slot,
                count = published,
                transactions = transaction_count,
                "Published inclusion lists"
            );
            crate::metrics::inc_inclusion_lists_published(published as u64);
        }
        Ok(published)
    }

    /// `fetched` without empty transactions, cut off before the first one
    /// that would take the list past `MAX_TRANSACTIONS_BYTES_PER_INCLUSION_LIST`.
    ///
    /// The execution client is held to both rules already
    /// (`engine_getInclusionListV1`), and the network rejects a list breaking
    /// either, so this is the backstop that keeps one wrong answer from
    /// costing the member its list.
    fn bounded(&self, fetched: Vec<Vec<u8>>) -> Vec<Transaction> {
        let limit = self
            .context
            .config
            .max_transactions_bytes_per_inclusion_list;
        let mut size = 0u64;
        let mut kept = Vec::new();
        for transaction in fetched.into_iter().filter(|tx| !tx.is_empty()) {
            size = size.saturating_add(transaction.len() as u64);
            if size > limit {
                break;
            }
            kept.push(Transaction::from(transaction));
        }
        kept
    }

    /// Record that `validator` is being served for `slot`. `false` when it
    /// already was, or when the record is unusable.
    fn record(&self, validator: ValidatorIndex, slot: Slot) -> bool {
        let Ok(mut done) = self.done.lock() else {
            error!(%slot, "Inclusion list record is poisoned; refusing to sign");
            return false;
        };
        done.retain(|(_, held)| held + HISTORY_SLOTS > slot);
        done.insert((validator, slot))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<(ValidatorIndex, Slot)>> {
        // A poisoned set is still a set; the signing path re-checks through
        // `record`, which refuses on poison.
        self.done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::dto::encode_hex;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    use ethlambda_types::beacon::primitives::BlsPubkey;

    const HEZE_EPOCH: u64 = 10;
    const DEPENDENT_ROOT: Root = Root::repeat_byte(4);

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet()
                .with_fork_epoch(ForkName::Gloas, 0)
                .with_fork_epoch(ForkName::Heze, HEZE_EPOCH),
            genesis_validators_root: Root::ZERO,
        })
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn slot() -> Slot {
        HEZE_EPOCH * SLOTS_PER_EPOCH + 4
    }

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> InclusionListDutyDto {
        InclusionListDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index,
            slot,
        }
    }

    fn node_with(transactions: Vec<Vec<u8>>) -> Arc<MockBeaconNode> {
        Arc::new(MockBeaconNode::new().with_inclusion_list_transactions(transactions))
    }

    #[tokio::test]
    async fn a_committee_member_signs_and_publishes_the_execution_clients_list() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store();
        let node = node_with(vec![vec![0x02, 0xf8, 0x01], vec![0xaa]]);
        let service = InclusionListService::new(node.clone(), context());

        let published = service
            .publish(slot(), DEPENDENT_ROOT, &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect("publishes");
        assert_eq!(published, 1);

        let lists = node.published_inclusion_lists();
        assert_eq!(lists.len(), 1);
        let message = &lists[0].message;
        assert_eq!(message.slot, slot());
        assert_eq!(message.validator_index, 9);
        assert_eq!(message.dependent_root, DEPENDENT_ROOT);
        assert_eq!(message.transactions.len(), 2);

        // Over the whole list, under the inclusion list committee domain at
        // the list's epoch.
        let root = context().inclusion_list_signing_root(message);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&lists[0].signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    /// An empty mempool is an ordinary answer: nothing is signed or published.
    #[tokio::test]
    async fn an_empty_list_is_not_published() {
        let (store, pubkey) = store();
        let node = node_with(Vec::new());
        let service = InclusionListService::new(node.clone(), context());

        let published = service
            .publish(slot(), DEPENDENT_ROOT, &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect("an empty list is not an error");
        assert_eq!(published, 0);
        assert_eq!(node.inclusion_list_transactions_call_count(), 1);
        assert!(node.published_inclusion_lists().is_empty());
    }

    /// One list per (validator, slot): the second call neither asks the node
    /// nor signs again.
    #[tokio::test]
    async fn a_member_is_served_once_per_slot() {
        let (store, pubkey) = store();
        let node = node_with(vec![vec![0x01]]);
        let service = InclusionListService::new(node.clone(), context());
        let duties = [duty(&pubkey, 9, slot())];

        service
            .publish(slot(), DEPENDENT_ROOT, &duties, &store)
            .await
            .expect("first");
        let again = service
            .publish(slot(), DEPENDENT_ROOT, &duties, &store)
            .await
            .expect("second");

        assert_eq!(again, 0);
        assert_eq!(node.published_inclusion_lists().len(), 1);
        assert_eq!(node.inclusion_list_transactions_call_count(), 1);
    }

    /// The list is cut at the byte bound and empty transactions dropped, so
    /// one oversized answer does not cost the member its list.
    #[tokio::test]
    async fn the_list_is_kept_within_the_byte_bound() {
        let (store, pubkey) = store();
        let limit = context().config.max_transactions_bytes_per_inclusion_list as usize;
        let node = node_with(vec![
            Vec::new(),
            vec![0x01; limit - 1],
            vec![0x02; 2],
            vec![0x03],
        ]);
        let service = InclusionListService::new(node.clone(), context());

        service
            .publish(slot(), DEPENDENT_ROOT, &[duty(&pubkey, 9, slot())], &store)
            .await
            .expect("publishes");
        let lists = node.published_inclusion_lists();
        assert_eq!(lists[0].message.transactions.len(), 1);
        assert_eq!(lists[0].message.transactions[0].len(), limit - 1);
    }

    #[tokio::test]
    async fn no_duties_asks_the_node_for_nothing() {
        let (store, _) = store();
        let node = node_with(vec![vec![0x01]]);
        let service = InclusionListService::new(node.clone(), context());

        assert_eq!(
            service
                .publish(slot(), DEPENDENT_ROOT, &[], &store)
                .await
                .expect("no-op"),
            0
        );
        assert_eq!(node.inclusion_list_transactions_call_count(), 0);
    }
}
