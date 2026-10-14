//! The decoupled fork's validator duties: the Goldfish vote and the
//! attestation, and the anti-slashing record that guards both.
//!
//! The decoupled protocol (Goldilocks) has no LMD attestations. A validator
//! instead:
//!
//! - votes for the head once per slot it sits on the committee of, a quarter
//!   of the way into the slot (`t_s + Δ`), and
//! - reads its attestation input every slot, half way into the slot
//!   (`t_s + 2Δ`, right after the node's confirmation update), and casts an
//!   attestation, carrying the height and finality pairs of the finality
//!   gadget, only when one of the pairs is new. On a chain without height
//!   progress nothing is new, so the attestation traffic of a stalled
//!   finality dies down by itself.
//!
//! # The record is the point
//!
//! The combined attestation is slashable (E1 and E2, see
//! [`ethlambda_decoupled::validator_client`]), and what keeps an honest
//! validator clear of both is [`Record`], the protocol's anti-slashing record
//! Λ. The protocol puts it in the validator client and gives it one entry
//! point, `create_attestation`: it takes the vote information the node derived
//! from its store, decides the pairs, updates the record, and only then
//! releases the attestation. This module calls exactly that and re-implements
//! none of the pair rules.
//!
//! # Persistence
//!
//! One record per validator public key, at
//! `<validators-dir>/decoupled/<0xpubkey>.json`, together with the last slot
//! voted and the last slot attested. Every change is written (to a temporary
//! file, synced, then renamed over the real one) **before** the signature that
//! depends on it exists: record, then release. A process killed between the two
//! loses one attestation and never signs a second, different one.
//!
//! A file that does not parse is a hard error for that validator, which then
//! signs nothing: a silent reset to an empty record would forget the very
//! votes the record exists to remember, and is how a restart becomes a
//! slashing.
//!
//! The record is read lazily, when a validator first has a duty, rather than at
//! startup, because keys can be imported while the client runs. A validator
//! whose file is unreadable is refused again on every duty, which keeps the
//! error visible until an operator deals with it.
//!
//! # What it does not do
//!
//! It does not judge the vote information. `AttestationInput` is the node's
//! answer, checked for being about the right slot and nothing more; a node that
//! lies about the chain costs a validator a bad vote, never a slashing, since
//! the record decides the pairs against what it already holds.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ethlambda_decoupled::Record;
use ethlambda_types::beacon::containers::decoupled::{
    SignedCombinedAttestation, SignedGoldfishVote,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, Slot, ValidatorIndex};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::dto::{AttesterDutyDto, encode_hex, parse_pubkey};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::secure_fs;
use crate::signing::SigningContext;

/// The directory under the validators directory the records live in.
pub const RECORDS_DIR: &str = "decoupled";

/// One validator's persisted state: the protocol's record plus the two
/// watermarks that stop a restart from signing twice in one slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ValidatorState {
    record: Record,
    /// The slot of the last Goldfish vote signed.
    last_vote_slot: Option<Slot>,
    /// The slot of the last attestation signed.
    #[serde(default)]
    last_attestation_slot: Option<Slot>,
}

pub struct DecoupledService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// `<validators-dir>/decoupled`.
    dir: PathBuf,
    /// The state of every validator seen so far, loaded from disk on first use.
    ///
    /// A `std::sync::Mutex`, held across disk I/O and never across an await:
    /// the critical section is one load or one read-modify-write-persist, and
    /// keeping it single-threaded is what makes "persist, then sign" atomic
    /// with respect to a second duty for the same validator.
    states: std::sync::Mutex<HashMap<BlsPubkey, ValidatorState>>,
}

impl<B: BeaconNodeApi> DecoupledService<B> {
    /// A service keeping its records under `validators_dir/decoupled`.
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>, validators_dir: &Path) -> Self {
        Self {
            beacon_node,
            context,
            dir: validators_dir.join(RECORDS_DIR),
            states: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Sign and submit this client's Goldfish votes for `slot`, one per
    /// validator in `duties` (the committee members it runs).
    ///
    /// Returns how many votes the node accepted.
    ///
    /// A validator that has already voted in `slot` or a later one is skipped,
    /// across restarts. When every validator is skipped, the node is not asked
    /// for anything.
    pub async fn vote(
        &self,
        slot: Slot,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        let pending: Vec<&AttesterDutyDto> = duties
            .iter()
            .filter(|duty| self.may_vote(duty, slot))
            .collect();
        if pending.is_empty() {
            return Ok(0);
        }

        let data = self.beacon_node.goldfish_vote_data(slot).await?;
        // Checked again here, having been checked by the implementation, for
        // the reason the attestation duty does: the trait is public and this is
        // the last point before the data becomes a signature.
        if data.slot != slot {
            return Err(Error::InconsistentResponse(format!(
                "requested goldfish vote data for slot {slot}, node answered for slot {}",
                data.slot
            )));
        }

        let mut votes = Vec::with_capacity(pending.len());
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

                // Recorded, and persisted, before the signature exists.
                let recorded = self.advance(&pubkey, |state| {
                    if state.last_vote_slot.is_some_and(|last| slot <= last) {
                        return None;
                    }
                    state.last_vote_slot = Some(slot);
                    Some(())
                });
                match recorded {
                    Ok(Some(())) => {}
                    Ok(None) => continue,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Refusing to sign a Goldfish vote");
                        crate::metrics::inc_goldfish_vote_failures();
                        continue;
                    }
                }

                match self.context.sign_goldfish_vote(&store, &pubkey, &data) {
                    Ok(signature) => {
                        crate::metrics::inc_goldfish_votes_signed();
                        votes.push(SignedGoldfishVote {
                            validator_index: duty.validator_index,
                            data,
                            signature,
                        });
                    }
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Failed to sign Goldfish vote");
                        crate::metrics::inc_signing_failures();
                        crate::metrics::inc_goldfish_vote_failures();
                    }
                }
            }
        }

        if votes.is_empty() {
            return Ok(0);
        }

        let submitted = votes.len();
        let published = self.beacon_node.submit_goldfish_votes(&votes).await?;
        if published < submitted {
            warn!(
                %slot,
                published,
                submitted,
                "Some Goldfish votes in this slot's batch were rejected by the beacon node"
            );
        }
        info!(%slot, head = %ethlambda_types::ShortRoot(&data.head.0), count = published, "Published Goldfish votes");
        crate::metrics::inc_goldfish_votes_published(published as u64);
        Ok(published)
    }

    /// Read the attestation input of `slot` (a round's action slot), and
    /// create, record, sign and submit an attestation for each of
    /// `validators` (every active validator this client runs) whose record
    /// finds a new height pair in it.
    ///
    /// Returns how many attestations the node accepted.
    ///
    /// A validator that has already attested in `slot` or a later one is
    /// skipped, across restarts. One whose record makes nothing of the input
    /// is skipped too, and its record left untouched.
    pub async fn attest(
        &self,
        slot: Slot,
        validators: &[(BlsPubkey, ValidatorIndex)],
        store: &RwLock<ValidatorStore>,
    ) -> Result<usize> {
        let pending: Vec<&(BlsPubkey, ValidatorIndex)> = validators
            .iter()
            .filter(|(pubkey, index)| self.may_attest(pubkey, *index, slot))
            .collect();
        if pending.is_empty() {
            return Ok(0);
        }

        let input = self.beacon_node.decoupled_attestation_input(slot).await?;
        if input.slot != slot {
            return Err(Error::InconsistentResponse(format!(
                "requested attestation input for slot {slot}, node answered for slot {}",
                input.slot
            )));
        }

        let mut attestations = Vec::with_capacity(pending.len());
        {
            let _timing = crate::metrics::time_signing();
            let store = store.read().await;
            for (pubkey, index) in pending {
                // `create_attestation` updates the record, the state is
                // persisted, and only then is anything signed.
                let created = self.advance(pubkey, |state| {
                    if state.last_attestation_slot.is_some_and(|last| slot <= last) {
                        return None;
                    }
                    let attestation = state.record.create_attestation(*index, &input)?;
                    state.last_attestation_slot = Some(slot);
                    // Heights below the finalized one can never be voted
                    // again. Pruned after the decision, so it was made against
                    // the whole record.
                    state.record.prune_below(input.finalized_height);
                    Some(attestation.data)
                });
                let data = match created {
                    Ok(Some(data)) => data,
                    Ok(None) => continue,
                    Err(err) => {
                        error!(%slot, validator = index, %err, "Refusing to sign a combined attestation");
                        crate::metrics::inc_combined_attestation_failures();
                        continue;
                    }
                };

                match self
                    .context
                    .sign_combined_attestation(&store, pubkey, &data)
                {
                    Ok(signature) => {
                        crate::metrics::inc_combined_attestations_signed();
                        attestations.push(SignedCombinedAttestation {
                            validator_index: *index,
                            data,
                            signature,
                        });
                    }
                    Err(err) => {
                        error!(%slot, validator = index, %err, "Failed to sign combined attestation");
                        crate::metrics::inc_signing_failures();
                        crate::metrics::inc_combined_attestation_failures();
                    }
                }
            }
        }

        if attestations.is_empty() {
            return Ok(0);
        }

        let submitted = attestations.len();
        let published = self
            .beacon_node
            .submit_combined_attestations(&attestations)
            .await?;
        if published < submitted {
            warn!(
                %slot,
                published,
                submitted,
                "Some combined attestations in this slot's batch were rejected by the beacon node"
            );
        }
        info!(%slot, count = published, "Published combined attestations");
        crate::metrics::inc_combined_attestations_published(published as u64);
        Ok(published)
    }

    /// Whether `duty`'s validator may still vote in `slot`. A validator whose
    /// record cannot be read may not, and the reason is logged.
    fn may_vote(&self, duty: &AttesterDutyDto, slot: Slot) -> bool {
        let Ok(pubkey) = parse_pubkey(&duty.pubkey) else {
            // Reported with the signing loop's own message, which names it.
            return true;
        };
        self.peek(&pubkey, duty.validator_index, |state| {
            state.last_vote_slot.is_none_or(|last| slot > last)
        })
    }

    /// Whether the validator may still attest in `slot`; see [`Self::may_vote`].
    fn may_attest(&self, pubkey: &BlsPubkey, index: ValidatorIndex, slot: Slot) -> bool {
        self.peek(pubkey, index, |state| {
            state.last_attestation_slot.is_none_or(|last| slot > last)
        })
    }

    fn peek(
        &self,
        pubkey: &BlsPubkey,
        index: ValidatorIndex,
        check: impl FnOnce(&ValidatorState) -> bool,
    ) -> bool {
        // `advance` persists only a changed state, and this changes nothing.
        match self.advance(pubkey, |state| check(state).then_some(())) {
            Ok(answer) => answer.is_some(),
            Err(err) => {
                error!(validator = index, %err, "Cannot read this validator's anti-slashing record; refusing its duty");
                false
            }
        }
    }

    /// Apply `change` to the validator's state and, when it answers `Some`,
    /// persist the result before keeping it. `None` leaves memory and disk
    /// untouched.
    ///
    /// The state is loaded from disk the first time a validator is seen. An
    /// unreadable file is an `Err` every time, and is not replaced by an empty
    /// record.
    fn advance<R>(
        &self,
        pubkey: &BlsPubkey,
        change: impl FnOnce(&mut ValidatorState) -> Option<R>,
    ) -> Result<Option<R>> {
        let mut states = self
            .states
            .lock()
            .map_err(|_| Error::Decode("anti-slashing record lock is poisoned".to_string()))?;
        if !states.contains_key(pubkey) {
            let loaded = self.load(pubkey)?;
            states.insert(*pubkey, loaded);
        }
        let held = states.get_mut(pubkey).expect("inserted above");

        // Worked on a copy, so a failed write leaves the held state as it was:
        // memory must never run ahead of disk.
        let mut next = held.clone();
        let Some(answer) = change(&mut next) else {
            return Ok(None);
        };
        if next != *held {
            self.persist(pubkey, &next)?;
            *held = next;
        }
        Ok(Some(answer))
    }

    fn path(&self, pubkey: &BlsPubkey) -> PathBuf {
        self.dir.join(format!("{}.json", encode_hex(&pubkey.0)))
    }

    fn load(&self, pubkey: &BlsPubkey) -> Result<ValidatorState> {
        let path = self.path(pubkey);
        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).map_err(|err| Error::Io {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("anti-slashing record does not parse: {err}"),
                ),
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ValidatorState::default()),
            Err(source) => Err(Error::Io {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Write `state` durably: a synced temporary file renamed over the record,
    /// then the directory synced, so the rename itself survives a crash.
    fn persist(&self, pubkey: &BlsPubkey, state: &ValidatorState) -> Result<()> {
        let path = self.path(pubkey);
        let io_error = |source| Error::Io {
            path: path.display().to_string(),
            source,
        };
        std::fs::create_dir_all(&self.dir).map_err(io_error)?;
        let json = serde_json::to_vec_pretty(state).map_err(|err| {
            io_error(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            ))
        })?;
        let tmp = path.with_extension("json.tmp");
        secure_fs::write_private_no_symlink(&tmp, &json).map_err(io_error)?;
        std::fs::File::open(&tmp)
            .and_then(|file| file.sync_all())
            .map_err(io_error)?;
        std::fs::rename(&tmp, &path).map_err(io_error)?;
        // Best effort: not every platform lets a directory be opened to sync.
        if let Ok(dir) = std::fs::File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_decoupled::{AttestationInput, SourceFields};
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::Root;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        let config = Config::mainnet().with_fork_epoch(ForkName::Decoupled, 0);
        Arc::new(SigningContext {
            config,
            genesis_validators_root: Root::repeat_byte(7),
        })
    }

    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn duty(pubkey: &BlsPubkey, slot: Slot) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: 7,
            committee_index: 0,
            committee_length: 1,
            committees_at_slot: 1,
            validator_committee_index: 0,
            slot,
        }
    }

    fn input(source: Option<(u64, u8)>) -> AttestationInput {
        AttestationInput {
            slot: 0,
            source: source.map(|(height, entry)| SourceFields {
                height,
                entry: Root::repeat_byte(entry),
            }),
            justified_height: 2,
            justified: Root::repeat_byte(9),
            finalized_height: 1,
        }
    }

    fn verifies(pubkey: &BlsPubkey, signature: &[u8; 96], root: Root) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(signature).expect("valid signature");
        sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    fn service(node: &Arc<MockBeaconNode>, dir: &Path) -> DecoupledService<MockBeaconNode> {
        DecoupledService::new(node.clone(), context(), dir)
    }

    /// The JSON the beacon node serves, as the API contract states it.
    #[test]
    fn the_nodes_json_shapes_parse() {
        use crate::beacon_node::dto::DataResponse;
        use ethlambda_types::beacon::containers::decoupled::GoldfishVoteData;

        let vote: DataResponse<GoldfishVoteData> = serde_json::from_str(&format!(
            r#"{{"data": {{"slot": "123", "head": "0x{}"}}}}"#,
            "11".repeat(32)
        ))
        .expect("goldfish vote data parses");
        assert_eq!(vote.data.slot, 123);
        assert_eq!(vote.data.head, Root::repeat_byte(0x11));

        let input: DataResponse<AttestationInput> = serde_json::from_str(&format!(
            r#"{{"data": {{"slot": 5, "source": {{"height": 3, "entry": "0x{b}"}}, "justified_height": 2, "justified": "0x{b}", "finalized_height": 1}}}}"#,
            b = "bb".repeat(32),
        ))
        .expect("attestation input parses");
        assert_eq!(input.data.slot, 5);
        assert_eq!(input.data.source.expect("a source").height, 3);

        let none: DataResponse<AttestationInput> = serde_json::from_str(&format!(
            r#"{{"data": {{"slot": 5, "source": null, "justified_height": 2, "justified": "0x{a}", "finalized_height": 1}}}}"#,
            a = "aa".repeat(32),
        ))
        .expect("a null source parses");
        assert!(none.data.source.is_none());
    }

    /// What the node is sent: quoted validator index, `AttestationData` with
    /// its height pair and an absent finality pair as `null`.
    #[test]
    fn the_submitted_json_matches_the_contract() {
        let attestation = SignedCombinedAttestation {
            validator_index: 7,
            data: ethlambda_decoupled::AttestationData::new(
                ethlambda_decoupled::HeightVote {
                    height: 3,
                    entry: Root::repeat_byte(1),
                    timeout: false,
                },
                None,
            ),
            signature: Default::default(),
        };
        let json = serde_json::to_value(&attestation).expect("serializes");
        assert!(json["data"].get("round").is_none(), "no rounds");
        assert_eq!(json["data"]["height_pair"]["height"], 3);
        assert!(json["data"]["finality_pair"].is_null());
        assert_eq!(json["validator_index"], "7");
    }

    #[tokio::test]
    async fn a_vote_is_signed_under_the_goldfish_domain_and_submitted_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_goldfish_head(Root::repeat_byte(5)));
        let service = service(&node, dir.path());
        let duties = [duty(&pubkey, 5)];

        assert_eq!(service.vote(5, &duties, &store).await.expect("votes"), 1);

        let votes = node.submitted_goldfish_votes();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].validator_index, 7);
        assert_eq!(votes[0].data.slot, 5);
        assert_eq!(votes[0].data.head, Root::repeat_byte(5));
        let root = context().goldfish_vote_signing_root(&votes[0].data);
        assert!(verifies(&pubkey, &votes[0].signature.0, root));
    }

    #[tokio::test]
    async fn a_second_vote_for_the_same_slot_is_not_signed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_goldfish_head(Root::repeat_byte(5)));
        let service = service(&node, dir.path());
        let duties = [duty(&pubkey, 5)];

        service.vote(5, &duties, &store).await.expect("votes");
        assert_eq!(service.vote(5, &duties, &store).await.expect("skips"), 0);
        // An earlier slot is refused as well: the watermark only advances.
        assert_eq!(service.vote(4, &duties, &store).await.expect("skips"), 0);

        assert_eq!(node.submitted_goldfish_votes().len(), 1);
        assert_eq!(
            node.goldfish_vote_data_call_count(),
            1,
            "a slot already served costs the node no request"
        );
    }

    #[tokio::test]
    async fn a_restart_does_not_vote_again_for_the_same_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_goldfish_head(Root::repeat_byte(5)));
        let duties = [duty(&pubkey, 5)];

        service(&node, dir.path())
            .vote(5, &duties, &store)
            .await
            .expect("votes");
        // A new service over the same directory is a restarted process.
        let restarted = service(&node, dir.path());
        assert_eq!(restarted.vote(5, &duties, &store).await.expect("skips"), 0);
        assert_eq!(restarted.vote(6, &duties, &store).await.expect("votes"), 1);
        assert_eq!(node.submitted_goldfish_votes().len(), 2);
    }

    #[tokio::test]
    async fn the_attestation_goes_through_the_record_and_is_signed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_decoupled_input(input(Some((3, 1)))));
        let service = service(&node, dir.path());

        let published = service
            .attest(5, &[(pubkey, 7)], &store)
            .await
            .expect("attests");
        assert_eq!(published, 1);

        let submitted = node.submitted_combined_attestations();
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].validator_index, 7);

        // The very data `Record::create_attestation` decides for a fresh record.
        let expected = Record::default()
            .create_attestation(7, &input(Some((3, 1))))
            .expect("a fresh record attests")
            .data;
        assert_eq!(submitted[0].data, expected);

        let root = context().combined_attestation_signing_root(&submitted[0].data);
        assert!(verifies(&pubkey, &submitted[0].signature.0, root));
    }

    #[tokio::test]
    async fn an_unchanged_input_is_not_attested_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_decoupled_input(input(Some((3, 1)))));
        let service = service(&node, dir.path());
        let validators = [(pubkey, 7)];

        assert_eq!(service.attest(5, &validators, &store).await.unwrap(), 1);
        for slot in 6..10 {
            assert_eq!(service.attest(slot, &validators, &store).await.unwrap(), 0);
        }
        assert_eq!(node.submitted_combined_attestations().len(), 1);
        // The slot watermark only moves with an attestation.
        let saved: ValidatorState = serde_json::from_str(
            &std::fs::read_to_string(service.path(&pubkey)).expect("file exists"),
        )
        .expect("parses");
        assert_eq!(saved.last_attestation_slot, Some(5));
    }

    #[tokio::test]
    async fn a_different_target_at_a_recorded_height_times_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_decoupled_input(input(Some((3, 1)))));
        let service = service(&node, dir.path());
        let validators = [(pubkey, 7)];

        service.attest(5, &validators, &store).await.expect("first");
        // The chain now offers another entry at the same height.
        node.set_decoupled_input(input(Some((3, 2))));
        service
            .attest(6, &validators, &store)
            .await
            .expect("second");

        let submitted = node.submitted_combined_attestations();
        assert_eq!(submitted.len(), 2);
        let first = submitted[0].data.height_pair();
        assert!(!first.timeout);
        let second = submitted[1].data.height_pair();
        assert!(second.timeout, "voting two entries at one height is E2");
        assert_eq!(second.height, 3);
    }

    #[tokio::test]
    async fn the_record_is_on_disk_before_the_attestation_is_released() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        // The node refuses the submission, so nothing is ever released.
        let node = Arc::new(
            MockBeaconNode::new()
                .with_decoupled_input(input(Some((3, 1))))
                .failing_call("submit_combined_attestations", "node is unhappy"),
        );
        let service = service(&node, dir.path());

        service
            .attest(5, &[(pubkey, 7)], &store)
            .await
            .expect_err("the submission fails");
        assert!(node.submitted_combined_attestations().is_empty());

        let path = service.path(&pubkey);
        let saved: ValidatorState =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("file exists"))
                .expect("parses");
        assert_eq!(saved.last_attestation_slot, Some(5));
        assert_eq!(saved.record.target.get(&3), Some(&Root::repeat_byte(1)));

        // And the lost attestation is not re-signed on a retry.
        let node = Arc::new(MockBeaconNode::new().with_decoupled_input(input(Some((3, 9)))));
        let restarted = self::service(&node, dir.path());
        assert_eq!(
            restarted
                .attest(5, &[(pubkey, 7)], &store)
                .await
                .expect("skips"),
            0
        );
        assert!(node.submitted_combined_attestations().is_empty());
    }

    #[tokio::test]
    async fn a_restart_refuses_a_repeated_slot_and_keeps_the_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_decoupled_input(input(Some((3, 1)))));
        let validators = [(pubkey, 7)];
        service(&node, dir.path())
            .attest(5, &validators, &store)
            .await
            .expect("attests");

        let restarted = service(&node, dir.path());
        assert_eq!(
            restarted
                .attest(5, &validators, &store)
                .await
                .expect("skips"),
            0
        );
        assert_eq!(
            restarted
                .attest(4, &validators, &store)
                .await
                .expect("skips"),
            0
        );
        assert_eq!(node.submitted_combined_attestations().len(), 1);

        // The reloaded record still remembers entry 1 at height 3.
        node.set_decoupled_input(input(Some((3, 2))));
        restarted
            .attest(6, &validators, &store)
            .await
            .expect("next slot");
        let submitted = node.submitted_combined_attestations();
        assert!(submitted[1].data.height_pair().timeout);
    }

    #[tokio::test]
    async fn a_corrupt_record_refuses_to_sign_and_is_not_reset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_decoupled_input(input(Some((3, 1))))
                .with_goldfish_head(Root::repeat_byte(5)),
        );
        let service = service(&node, dir.path());
        let path = service.path(&pubkey);
        std::fs::create_dir_all(path.parent().expect("has a parent")).expect("creates");
        std::fs::write(&path, "{ not json").expect("writes");

        assert_eq!(
            service
                .attest(5, &[(pubkey, 7)], &store)
                .await
                .expect("refuses quietly"),
            0
        );
        assert_eq!(
            service
                .vote(5, &[duty(&pubkey, 5)], &store)
                .await
                .expect("refuses quietly"),
            0
        );
        assert!(node.submitted_combined_attestations().is_empty());
        assert!(node.submitted_goldfish_votes().is_empty());
        assert_eq!(
            std::fs::read_to_string(&path).expect("still there"),
            "{ not json",
            "the unreadable file is left for the operator, not overwritten"
        );
    }

    #[tokio::test]
    async fn the_record_is_pruned_below_the_finalized_height() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_decoupled_input(input(Some((1, 1)))));
        let service = service(&node, dir.path());
        service
            .attest(1, &[(pubkey, 7)], &store)
            .await
            .expect("attests at height 1");

        // Finality moves past height 1.
        node.set_decoupled_input(AttestationInput {
            finalized_height: 4,
            justified_height: 5,
            ..input(Some((6, 2)))
        });
        service
            .attest(2, &[(pubkey, 7)], &store)
            .await
            .expect("attests at height 6");

        let saved: ValidatorState = serde_json::from_str(
            &std::fs::read_to_string(service.path(&pubkey)).expect("file exists"),
        )
        .expect("parses");
        assert!(!saved.record.target.contains_key(&1));
        assert!(saved.record.target.contains_key(&6));
    }
}
