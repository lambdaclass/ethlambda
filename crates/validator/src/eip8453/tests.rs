//! The EIP-8453 duties against the mock beacon node.

use super::*;
use crate::beacon_node::dto::{FinalityAttestationInputDto, encode_hex};
use crate::beacon_node::mock::MockBeaconNode;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::{PAYLOAD_STATUS_EMPTY, PAYLOAD_STATUS_FULL};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::{BlsSignature, Root};

const FORK_EPOCH: u64 = 10;
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn secret(byte: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = byte;
    secret[0] = 0x1a;
    secret
}

fn context() -> Arc<SigningContext> {
    Arc::new(SigningContext {
        config: Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Heze, 0)
            .with_fork_epoch(ForkName::Eip8453, FORK_EPOCH),
        genesis_validators_root: Root::repeat_byte(3),
    })
}

/// A key store holding `count` keys, and their pubkeys.
fn store(count: u8) -> (RwLock<ValidatorStore>, Vec<BlsPubkey>) {
    let mut store = ValidatorStore::new();
    let pubkeys = (1..=count)
        .map(|byte| store.insert_secret("test", &secret(byte)).expect("inserts"))
        .collect();
    (RwLock::new(store), pubkeys)
}

fn slot() -> Slot {
    FORK_EPOCH * SLOTS_PER_EPOCH + 3
}

fn verifies(pubkey: &BlsPubkey, signature: &BlsSignature, root: Root) -> bool {
    use blst::min_pk::{PublicKey, Signature};
    let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
    let sig = Signature::from_bytes(&signature.0).expect("valid signature");
    sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
}

fn head_vote_duty(pubkey: &BlsPubkey, index: u64, slots: Vec<Slot>) -> HeadVoteDutyDto {
    HeadVoteDutyDto {
        pubkey: encode_hex(&pubkey.0),
        validator_index: index,
        slots,
    }
}

fn head_vote_data(slot: Slot, byte: u8, payload_status: u8) -> eip8453::HeadVoteData {
    eip8453::HeadVoteData {
        slot,
        beacon_block_root: Root::repeat_byte(byte),
        payload_status,
    }
}

// ── Head votes ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn each_committee_member_signs_the_nodes_head_once_under_the_head_vote_domain() {
    let (store, pubkeys) = store(2);
    let node = Arc::new(MockBeaconNode::new());
    let data = head_vote_data(slot(), 7, PAYLOAD_STATUS_EMPTY);
    node.set_head_vote_data(data);
    let service = HeadVoteService::new(node.clone(), context());
    let duties = [
        head_vote_duty(&pubkeys[0], 4, vec![slot(), slot() + 2]),
        head_vote_duty(&pubkeys[1], 9, vec![slot() + 1]),
    ];

    let published = service.vote(slot(), &duties, &store).await.unwrap();
    assert_eq!(published, 1, "only the member seated at this slot votes");
    let submitted = node.submitted_head_votes.lock().unwrap().clone();
    assert_eq!(submitted.len(), 1);
    let message = &submitted[0];
    assert_eq!(message.validator_index, 4);
    assert_eq!(message.data, data);
    let root = context().head_vote_signing_root(&data);
    assert!(verifies(&pubkeys[0], &message.signature, root));
    // The domain is DOMAIN_HEAD_VOTE's, not the attester's.
    let attester =
        context().fg_attestation_signing_root(&eip8453::AttestationData::default(), FORK_EPOCH);
    assert_ne!(root, attester);
}

#[tokio::test]
async fn a_second_head_for_a_slot_is_never_signed() {
    let (store, pubkeys) = store(1);
    let node = Arc::new(MockBeaconNode::new());
    let service = HeadVoteService::new(node.clone(), context());
    let duties = [head_vote_duty(&pubkeys[0], 4, vec![slot()])];

    node.set_head_vote_data(head_vote_data(slot(), 7, PAYLOAD_STATUS_EMPTY));
    assert_eq!(service.vote(slot(), &duties, &store).await.unwrap(), 1);

    // The node's head moved within the slot: the record refuses a second
    // head, so nothing is signed or submitted.
    node.set_head_vote_data(head_vote_data(slot(), 8, PAYLOAD_STATUS_FULL));
    assert_eq!(service.vote(slot(), &duties, &store).await.unwrap(), 0);
    assert_eq!(node.submitted_head_votes.lock().unwrap().len(), 1);

    // The same head again (a retry after a failed submission) is the same
    // message, and is signed again.
    node.set_head_vote_data(head_vote_data(slot(), 7, PAYLOAD_STATUS_EMPTY));
    assert_eq!(service.vote(slot(), &duties, &store).await.unwrap(), 1);
    let submitted = node.submitted_head_votes.lock().unwrap().clone();
    assert_eq!(submitted[0], submitted[1]);

    // The next slot is a new vote.
    let next = slot() + 1;
    let duties = [head_vote_duty(&pubkeys[0], 4, vec![next])];
    node.set_head_vote_data(head_vote_data(next, 8, PAYLOAD_STATUS_FULL));
    assert_eq!(service.vote(next, &duties, &store).await.unwrap(), 1);
}

#[tokio::test]
async fn head_vote_data_for_another_slot_is_not_signed() {
    let (store, pubkeys) = store(1);
    let node = Arc::new(MockBeaconNode::new());
    // The mock answers for the slot it is asked about; put a wrong one there.
    node.head_vote_data
        .lock()
        .unwrap()
        .insert(slot(), head_vote_data(slot() + 1, 7, PAYLOAD_STATUS_EMPTY));
    let service = HeadVoteService::new(node.clone(), context());
    let duties = [head_vote_duty(&pubkeys[0], 4, vec![slot()])];
    assert!(service.vote(slot(), &duties, &store).await.is_err());
    assert!(node.submitted_head_votes.lock().unwrap().is_empty());
    // Nothing was recorded either: the right data is signed afterwards.
    node.set_head_vote_data(head_vote_data(slot(), 8, PAYLOAD_STATUS_EMPTY));
    assert_eq!(service.vote(slot(), &duties, &store).await.unwrap(), 1);
}

// ── FG attestations ─────────────────────────────────────────────────────────

fn attester_duty(pubkey: &BlsPubkey, index: u64, committee: u64) -> AttestationCommitteeDutyDto {
    AttestationCommitteeDutyDto {
        pubkey: encode_hex(&pubkey.0),
        validator_index: index,
        committee_index: committee,
        committee_length: 3,
        validator_committee_index: 1,
        slots: vec![slot(), slot() + 8],
    }
}

fn checkpoint(height: u64, byte: u8) -> eip8453::HeightCheckpoint {
    eip8453::HeightCheckpoint {
        height,
        root: Root::repeat_byte(byte),
    }
}

fn input(target: eip8453::HeightCheckpoint) -> FinalityAttestationInputDto {
    FinalityAttestationInputDto {
        target,
        justified: eip8453::HeightCheckpoint::empty(),
        finalized_height: 0,
    }
}

#[tokio::test]
async fn an_attester_selects_through_its_record_and_signs_at_its_slots_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let records = Arc::new(FinalitySigningRecords::in_validators_dir(dir.path()));
    let (store, pubkeys) = store(2);
    let node = Arc::new(MockBeaconNode::new());
    node.set_finality_attestation_input(Some(input(checkpoint(2, 0xaa))));
    let service = FgAttestationService::new(node.clone(), context(), records.clone());
    let duties = [
        attester_duty(&pubkeys[0], 4, 17),
        attester_duty(&pubkeys[1], 9, 18),
    ];

    assert_eq!(service.attest(slot(), &duties, &store).await.unwrap(), 2);
    let submitted = node.submitted_fg_attestations.lock().unwrap().clone();
    assert_eq!(submitted.len(), 2);
    let first = &submitted[0];
    assert_eq!(first.committee_index, 17);
    assert_eq!(first.attester_index, 4);
    assert_eq!(first.epoch, FORK_EPOCH);
    assert_eq!(first.data.target, checkpoint(2, 0xaa));
    assert!(!first.data.timeout);
    let root = context().fg_attestation_signing_root(&first.data, FORK_EPOCH);
    assert!(verifies(&pubkeys[0], &first.signature, root));
    // Recorded, on disk, before the signature existed.
    let on_disk = FinalitySigningRecords::in_validators_dir(dir.path());
    let record = on_disk.record(&pubkeys[0]).await.unwrap();
    assert_eq!(record.targets.get(&2), Some(&Root::repeat_byte(0xaa)));
}

#[tokio::test]
async fn the_record_suppresses_a_repeat_and_times_out_a_conflicting_target() {
    let dir = tempfile::tempdir().unwrap();
    let records = Arc::new(FinalitySigningRecords::in_validators_dir(dir.path()));
    let (store, pubkeys) = store(1);
    let node = Arc::new(MockBeaconNode::new());
    let service = FgAttestationService::new(node.clone(), context(), records);
    let duties = [attester_duty(&pubkeys[0], 4, 17)];

    node.set_finality_attestation_input(Some(input(checkpoint(2, 0xaa))));
    assert_eq!(service.attest(slot(), &duties, &store).await.unwrap(), 1);
    // The same input again (a retry, or the next round with no progress):
    // the entry is already named at the height, so nothing is sent.
    assert_eq!(service.attest(slot(), &duties, &store).await.unwrap(), 0);

    // A restart: a fresh service over the same directory still remembers,
    // and a different target at the height becomes a timeout.
    let records = Arc::new(FinalitySigningRecords::in_validators_dir(dir.path()));
    let service = FgAttestationService::new(node.clone(), context(), records);
    node.set_finality_attestation_input(Some(input(checkpoint(2, 0xbb))));
    assert_eq!(
        service.attest(slot() + 8, &duties, &store).await.unwrap(),
        1
    );
    let submitted = node.submitted_fg_attestations.lock().unwrap().clone();
    assert_eq!(submitted.len(), 2);
    assert!(
        submitted[1].data.timeout,
        "a second target at a height is a timeout"
    );
    assert_eq!(submitted[1].data.target, checkpoint(2, 0xbb));
}

#[tokio::test]
async fn no_fg_source_means_no_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let records = Arc::new(FinalitySigningRecords::in_validators_dir(dir.path()));
    let (store, pubkeys) = store(1);
    let node = Arc::new(MockBeaconNode::new());
    node.set_finality_attestation_input(None);
    let service = FgAttestationService::new(node.clone(), context(), records);
    let duties = [attester_duty(&pubkeys[0], 4, 17)];
    assert_eq!(service.attest(slot(), &duties, &store).await.unwrap(), 0);
    assert!(node.submitted_fg_attestations.lock().unwrap().is_empty());
    // Not even asked when no duty falls in the slot.
    assert_eq!(
        service.attest(slot() + 1, &duties, &store).await.unwrap(),
        0
    );
    assert_eq!(*node.finality_attestation_input_calls.lock().unwrap(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn an_unwritable_record_signs_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let records_dir = dir.path().join(crate::finality_record::RECORDS_DIR);
    std::fs::create_dir_all(&records_dir).unwrap();
    std::fs::set_permissions(&records_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let records = Arc::new(FinalitySigningRecords::in_validators_dir(dir.path()));
    let (store, pubkeys) = store(1);
    let node = Arc::new(MockBeaconNode::new());
    node.set_finality_attestation_input(Some(input(checkpoint(2, 0xaa))));
    let service = FgAttestationService::new(node.clone(), context(), records);
    let duties = [attester_duty(&pubkeys[0], 4, 17)];
    let attested = service.attest(slot(), &duties, &store).await;
    std::fs::set_permissions(&records_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(attested.unwrap(), 0);
    assert!(node.submitted_fg_attestations.lock().unwrap().is_empty());
}
