//! `ethlambda validator`'s own HTTP client, driven against this node's Beacon
//! API over a real socket.
//!
//! The endpoint tests elsewhere check each answer against the spec; this checks
//! the two ends agree on the wire. A field this node names differently from what
//! the client parses, a number left unquoted, or a status the client does not
//! expect would each pass every endpoint test here and still leave the client
//! unable to attest.

use std::sync::Arc;

use axum::Extension;
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::helpers::{
    accessors::get_domain,
    fulu::initialize_proposer_lookahead,
    test_state::{sign_for, with_signing_validators_at},
};
use ethlambda_types::{
    beacon::{
        constants::DOMAIN_BEACON_ATTESTER,
        containers::BeaconState,
        fork::ForkName,
        preset,
        primitives::BlsPubkey,
        signing::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch},
    },
    primitives::HashTreeRoot as _,
};
use ethlambda_validator::{
    Error,
    beacon_node::{
        BeaconNodeApi, BlockRequest,
        dto::{
            AttestationDataOutDto, CommitteeSubscriptionDto, ProposerPreparationDto,
            SingleAttestationDto, encode_hex,
        },
        http::HttpBeaconNode,
    },
};

use crate::test_utils::{RecordingNetwork, beacon_store_at};

const COUNT: usize = 64;

/// A fulu head state at the first slot of the wall clock's current epoch, with
/// its proposer lookahead filled in, served over HTTP on an ephemeral port.
async fn serve() -> (HttpBeaconNode, BeaconState, Arc<RecordingNetwork>) {
    let mut state = with_signing_validators_at(ForkName::Fulu, COUNT);
    let (probe, _) = beacon_store_at(state.clone());
    let wall_epoch = compute_epoch_at_slot(crate::beacon::node::wall_slot(&probe));
    let lookahead = {
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot = compute_start_slot_at_epoch(wall_epoch);
        initialize_proposer_lookahead(&state).unwrap()
    };
    let BeaconState::Fulu(fulu) = &mut state else {
        unreachable!("built as fulu")
    };
    fulu.proposer_lookahead = lookahead.try_into().unwrap();

    let (store, _root) = beacon_store_at(state.clone());
    let network = Arc::new(RecordingNetwork::default());
    let p2p: RpcToP2PRef = network.clone();
    let router = crate::build_beacon_api_router(store, "ethlambda/test", "peer".into())
        .layer(Extension(SyncStatusController::new(SyncStatus::Synced)))
        .layer(Extension(p2p));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });

    let client = HttpBeaconNode::new(format!("http://{address}")).unwrap();
    (client, state, network)
}

/// One slot of an attester's work, in the order `ethlambda validator` does it.
#[tokio::test]
async fn the_validator_client_can_attest_through_this_node() {
    let (client, state, network) = serve().await;
    let slot = state.slot();
    let epoch = compute_epoch_at_slot(slot);

    client.genesis().await.expect("genesis");
    client
        .spec()
        .await
        .expect("the client reads this node's spec");
    assert!(
        !client.is_optimistic_or_syncing().await.unwrap(),
        "a synced node with no optimistic block must be signable against"
    );

    let pubkeys: Vec<BlsPubkey> = (0..COUNT as u64)
        .map(|index| state.validator(index).unwrap().pubkey)
        .collect();
    let entries = client.validator_indices(&pubkeys).await.unwrap();
    assert_eq!(entries.len(), COUNT);
    let indices: Vec<u64> = entries.iter().map(|entry| entry.index).collect();

    let proposers = client.proposer_duties(epoch).await.unwrap();
    assert_eq!(proposers.duties.len(), preset::SLOTS_PER_EPOCH as usize);

    let attesters = client.attester_duties(epoch, &indices).await.unwrap();
    assert_eq!(
        attesters.duties.len(),
        COUNT,
        "everyone attests once per epoch"
    );

    let subscriptions: Vec<CommitteeSubscriptionDto> = attesters
        .duties
        .iter()
        .map(|duty| CommitteeSubscriptionDto {
            validator_index: duty.validator_index,
            committee_index: duty.committee_index,
            committees_at_slot: duty.committees_at_slot,
            slot: duty.slot,
            is_aggregator: false,
        })
        .collect();
    client.subscribe_committees(&subscriptions).await.unwrap();
    let preparation = ProposerPreparationDto {
        validator_index: 0,
        fee_recipient: format!("0x{}", "de".repeat(20)),
    };
    client
        .prepare_beacon_proposer(&[preparation])
        .await
        .unwrap();

    // The attestation data is checked by the client itself before it signs.
    let data = client.attestation_data(slot).await.unwrap();
    let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(data.target.epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    let data_dto = AttestationDataOutDto::from(&data);
    let attestations: Vec<SingleAttestationDto> = attesters
        .duties
        .iter()
        .filter(|duty| duty.slot == slot)
        .map(|duty| SingleAttestationDto {
            committee_index: duty.committee_index,
            attester_index: duty.validator_index,
            data: data_dto.clone(),
            signature: encode_hex(&sign_for(duty.validator_index as usize, signing_root).0),
        })
        .collect();
    assert!(!attestations.is_empty(), "someone attests at the head slot");

    let accepted = client
        .submit_attestations(&attestations, "fulu")
        .await
        .unwrap();
    assert_eq!(accepted, attestations.len());
    assert_eq!(network.published.lock().unwrap().len(), attestations.len());
}

/// Block production is not served, and the client sees a node failure it can
/// fail over on, not a malformed answer.
#[tokio::test]
async fn block_production_is_refused_as_a_node_failure() {
    let (client, state, _) = serve().await;
    let request = BlockRequest {
        slot: state.slot() + 1,
        proposer_index: 0,
        randao_reveal: Default::default(),
        graffiti: Default::default(),
    };
    let err = client.produce_block(&request).await.unwrap_err();
    assert!(
        matches!(err, Error::BeaconNodeStatus { status: 501, .. }),
        "got {err:?}"
    );
    assert!(err.is_retryable());
}
