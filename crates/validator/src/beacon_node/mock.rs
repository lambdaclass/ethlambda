//! A `BeaconNodeApi` that answers from values a test sets, used by the duty
//! service tests. Compiled only under `cfg(test)`.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::electra::{Attestation, SignedAggregateAndProof};
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::containers::shared::Checkpoint;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot, ValidatorIndex};

use crate::beacon_node::block_contents::{Contents, ProducedBlock, empty_block_for};
use crate::beacon_node::dto::{
    AttesterDutyDto, CommitteeSubscriptionDto, ProposerDutyDto, ProposerPreparationDto,
    SingleAttestationDto,
};
use crate::beacon_node::{
    AggregateAttestation, AttesterDuties, BeaconNodeApi, BlockRequest, Genesis, ProposerDuties,
    Published, ValidatorEntry,
};
use crate::error::{BeaconNodeFailure, Error, Result};

/// A `BeaconNodeApi` driven entirely by fields and methods a test controls,
/// rather than by a network or a real beacon node.
#[derive(Default)]
pub struct MockBeaconNode {
    /// Failures keyed by method name, plus an optional catch-all.
    ///
    /// Per-method rather than blanket because the scenarios worth testing are
    /// partial: a node that answers `genesis` and `spec` at startup and then
    /// fails `attester_duties` every epoch is a real and common shape, and a
    /// single flag cannot express it.
    pub failures: Mutex<HashMap<&'static str, String>>,
    /// When set, every method fails with this message, regardless of `failures`.
    pub fail_everything: Option<String>,
    pub genesis: Option<Genesis>,
    pub syncing: bool,
    /// Tracking a head its execution client has not validated. Separate from
    /// `syncing`, because the pair a real node can report and this client must
    /// still refuse is exactly "synced, but optimistic".
    pub optimistic: bool,
    pub validators: Vec<ValidatorEntry>,
    pub duties: Mutex<Vec<(Epoch, AttesterDuties)>>,
    pub proposers: Mutex<Vec<(Epoch, ProposerDuties)>>,
    pub attestation_data: Option<AttestationData>,
    /// The slot and proposer the mock will produce a block for. `None` makes
    /// `produce_block` fail, the way an unset `attestation_data` does.
    pub produces_block: Option<(Slot, ValidatorIndex)>,
    /// What `publish_block` reports. Defaults to `Imported`; a test that cares
    /// about the 202 path sets it.
    pub publish_outcome: Option<Published>,

    /// What the test asserts against.
    pub submitted: Mutex<Vec<SingleAttestationDto>>,
    /// The `fork_name` argument `submit_attestations` was called with, in
    /// call order; parallel to `submitted` batch-for-batch.
    pub submitted_fork_names: Mutex<Vec<String>>,
    pub subscriptions: Mutex<Vec<CommitteeSubscriptionDto>>,
    pub preparations: Mutex<Vec<ProposerPreparationDto>>,
    /// Every published block body, with the fork named alongside it.
    pub published_blocks: Mutex<Vec<(ForkName, Vec<u8>)>>,
    /// Every `produce_block` request, in call order.
    pub block_requests: Mutex<Vec<BlockRequest>>,
    /// Every `aggregate_attestation` request, as (slot, data root, committee).
    pub aggregate_requests: Mutex<Vec<(Slot, Root, u64)>>,
    /// Every published aggregate body, with the fork named alongside it.
    pub published_aggregates: Mutex<Vec<(ForkName, Vec<SignedAggregateAndProof>)>>,
    /// When set, `aggregate_attestation` answers with an aggregate over this
    /// data. `None` makes it fail the way a node with nothing to fold does.
    pub aggregate: Option<AttestationData>,
    pub duties_calls: Mutex<usize>,
    pub validator_indices_calls: Mutex<usize>,
    pub proposer_duties_calls: Mutex<usize>,
    pub attestation_data_calls: Mutex<usize>,
}

impl MockBeaconNode {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fails every call with `message`. For a test that only cares whether the
    /// node is up, not which call it made; failover tests use this.
    pub fn failing(message: &str) -> Self {
        Self {
            fail_everything: Some(message.to_string()),
            ..Self::default()
        }
    }

    /// Fails only the named method (its `BeaconNodeApi` name, e.g.
    /// `"attester_duties"`) with `message`; every other call succeeds
    /// normally. This is what makes "the node is up but its duties poll is
    /// failing" expressible.
    pub fn failing_call(self, what: &'static str, message: &str) -> Self {
        self.failures
            .lock()
            .expect("lock")
            .insert(what, message.to_string());
        self
    }

    pub fn with_duties(
        self,
        epoch: Epoch,
        dependent_root: Root,
        duties: Vec<AttesterDutyDto>,
    ) -> Self {
        self.duties.lock().expect("lock").push((
            epoch,
            AttesterDuties {
                dependent_root,
                duties,
            },
        ));
        self
    }

    /// Replace the duties stored for `epoch`.
    ///
    /// Distinct from `with_duties`, which appends at construction: a reorg is
    /// the same epoch answering differently on a later call, so a test needs
    /// to overwrite between calls without knowing how they are stored.
    pub fn set_duties(&self, epoch: Epoch, dependent_root: Root, duties: Vec<AttesterDutyDto>) {
        let mut stored = self.duties.lock().expect("lock");
        let entry = AttesterDuties {
            dependent_root,
            duties,
        };
        match stored
            .iter_mut()
            .find(|(stored_epoch, _)| *stored_epoch == epoch)
        {
            Some((_, existing)) => *existing = entry,
            None => stored.push((epoch, entry)),
        }
    }

    pub fn with_proposers(
        self,
        epoch: Epoch,
        dependent_root: Root,
        duties: Vec<ProposerDutyDto>,
    ) -> Self {
        self.proposers.lock().expect("lock").push((
            epoch,
            ProposerDuties {
                dependent_root,
                duties,
            },
        ));
        self
    }

    /// Replace the proposer duties stored for `epoch`, the way `set_duties`
    /// replaces the attester ones: a reorg is the same epoch answering
    /// differently on a later call.
    pub fn set_proposers(&self, epoch: Epoch, dependent_root: Root, duties: Vec<ProposerDutyDto>) {
        let mut stored = self.proposers.lock().expect("lock");
        let entry = ProposerDuties {
            dependent_root,
            duties,
        };
        match stored
            .iter_mut()
            .find(|(stored_epoch, _)| *stored_epoch == epoch)
        {
            Some((_, existing)) => *existing = entry,
            None => stored.push((epoch, entry)),
        }
    }

    pub fn with_attestation_data(mut self, slot: Slot) -> Self {
        self.attestation_data = Some(AttestationData {
            slot,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: Checkpoint {
                epoch: 0,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: slot / 32,
                root: Root::ZERO,
            },
        });
        self
    }

    /// Answer `produce_block` with a minimal well-formed electra block for
    /// `slot`, proposed by `proposer_index`.
    ///
    /// The same fixture `block_contents`' own tests decode, rather than a
    /// second one: a mock that built its block differently would let a decoding
    /// bug pass here and fail in production.
    pub fn with_block(mut self, slot: Slot, proposer_index: ValidatorIndex) -> Self {
        self.produces_block = Some((slot, proposer_index));
        self
    }

    pub fn with_publish_outcome(mut self, outcome: Published) -> Self {
        self.publish_outcome = Some(outcome);
        self
    }

    /// Every block body published so far, with its fork, in publication order.
    pub fn published_blocks(&self) -> Vec<(ForkName, Vec<u8>)> {
        self.published_blocks.lock().expect("lock").clone()
    }

    /// Every block this mock was asked to produce, in call order. What a test
    /// asserts the randao reveal and graffiti against, since the mock builds
    /// its own block rather than echoing the request back.
    pub fn block_requests(&self) -> Vec<BlockRequest> {
        self.block_requests.lock().expect("lock").clone()
    }

    /// Answer `aggregate_attestation` with an aggregate over `data`.
    pub fn with_aggregate(mut self, data: AttestationData) -> Self {
        self.aggregate = Some(data);
        self
    }

    /// Every aggregate this mock was asked for, as (slot, data root,
    /// committee index), in call order.
    pub fn aggregate_requests(&self) -> Vec<(Slot, Root, u64)> {
        self.aggregate_requests.lock().expect("lock").clone()
    }

    /// Every aggregate body published so far, with its fork.
    pub fn published_aggregates(&self) -> Vec<(ForkName, Vec<SignedAggregateAndProof>)> {
        self.published_aggregates.lock().expect("lock").clone()
    }

    /// Stop failing the named method, so one node can fail a call and then
    /// answer it. A test that needs "failed once, worked next time" cannot get
    /// it from `failing_call` alone, which is fixed at construction.
    pub fn stop_failing(&self, what: &'static str) {
        self.failures.lock().expect("lock").remove(what);
    }

    /// The attestations submitted so far, in submission order.
    pub fn submitted(&self) -> Vec<SingleAttestationDto> {
        self.submitted.lock().expect("lock").clone()
    }

    /// The `fork_name` of the most recent `submit_attestations` call.
    pub fn last_submitted_fork_name(&self) -> Option<String> {
        self.submitted_fork_names
            .lock()
            .expect("lock")
            .last()
            .cloned()
    }

    /// The committee subscriptions submitted so far, in submission order.
    pub fn subscriptions(&self) -> Vec<CommitteeSubscriptionDto> {
        self.subscriptions.lock().expect("lock").clone()
    }

    /// The proposer preparations submitted so far, in submission order.
    pub fn preparations(&self) -> Vec<ProposerPreparationDto> {
        self.preparations.lock().expect("lock").clone()
    }

    /// How many times `attester_duties` has been called, successes and
    /// failures alike.
    pub fn duties_call_count(&self) -> usize {
        *self.duties_calls.lock().expect("lock")
    }

    /// How many times `validator_indices` has been called, successes and
    /// failures alike.
    pub fn validator_indices_call_count(&self) -> usize {
        *self.validator_indices_calls.lock().expect("lock")
    }

    /// How many times `proposer_duties` has been called, successes and
    /// failures alike.
    pub fn proposer_duties_call_count(&self) -> usize {
        *self.proposer_duties_calls.lock().expect("lock")
    }

    /// How many times `attestation_data` has been called, successes and
    /// failures alike.
    pub fn attestation_data_call_count(&self) -> usize {
        *self.attestation_data_calls.lock().expect("lock")
    }

    fn guard(&self, what: &'static str) -> Result<()> {
        if let Some(detail) = self.failures.lock().expect("lock").get(what) {
            return Err(Error::BeaconNode {
                url: "mock".to_string(),
                failure: BeaconNodeFailure::Request,
                detail: detail.clone(),
            });
        }
        if let Some(detail) = &self.fail_everything {
            return Err(Error::BeaconNode {
                url: "mock".to_string(),
                failure: BeaconNodeFailure::Request,
                detail: detail.clone(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl BeaconNodeApi for MockBeaconNode {
    async fn genesis(&self) -> Result<Genesis> {
        self.guard("genesis")?;
        self.genesis.ok_or_else(|| Error::BeaconNode {
            url: "mock".to_string(),
            failure: BeaconNodeFailure::Request,
            detail: "no genesis set".into(),
        })
    }

    async fn spec(&self) -> Result<Config> {
        self.guard("spec")?;
        Ok(Config::mainnet())
    }

    async fn is_optimistic_or_syncing(&self) -> Result<bool> {
        self.guard("is_syncing")?;
        Ok(self.syncing || self.optimistic)
    }

    async fn validator_indices(&self, pubkeys: &[BlsPubkey]) -> Result<Vec<ValidatorEntry>> {
        self.guard("validator_indices")?;
        *self.validator_indices_calls.lock().expect("lock") += 1;
        // Honours the same contract every real implementation does, so a test
        // cannot pass here and ask a live node for the whole registry.
        if pubkeys.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self.validators.clone())
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        _indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        self.guard("attester_duties")?;
        *self.duties_calls.lock().expect("lock") += 1;
        self.duties
            .lock()
            .expect("lock")
            .iter()
            .find(|(stored, _)| *stored == epoch)
            .map(|(_, duties)| duties.clone())
            .ok_or_else(|| Error::BeaconNode {
                url: "mock".to_string(),
                failure: BeaconNodeFailure::Request,
                detail: format!("no duties for epoch {epoch}"),
            })
    }

    async fn proposer_duties(&self, epoch: Epoch) -> Result<ProposerDuties> {
        self.guard("proposer_duties")?;
        *self.proposer_duties_calls.lock().expect("lock") += 1;
        self.proposers
            .lock()
            .expect("lock")
            .iter()
            .find(|(stored, _)| *stored == epoch)
            .map(|(_, duties)| duties.clone())
            .ok_or_else(|| Error::BeaconNode {
                url: "mock".to_string(),
                failure: BeaconNodeFailure::Request,
                detail: format!("no proposer duties for epoch {epoch}"),
            })
    }

    async fn attestation_data(&self, slot: Slot) -> Result<AttestationData> {
        self.guard("attestation_data")?;
        *self.attestation_data_calls.lock().expect("lock") += 1;
        let data = self.attestation_data.ok_or_else(|| Error::BeaconNode {
            url: "mock".to_string(),
            failure: BeaconNodeFailure::Request,
            detail: "no attestation data set".into(),
        })?;
        // The mock honours the same contract every real implementation does
        // (see `BeaconNodeApi::attestation_data`), so a test double configured
        // with data for another slot behaves like a node stuck on a stale
        // head: it errors, and failover moves past it. Without this the mock
        // would be a more permissive node than any real one, and tests built
        // on it would not reflect what happens in production.
        crate::beacon_node::validate_attestation_data(slot, &data)?;
        Ok(data)
    }

    /// Honours the same contract every real implementation does (see
    /// `BeaconNodeApi::produce_block`), so a mock configured for another slot
    /// or another proposer behaves like a node on a stale head: it errors, and
    /// failover moves past it.
    async fn produce_block(&self, request: &BlockRequest) -> Result<ProducedBlock> {
        self.guard("produce_block")?;
        self.block_requests
            .lock()
            .expect("lock")
            .push(request.clone());
        let (slot, proposer_index) = self.produces_block.ok_or_else(|| Error::BeaconNode {
            url: "mock".to_string(),
            failure: BeaconNodeFailure::Request,
            detail: "no block set".into(),
        })?;
        // Electra, matching the block shape `empty_block_for` builds. A test
        // that needs a fork mismatch constructs one itself rather than getting
        // it by accident here.
        let block = ProducedBlock {
            fork: ForkName::Electra,
            contents: Contents::WithBlobProofs {
                block: empty_block_for(slot, proposer_index),
                kzg_proofs: Default::default(),
                blobs: Default::default(),
            },
        };
        crate::beacon_node::validate_produced_block(request, &block)?;
        Ok(block)
    }

    async fn publish_block(&self, fork: ForkName, body: &[u8]) -> Result<Published> {
        self.guard("publish_block")?;
        self.published_blocks
            .lock()
            .expect("lock")
            .push((fork, body.to_vec()));
        Ok(self.publish_outcome.unwrap_or(Published::Imported))
    }

    async fn submit_attestations(
        &self,
        attestations: &[SingleAttestationDto],
        fork_name: &str,
    ) -> Result<usize> {
        self.guard("submit_attestations")?;
        self.submitted
            .lock()
            .expect("lock")
            .extend_from_slice(attestations);
        self.submitted_fork_names
            .lock()
            .expect("lock")
            .push(fork_name.to_string());
        Ok(attestations.len())
    }

    /// Honours the slot contract the real implementation does, so a mock
    /// configured for another slot behaves like a node on a stale head.
    async fn aggregate_attestation(
        &self,
        slot: Slot,
        attestation_data_root: Root,
        committee_index: u64,
    ) -> Result<AggregateAttestation> {
        self.guard("aggregate_attestation")?;
        self.aggregate_requests.lock().expect("lock").push((
            slot,
            attestation_data_root,
            committee_index,
        ));

        let data = self.aggregate.ok_or_else(|| Error::BeaconNodeStatus {
            status: 404,
            body: "no aggregate available".to_string(),
        })?;
        if data.slot != slot {
            return Err(Error::InconsistentResponse(format!(
                "requested an aggregate for slot {slot}, node answered for slot {}",
                data.slot
            )));
        }
        Ok(AggregateAttestation {
            fork: ForkName::Electra,
            attestation: Attestation {
                aggregation_bits: Default::default(),
                data,
                signature: Default::default(),
                committee_bits: Default::default(),
            },
        })
    }

    async fn publish_aggregates(
        &self,
        fork: ForkName,
        aggregates: &[SignedAggregateAndProof],
    ) -> Result<()> {
        self.guard("publish_aggregates")?;
        self.published_aggregates
            .lock()
            .expect("lock")
            .push((fork, aggregates.to_vec()));
        Ok(())
    }

    async fn prepare_beacon_proposer(&self, preparations: &[ProposerPreparationDto]) -> Result<()> {
        self.guard("prepare_beacon_proposer")?;
        self.preparations
            .lock()
            .expect("lock")
            .extend(preparations.iter().cloned());
        Ok(())
    }

    async fn subscribe_committees(&self, subscriptions: &[CommitteeSubscriptionDto]) -> Result<()> {
        self.guard("subscribe_committees")?;
        self.subscriptions
            .lock()
            .expect("lock")
            .extend_from_slice(subscriptions);
        Ok(())
    }
}
