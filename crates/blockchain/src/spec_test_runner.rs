//! Shared execution primitives for leanSpec fixtures.
//!
//! Both the offline spec-test binaries and Hive's HTTP test driver use these
//! functions so fixture replay cannot drift between the two entry points.

use ethlambda_storage::Store;
use ethlambda_test_fixtures::fork_choice::ForkChoiceStep;
use ethlambda_types::{
    attestation::{
        AggregationBits, HashedAttestationData, SignedAggregatedAttestation, SignedAttestation,
    },
    block::{ByteList512KiB, SingleMessageAggregate},
};

use crate::{MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT, store};

/// Prefix emitted by leanSpec's mocked aggregation prover.
const MOCK_PROOF_PREFIX: &[u8] = b"\x00MOCKED-AGGREGATION-PROOF\x00";

/// Apply one fork-choice fixture step.
///
/// `proofs_are_mocked` is supplied by complete offline vectors through their
/// `proofSetting`. Hive sends individual steps, so `None` detects the mocked
/// prover's sentinel directly from the proof bytes.
pub fn apply_fork_choice_step(
    store: &mut Store,
    step: &ForkChoiceStep,
    proofs_are_mocked: Option<bool>,
) -> Result<(), String> {
    match step.step_type.as_str() {
        "tick" => {
            let genesis_time = store.config().expect("config exists").genesis_time;
            let timestamp_ms = match (step.time, step.interval) {
                (Some(time_s), _) => time_s * 1000,
                (None, Some(interval)) => {
                    genesis_time * 1000 + interval * MILLISECONDS_PER_INTERVAL
                }
                (None, None) => return Err("tick step missing time and interval".to_string()),
            };
            store::on_tick(store, timestamp_ms, step.has_proposal.unwrap_or(false));
            Ok(())
        }
        "block" => {
            let block_data = step
                .block
                .as_ref()
                .ok_or_else(|| "block step missing block data".to_string())?;
            let signed_block = block_data.to_blank_signed_block();
            if step.tick_to_slot {
                let block_time_ms = store.config().expect("config exists").genesis_time * 1000
                    + signed_block.message.slot * MILLISECONDS_PER_SLOT;
                store::on_tick(store, block_time_ms, true);
            }
            store::on_block_without_verification(store, signed_block).map_err(|e| e.to_string())?;

            let block = block_data.to_block();
            let entries = block.body.attestations.iter().map(|att| {
                (
                    HashedAttestationData::new(att.data.clone()),
                    SingleMessageAggregate::empty(att.aggregation_bits.clone()),
                )
            });
            store.insert_known_aggregated_payloads_batch(entries.collect());
            store::update_head(store, false);
            Ok(())
        }
        "attestation" => {
            let att = step
                .attestation
                .as_ref()
                .ok_or_else(|| "attestation step missing data".to_string())?;
            let signed = SignedAttestation {
                validator_id: att
                    .validator_id
                    .ok_or_else(|| "attestation step missing validatorId".to_string())?,
                data: att.data.clone().into(),
                signature: att
                    .signature
                    .clone()
                    .ok_or_else(|| "attestation step missing signature".to_string())?,
            };
            store::on_gossip_attestation(store, &signed, step.is_aggregator.unwrap_or(false))
                .map_err(|e| e.to_string())
        }
        "gossipAggregatedAttestation" => {
            let att = step
                .attestation
                .as_ref()
                .ok_or_else(|| "gossipAggregatedAttestation step missing data".to_string())?;
            let proof = att
                .proof
                .as_ref()
                .ok_or_else(|| "gossipAggregatedAttestation step missing proof".to_string())?;
            let participants: AggregationBits = proof.participants.clone().into();
            let proof_bytes: Vec<u8> = proof.proof.clone().into();
            let is_mocked =
                proofs_are_mocked.unwrap_or_else(|| proof_bytes.starts_with(MOCK_PROOF_PREFIX));
            let proof_data = ByteList512KiB::try_from(proof_bytes)
                .map_err(|err| format!("aggregated proof data too large: {err:?}"))?;
            let aggregated = SignedAggregatedAttestation {
                proof: SingleMessageAggregate::new(participants, proof_data),
                data: att.data.clone().into(),
            };
            if is_mocked {
                store::on_gossip_aggregated_attestation_without_verification(store, aggregated)
                    .map_err(|e| e.to_string())
            } else {
                store::on_gossip_aggregated_attestation(store, aggregated)
                    .map_err(|e| e.to_string())
            }
        }
        "checks" => Ok(()),
        other => Err(format!("unknown step type: {other}")),
    }
}
