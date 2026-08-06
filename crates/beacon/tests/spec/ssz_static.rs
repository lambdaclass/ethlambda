//! The `ssz_static` runner.
//!
//! For each case: decode `serialized.ssz_snappy`, check its `hash_tree_root`
//! against `roots.yaml`, and check that re-encoding reproduces the fixture's
//! bytes exactly. That covers all three of the things a container has to get
//! right, and the round trip catches a field that decodes but encodes back
//! differently, which a root check alone can miss.
//!
//! The case's `value.yaml` is deliberately unused. Reading it would mean a serde
//! implementation for every container, and it tests nothing the other two files
//! do not already pin down.
//!
//! Containers this crate has not defined yet are counted and reported rather
//! than passed over quietly, so the output never implies more coverage than
//! there is. `LightClient*` is a special case within that bucket: this crate
//! deliberately does not implement it, so those pairs are counted separately
//! from a genuine gap rather than folded into the same count.

use std::collections::BTreeSet;

use ethlambda_beacon::ForkName;
use ethlambda_beacon::containers::{
    altair, bellatrix, capella, deneb, electra, fulu, phase0, shared,
};
use ethlambda_beacon::primitives::{HashTreeRoot, Root};
use libssz::{SszDecode, SszEncode};

use super::{Case, PRESET, Report, collect_all_handlers};

/// Decodes a case, then checks its root and its re-encoding.
fn check<T>(case: &Case) -> Result<(), String>
where
    T: SszDecode + SszEncode + HashTreeRoot,
{
    let bytes = case.ssz_bytes("serialized");

    let value = T::from_ssz_bytes(&bytes).map_err(|err| format!("decode failed: {err:?}"))?;

    let expected: RootFile = case.yaml("roots");
    let expected_root: Root = parse_root(&expected.root);
    // Disambiguated because the generic bound brings both this crate's
    // convenience trait and libssz's underlying one into scope.
    let actual = HashTreeRoot::hash_tree_root(&value);
    if actual != expected_root {
        return Err(format!(
            "hash_tree_root 0x{} != expected {}",
            hex::encode(actual.0),
            expected.root
        ));
    }

    let reencoded = value.to_ssz();
    if reencoded != bytes {
        return Err(format!(
            "re-encoding produced {} bytes, fixture has {}",
            reencoded.len(),
            bytes.len()
        ));
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct RootFile {
    root: String,
}

fn parse_root(hex_root: &str) -> Root {
    let stripped = hex_root.strip_prefix("0x").unwrap_or(hex_root);
    let bytes = hex::decode(stripped).expect("roots.yaml holds a hex string");
    Root::from_slice(&bytes)
}

#[test]
fn ssz_static() {
    let mut report = Report::new();
    let mut unimplemented: BTreeSet<String> = BTreeSet::new();
    let mut light_client: BTreeSet<String> = BTreeSet::new();

    for (handler, case) in collect_all_handlers(PRESET, "ssz_static") {
        let fork = case.fork;

        // The fork-invariant containers are checked against every fork's cases,
        // since a container that does not change shape should decode identically
        // under all of them. That is coverage for free, and it would catch a
        // container wrongly believed to be fork-invariant.
        let outcome = match handler.as_str() {
            "Fork" => check::<shared::Fork>(&case),
            "ForkData" => check::<shared::ForkData>(&case),
            "Checkpoint" => check::<shared::Checkpoint>(&case),
            "Validator" => check::<shared::Validator>(&case),
            "AttestationData" => check::<shared::AttestationData>(&case),
            "Eth1Data" => check::<shared::Eth1Data>(&case),
            "Eth1Block" => check::<shared::Eth1Block>(&case),
            "DepositMessage" => check::<shared::DepositMessage>(&case),
            "DepositData" => check::<shared::DepositData>(&case),
            "Deposit" => check::<shared::Deposit>(&case),
            "SigningData" => check::<shared::SigningData>(&case),
            "HistoricalBatch" => check::<shared::HistoricalBatch>(&case),
            "HistoricalSummary" => check::<shared::HistoricalSummary>(&case),
            "BeaconBlockHeader" => check::<shared::BeaconBlockHeader>(&case),
            "SignedBeaconBlockHeader" => check::<shared::SignedBeaconBlockHeader>(&case),
            "ProposerSlashing" => check::<shared::ProposerSlashing>(&case),
            "VoluntaryExit" => check::<shared::VoluntaryExit>(&case),
            "SignedVoluntaryExit" => check::<shared::SignedVoluntaryExit>(&case),

            // Electra reshapes the attestation containers, widening the
            // aggregation bits and attesting indices from one committee to a
            // whole slot's worth, so phase0's definitions hold only through
            // deneb, and electra's take over from electra on. Fulu makes no
            // further change here, so electra's types cover it too.
            "Attestation" if fork <= ForkName::Deneb => check::<phase0::Attestation>(&case),
            "Attestation" if fork >= ForkName::Electra => check::<electra::Attestation>(&case),
            "IndexedAttestation" if fork <= ForkName::Deneb => {
                check::<phase0::IndexedAttestation>(&case)
            }
            "IndexedAttestation" if fork >= ForkName::Electra => {
                check::<electra::IndexedAttestation>(&case)
            }
            "AttesterSlashing" if fork <= ForkName::Deneb => {
                check::<phase0::AttesterSlashing>(&case)
            }
            "AttesterSlashing" if fork >= ForkName::Electra => {
                check::<electra::AttesterSlashing>(&case)
            }
            "AggregateAndProof" if fork <= ForkName::Deneb => {
                check::<phase0::AggregateAndProof>(&case)
            }
            "AggregateAndProof" if fork >= ForkName::Electra => {
                check::<electra::AggregateAndProof>(&case)
            }
            "SignedAggregateAndProof" if fork <= ForkName::Deneb => {
                check::<phase0::SignedAggregateAndProof>(&case)
            }
            "SignedAggregateAndProof" if fork >= ForkName::Electra => {
                check::<electra::SignedAggregateAndProof>(&case)
            }
            // Pre-electra, a lone attester's unaggregated vote reused
            // Attestation itself with one bit set, since aggregation_bits was
            // already scoped to a single committee. Electra's
            // aggregation_bits spans a whole slot, so a lone bit no longer
            // says which committee it belongs to, and SingleAttestation
            // exists to carry that index explicitly instead.
            "SingleAttestation" if fork >= ForkName::Electra => {
                check::<electra::SingleAttestation>(&case)
            }
            // The fixtures ship this for every fork even though no state
            // after phase0 holds one; that is upstream's choice, and checking
            // it costs nothing.
            "PendingAttestation" => check::<phase0::PendingAttestation>(&case),

            // The state changes shape in almost every fork, so it gets one
            // arm per fork rather than a range, unlike the block family
            // below.
            "BeaconState" if fork == ForkName::Phase0 => check::<phase0::BeaconState>(&case),
            "BeaconState" if fork == ForkName::Altair => check::<altair::BeaconState>(&case),
            "BeaconState" if fork == ForkName::Bellatrix => check::<bellatrix::BeaconState>(&case),
            "BeaconState" if fork == ForkName::Capella => check::<capella::BeaconState>(&case),
            "BeaconState" if fork == ForkName::Deneb => check::<deneb::BeaconState>(&case),
            "BeaconState" if fork == ForkName::Electra => check::<electra::BeaconState>(&case),
            // Fulu appends proposer_lookahead to electra's state, so unlike
            // the block family below it needs its own type here.
            "BeaconState" if fork == ForkName::Fulu => check::<fulu::BeaconState>(&case),

            "BeaconBlock" if fork == ForkName::Phase0 => check::<phase0::BeaconBlock>(&case),
            "BeaconBlockBody" if fork == ForkName::Phase0 => {
                check::<phase0::BeaconBlockBody>(&case)
            }
            "SignedBeaconBlock" if fork == ForkName::Phase0 => {
                check::<phase0::SignedBeaconBlock>(&case)
            }

            "BeaconBlock" if fork == ForkName::Altair => check::<altair::BeaconBlock>(&case),
            "BeaconBlockBody" if fork == ForkName::Altair => {
                check::<altair::BeaconBlockBody>(&case)
            }
            "SignedBeaconBlock" if fork == ForkName::Altair => {
                check::<altair::SignedBeaconBlock>(&case)
            }

            "BeaconBlock" if fork == ForkName::Bellatrix => check::<bellatrix::BeaconBlock>(&case),
            "BeaconBlockBody" if fork == ForkName::Bellatrix => {
                check::<bellatrix::BeaconBlockBody>(&case)
            }
            "SignedBeaconBlock" if fork == ForkName::Bellatrix => {
                check::<bellatrix::SignedBeaconBlock>(&case)
            }

            "BeaconBlock" if fork == ForkName::Capella => check::<capella::BeaconBlock>(&case),
            "BeaconBlockBody" if fork == ForkName::Capella => {
                check::<capella::BeaconBlockBody>(&case)
            }
            "SignedBeaconBlock" if fork == ForkName::Capella => {
                check::<capella::SignedBeaconBlock>(&case)
            }

            "BeaconBlock" if fork == ForkName::Deneb => check::<deneb::BeaconBlock>(&case),
            "BeaconBlockBody" if fork == ForkName::Deneb => check::<deneb::BeaconBlockBody>(&case),
            "SignedBeaconBlock" if fork == ForkName::Deneb => {
                check::<deneb::SignedBeaconBlock>(&case)
            }

            // Fulu does not change the block's shape: its body still carries
            // exactly the execution_payload and execution_requests electra's
            // does, so there is no fulu::BeaconBlock, fulu::BeaconBlockBody,
            // or fulu::SignedBeaconBlock to define. Electra's types are
            // checked against both forks' cases instead of being duplicated,
            // which is the same reasoning that lets the sync committee
            // containers below use one type across many forks.
            "BeaconBlock" if fork >= ForkName::Electra => check::<electra::BeaconBlock>(&case),
            "BeaconBlockBody" if fork >= ForkName::Electra => {
                check::<electra::BeaconBlockBody>(&case)
            }
            "SignedBeaconBlock" if fork >= ForkName::Electra => {
                check::<electra::SignedBeaconBlock>(&case)
            }

            // The sync committee containers arrive in altair and, unlike the
            // state, do not change shape again, so they are checked against every
            // fork from altair on.
            "SyncCommittee" if fork >= ForkName::Altair => check::<altair::SyncCommittee>(&case),
            "SyncAggregate" if fork >= ForkName::Altair => check::<altair::SyncAggregate>(&case),
            "SyncCommitteeMessage" if fork >= ForkName::Altair => {
                check::<altair::SyncCommitteeMessage>(&case)
            }
            "SyncCommitteeContribution" if fork >= ForkName::Altair => {
                check::<altair::SyncCommitteeContribution>(&case)
            }
            "ContributionAndProof" if fork >= ForkName::Altair => {
                check::<altair::ContributionAndProof>(&case)
            }
            "SignedContributionAndProof" if fork >= ForkName::Altair => {
                check::<altair::SignedContributionAndProof>(&case)
            }
            "SyncAggregatorSelectionData" if fork >= ForkName::Altair => {
                check::<altair::SyncAggregatorSelectionData>(&case)
            }

            // The execution payload pair changes shape at bellatrix, capella,
            // and deneb, then holds steady: neither electra nor fulu touches
            // it, since their own changes land elsewhere (the attestation and
            // pending-queue containers above, and fulu's proposer lookahead),
            // so deneb's definitions cover deneb, electra, and fulu alike.
            "ExecutionPayload" if fork == ForkName::Bellatrix => {
                check::<bellatrix::ExecutionPayload>(&case)
            }
            "ExecutionPayloadHeader" if fork == ForkName::Bellatrix => {
                check::<bellatrix::ExecutionPayloadHeader>(&case)
            }
            "ExecutionPayload" if fork == ForkName::Capella => {
                check::<capella::ExecutionPayload>(&case)
            }
            "ExecutionPayloadHeader" if fork == ForkName::Capella => {
                check::<capella::ExecutionPayloadHeader>(&case)
            }
            "ExecutionPayload" if fork >= ForkName::Deneb => {
                check::<deneb::ExecutionPayload>(&case)
            }
            "ExecutionPayloadHeader" if fork >= ForkName::Deneb => {
                check::<deneb::ExecutionPayloadHeader>(&case)
            }

            // Transcribed from fork-choice.md rather than beacon-chain.md, and
            // unchanged since the merge introduced it, so one type covers
            // every fork that carries it.
            "PowBlock" if fork >= ForkName::Bellatrix => check::<bellatrix::PowBlock>(&case),

            // The withdrawal machinery arrives in capella and does not change
            // shape again through fulu.
            "Withdrawal" if fork >= ForkName::Capella => check::<capella::Withdrawal>(&case),
            "BLSToExecutionChange" if fork >= ForkName::Capella => {
                check::<capella::BLSToExecutionChange>(&case)
            }
            "SignedBLSToExecutionChange" if fork >= ForkName::Capella => {
                check::<capella::SignedBLSToExecutionChange>(&case)
            }

            // Blob wire types arrive in deneb and are unchanged by fulu's data
            // column sampling: sampling changes how the data behind a blob's
            // commitment travels over the network, not the blob sidecar or
            // identifier themselves, so both keep deneb's shape through fulu.
            "BlobIdentifier" if fork >= ForkName::Deneb => check::<deneb::BlobIdentifier>(&case),
            "BlobSidecar" if fork >= ForkName::Deneb => check::<deneb::BlobSidecar>(&case),

            // Electra's balance-churn queues and execution-layer-triggered
            // requests are unchanged by fulu, so one set of types covers both.
            "DepositRequest" if fork >= ForkName::Electra => {
                check::<electra::DepositRequest>(&case)
            }
            "WithdrawalRequest" if fork >= ForkName::Electra => {
                check::<electra::WithdrawalRequest>(&case)
            }
            "ConsolidationRequest" if fork >= ForkName::Electra => {
                check::<electra::ConsolidationRequest>(&case)
            }
            "ExecutionRequests" if fork >= ForkName::Electra => {
                check::<electra::ExecutionRequests>(&case)
            }
            "PendingDeposit" if fork >= ForkName::Electra => {
                check::<electra::PendingDeposit>(&case)
            }
            "PendingPartialWithdrawal" if fork >= ForkName::Electra => {
                check::<electra::PendingPartialWithdrawal>(&case)
            }
            "PendingConsolidation" if fork >= ForkName::Electra => {
                check::<electra::PendingConsolidation>(&case)
            }

            // Data availability sampling is fulu-only: no earlier fork has
            // these containers at all.
            "DataColumnSidecar" if fork == ForkName::Fulu => {
                check::<fulu::DataColumnSidecar>(&case)
            }
            "MatrixEntry" if fork == ForkName::Fulu => check::<fulu::MatrixEntry>(&case),
            "DataColumnsByRootIdentifier" if fork == ForkName::Fulu => {
                check::<fulu::DataColumnsByRootIdentifier>(&case)
            }

            _ => {
                // LightClient* is deliberately out of scope for this crate,
                // so it is tracked apart from any other handler that falls
                // through here: a nonempty light_client set is expected, but
                // a nonempty unimplemented set means some handler this crate
                // should cover has gone unmapped.
                if handler.starts_with("LightClient") {
                    light_client.insert(format!("{fork}/{handler}"));
                } else {
                    unimplemented.insert(format!("{fork}/{handler}"));
                }
                continue;
            }
        };

        report.record(&case, outcome);
    }

    if !light_client.is_empty() {
        println!(
            "ssz_static: {} LightClient* container/fork pairs skipped, out of \
             scope for this crate:\n  {}",
            light_client.len(),
            light_client
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    if !unimplemented.is_empty() {
        println!(
            "ssz_static: {} container/fork pairs not implemented yet:\n  {}",
            unimplemented.len(),
            unimplemented
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n  ")
        );
    }

    report.finish("ssz_static");
}
