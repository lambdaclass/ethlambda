//! Gloas's type-specific SSZ bounds (EIP-7688, `gloas/p2p-interface.md`).
//!
//! A message's uncompressed size must not exceed `MAX_PAYLOAD_SIZE` or its
//! type's largest encoding, whichever is lower (phase0's gossip and req/resp
//! rules). Before gloas every list a message holds carries a limit, so the
//! SSZ decoder enforces the second bound on its own. Gloas makes the lists of
//! four messages progressive, which have no limit, so the specification gives
//! their bounds as numbers instead: three preset values and
//! `compute_max_data_column_sidecar_size`. They are checked here against the
//! length snappy declares, before anything is decompressed or decoded.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::gloas;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::KZG_POINT_SIZE;
use libssz::SszEncode as _;

use crate::beacon::topics;

/// The most bytes a gossip payload on a topic of `kind` may decompress to
/// under `fork`, when its type sets a bound below `MAX_PAYLOAD_SIZE` that its
/// decoder does not enforce. `None` leaves only `MAX_PAYLOAD_SIZE`: every
/// topic before gloas, and every gloas topic whose type the specification
/// gives no bound for.
pub(crate) fn gossip_payload_bound(fork: ForkName, kind: &str, config: &Config) -> Option<usize> {
    if fork < ForkName::Gloas || fork == ForkName::Lean {
        return None;
    }
    match kind {
        topics::BEACON_AGGREGATE_AND_PROOF => Some(preset::max_signed_aggregate_and_proof_size()),
        topics::ATTESTER_SLASHING => Some(preset::max_attester_slashing_size()),
        topics::EXECUTION_PAYLOAD_BID => Some(preset::MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE),
        kind if topics::data_column_subnet(kind).is_some() => {
            Some(max_data_column_sidecar_size(config))
        }
        _ => None,
    }
}

/// `compute_max_data_column_sidecar_size`: the encoding of a gloas sidecar
/// holding a cell and a proof for each of the most blobs any block may carry,
/// under `MAX_BLOBS_PER_BLOCK_ELECTRA` or any blob schedule entry, whichever is
/// largest, whether or not that entry is in force yet.
///
/// Computed from the empty sidecar's length rather than by encoding a full one,
/// since a gossip column asks for it: cells and proofs are fixed-size, so each
/// blob adds one of each to the empty encoding.
pub(crate) fn max_data_column_sidecar_size(config: &Config) -> usize {
    let max_blobs = config
        .blob_schedule
        .iter()
        .map(|entry| entry.max_blobs_per_block)
        .fold(config.max_blobs_per_block_electra, u64::max);
    let max_blobs = usize::try_from(max_blobs).unwrap_or(usize::MAX);
    let empty = gloas::DataColumnSidecar::default().to_ssz().len();
    max_blobs
        .saturating_mul(preset::BYTES_PER_CELL + KZG_POINT_SIZE)
        .saturating_add(empty)
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::config::BlobScheduleEntry;
    use ethlambda_types::beacon::containers::fulu::Cell;
    use ethlambda_types::beacon::primitives::KzgProof;

    use super::*;

    #[test]
    fn the_column_bound_is_the_largest_sidecars_encoding() {
        let mut config = Config::mainnet();
        let schedule = vec![
            BlobScheduleEntry {
                epoch: 1,
                max_blobs_per_block: 15,
            },
            BlobScheduleEntry {
                epoch: 2,
                max_blobs_per_block: 21,
            },
        ];
        config.blob_schedule = schedule.try_into().expect("two entries fit");
        let cell = Cell::try_from(vec![0u8; preset::BYTES_PER_CELL]).expect("one cell's bytes");
        let largest = gloas::DataColumnSidecar {
            column: vec![cell; 21].into(),
            kzg_proofs: vec![KzgProof([0; KZG_POINT_SIZE]); 21].into(),
            ..Default::default()
        };
        assert_eq!(
            max_data_column_sidecar_size(&config),
            largest.to_ssz().len()
        );
    }

    #[test]
    fn an_empty_schedule_falls_back_to_electras_blob_limit() {
        let mut config = Config::mainnet();
        config.blob_schedule = Vec::new().try_into().expect("empty fits");
        let empty = gloas::DataColumnSidecar::default().to_ssz().len();
        let per_blob = preset::BYTES_PER_CELL + KZG_POINT_SIZE;
        assert_eq!(
            max_data_column_sidecar_size(&config),
            empty + per_blob * config.max_blobs_per_block_electra as usize
        );
    }

    #[test]
    fn only_gloas_topics_carry_a_bound() {
        let config = Config::mainnet();
        let column = "data_column_sidecar_3".to_string();
        for fork in [ForkName::Electra, ForkName::Fulu] {
            for kind in [
                topics::BEACON_AGGREGATE_AND_PROOF,
                topics::ATTESTER_SLASHING,
                column.as_str(),
            ] {
                assert_eq!(gossip_payload_bound(fork, kind, &config), None);
            }
        }
        let bound = |kind| gossip_payload_bound(ForkName::Gloas, kind, &config);
        assert_eq!(
            bound(topics::ATTESTER_SLASHING),
            Some(preset::max_attester_slashing_size())
        );
        assert_eq!(
            bound(topics::BEACON_AGGREGATE_AND_PROOF),
            Some(preset::max_signed_aggregate_and_proof_size())
        );
        assert_eq!(
            bound(topics::EXECUTION_PAYLOAD_BID),
            Some(preset::MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE)
        );
        assert_eq!(
            bound(column.as_str()),
            Some(max_data_column_sidecar_size(&config))
        );
        assert_eq!(bound(topics::BEACON_BLOCK), None);
        assert_eq!(bound(topics::VOLUNTARY_EXIT), None);
    }
}
