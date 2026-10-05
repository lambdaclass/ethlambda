//! `/eth/v1/config/spec`.
//!
//! The Beacon API asks for three things in one flat object: the network's
//! configuration, the preset the node was built against, and the
//! specification's constants. Validator clients read all three: lighthouse's,
//! for one, refuses a beacon node whose `PRESET_BASE` does not match its own,
//! and an absent key counts as a mismatch.
//!
//! The configuration, `PRESET_BASE` and `CONFIG_NAME` included, comes straight
//! off the `Config` the store was bootstrapped with, so a node started with
//! `--network <dir>` reports that network's values rather than mainnet's.
//! Where the node runs on a compile-time constant rather than reading
//! `Config` (the custody counts, `MAX_REQUEST_BLOCKS`, ...), startup refuses a
//! network whose `Config` differs from the constant, so reporting the
//! `Config`'s value is reporting the one the node uses.
//! `GENESIS_TIME` is absent by design: it is not a `config.yaml` key, and
//! `/eth/v1/beacon/genesis` is where it is reported.
//!
//! The configuration keys include gloas's (`GLOAS_*` and the other gloas
//! timing and churn keys), since `Config` holds them and this serializes the
//! whole of it. The preset and constant keys are the ones lighthouse reports
//! plus gloas's own, from `presets/*/gloas.yaml` and `beacon-chain.md`'s
//! constants (`PTC_SIZE`, `DOMAIN_BEACON_BUILDER`, ...), less keys the
//! specification does not define at all (`GAS_LIMIT_ADJUSTMENT_FACTOR`,
//! `RESP_TIMEOUT`, `TTFB_TIMEOUT`). Constants lighthouse leaves out, such as
//! `JUSTIFICATION_BITS_LENGTH`, are left out here too. Gloas's `MAX_*_SIZE`
//! preset keys bound gossip message sizes, which the node does not run on, so
//! they are left out as well.

use axum::{Router, extract::State, response::Response, routing::get};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{config::Config, constants, preset, serde_helpers::HexPrefixed};
use serde_json::{Map, Value};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/eth/v1/config/spec", get(get_spec))
}

async fn get_spec(State(store): State<Store>) -> Response {
    // Through the `Arc` rather than cloning: `Config` carries a blob of
    // scalars plus the blob schedule, and nothing here needs to own it.
    let data = spec(store.config().as_ref());
    crate::json_response(serde_json::json!({ "data": data }))
}

/// Pairs each named item of `$module` with `$render` of its value, keyed by
/// the item's own name, which is the specification's.
macro_rules! entries {
    ($render:expr; $module:ident: $($name:ident),+ $(,)?) => {
        [$((stringify!($name), ($render)($module::$name))),+]
    };
}

/// The `data` object: `config`'s own keys, then everything else in
/// [`extra_entries`].
fn spec(config: &Config) -> Map<String, Value> {
    let Value::Object(mut data) =
        serde_json::to_value(config).expect("Config serializes to a JSON value")
    else {
        unreachable!("Config serializes as a struct, so as a JSON object");
    };
    data.extend(extra_entries().map(|(key, value)| (key.to_owned(), Value::String(value))));
    data
}

/// Every key the endpoint reports that is not a [`Config`] field: the
/// preset, then the constants.
///
/// A key must not also be a `Config` field, or it would silently replace that
/// field's value; `no_key_is_reported_twice` checks this.
fn extra_entries() -> impl Iterator<Item = (&'static str, String)> {
    // Phase0 through fulu, in the order of `preset.rs`.
    let preset = entries!(decimal; preset:
        MAX_COMMITTEES_PER_SLOT,
        TARGET_COMMITTEE_SIZE,
        MAX_VALIDATORS_PER_COMMITTEE,
        SHUFFLE_ROUND_COUNT,
        HYSTERESIS_QUOTIENT,
        HYSTERESIS_DOWNWARD_MULTIPLIER,
        HYSTERESIS_UPWARD_MULTIPLIER,
        MIN_DEPOSIT_AMOUNT,
        MAX_EFFECTIVE_BALANCE,
        EFFECTIVE_BALANCE_INCREMENT,
        MIN_ATTESTATION_INCLUSION_DELAY,
        SLOTS_PER_EPOCH,
        MIN_SEED_LOOKAHEAD,
        MAX_SEED_LOOKAHEAD,
        EPOCHS_PER_ETH1_VOTING_PERIOD,
        SLOTS_PER_HISTORICAL_ROOT,
        MIN_EPOCHS_TO_INACTIVITY_PENALTY,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        HISTORICAL_ROOTS_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        BASE_REWARD_FACTOR,
        WHISTLEBLOWER_REWARD_QUOTIENT,
        PROPOSER_REWARD_QUOTIENT,
        INACTIVITY_PENALTY_QUOTIENT,
        MIN_SLASHING_PENALTY_QUOTIENT,
        PROPORTIONAL_SLASHING_MULTIPLIER,
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
        MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
        PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,
        SYNC_COMMITTEE_SIZE,
        EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
        MIN_SYNC_COMMITTEE_PARTICIPANTS,
        UPDATE_TIMEOUT,
        INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
        MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
        PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,
        MAX_BYTES_PER_TRANSACTION,
        MAX_TRANSACTIONS_PER_PAYLOAD,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        MAX_BLS_TO_EXECUTION_CHANGES,
        MAX_WITHDRAWALS_PER_PAYLOAD,
        MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        KZG_COMMITMENT_INCLUSION_PROOF_DEPTH,
        FIELD_ELEMENTS_PER_BLOB,
        MIN_ACTIVATION_BALANCE,
        MAX_EFFECTIVE_BALANCE_ELECTRA,
        MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA,
        WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_ATTESTATIONS_ELECTRA,
        MAX_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
        MAX_PENDING_DEPOSITS_PER_EPOCH,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
        FIELD_ELEMENTS_PER_CELL,
        FIELD_ELEMENTS_PER_EXT_BLOB,
        CELLS_PER_EXT_BLOB,
        NUMBER_OF_COLUMNS,
        // Gloas, in the order of the specification's `presets/*/gloas.yaml`.
        PTC_SIZE,
        MAX_PAYLOAD_ATTESTATIONS,
        MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        MAX_BUILDERS_PER_WITHDRAWALS_SWEEP,
    );

    let domains = entries!(hex_string; constants:
        DOMAIN_BEACON_PROPOSER,
        DOMAIN_BEACON_ATTESTER,
        DOMAIN_RANDAO,
        DOMAIN_DEPOSIT,
        DOMAIN_VOLUNTARY_EXIT,
        DOMAIN_SELECTION_PROOF,
        DOMAIN_AGGREGATE_AND_PROOF,
        DOMAIN_APPLICATION_MASK,
        DOMAIN_SYNC_COMMITTEE,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        DOMAIN_CONTRIBUTION_AND_PROOF,
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        DOMAIN_BEACON_BUILDER,
        DOMAIN_PTC_ATTESTER,
        DOMAIN_PROPOSER_PREFERENCES,
        DOMAIN_BUILDER_DEPOSIT,
    );

    // One-byte constants (withdrawal prefixes and execution request types), so
    // each goes out as a one-byte array would.
    let one_byte_constants = entries!(|prefix: u8| hex_string([prefix]); constants:
        BLS_WITHDRAWAL_PREFIX,
        ETH1_ADDRESS_WITHDRAWAL_PREFIX,
        COMPOUNDING_WITHDRAWAL_PREFIX,
        DEPOSIT_REQUEST_TYPE,
        WITHDRAWAL_REQUEST_TYPE,
        CONSOLIDATION_REQUEST_TYPE,
        BUILDER_WITHDRAWAL_PREFIX,
        BUILDER_DEPOSIT_REQUEST_TYPE,
        BUILDER_EXIT_REQUEST_TYPE,
    );

    // `VERSIONED_HASH_VERSION_KZG` is a `Bytes1` like the withdrawal prefixes,
    // but it goes out as a decimal, which is how lighthouse reports it.
    let other_constants = entries!(decimal; constants:
        TARGET_AGGREGATORS_PER_COMMITTEE,
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
        SYNC_COMMITTEE_SUBNET_COUNT,
        VERSIONED_HASH_VERSION_KZG,
        UNSET_DEPOSIT_REQUESTS_START_INDEX,
        FULL_EXIT_REQUEST_AMOUNT,
        BUILDER_INDEX_FLAG,
        BUILDER_INDEX_SELF_BUILD,
        BUILDER_PAYMENT_THRESHOLD_NUMERATOR,
        BUILDER_PAYMENT_THRESHOLD_DENOMINATOR,
        PAYLOAD_BUILDER_VERSION,
    );

    preset
        .into_iter()
        .chain(domains)
        .chain(one_byte_constants)
        .chain(other_constants)
}

/// A quoted decimal, the Beacon API's encoding for every integer.
fn decimal(value: impl ToString) -> String {
    value.to_string()
}

/// `0x`-prefixed hex, the Beacon API's encoding for every byte string.
fn hex_string(bytes: impl AsRef<[u8]>) -> String {
    HexPrefixed(bytes.as_ref()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_fixture;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    async fn get_spec_json() -> serde_json::Value {
        let fixture = beacon_fixture(64);
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/eth/v1/config/spec")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn the_spec_is_screaming_snake_case_with_quoted_values() {
        let json = get_spec_json().await;

        assert_eq!(json["data"]["SECONDS_PER_SLOT"], "12");
        assert!(
            json["data"]["GENESIS_FORK_VERSION"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert!(json["data"]["DEPOSIT_CHAIN_ID"].is_string());
        // No bare numbers, lists aside: the Beacon API quotes every value.
        for (key, value) in json["data"].as_object().unwrap() {
            assert!(
                value.is_string() || value.is_array(),
                "{key} is {value}, not a string"
            );
        }
    }

    #[tokio::test]
    async fn the_spec_carries_the_preset_and_constants() {
        let json = get_spec_json().await;
        let data = &json["data"];

        // What lighthouse's validator client checks before anything else. The
        // fixture's store is bootstrapped with `Config::mainnet()`.
        assert_eq!(data["PRESET_BASE"], "mainnet");
        assert_eq!(data["CONFIG_NAME"], "mainnet");

        assert_eq!(data["SLOTS_PER_EPOCH"], preset::SLOTS_PER_EPOCH.to_string());
        assert_eq!(data["DOMAIN_BEACON_ATTESTER"], "0x01000000");
        assert_eq!(data["DOMAIN_APPLICATION_MASK"], "0x00000001");
        assert_eq!(data["COMPOUNDING_WITHDRAWAL_PREFIX"], "0x02");
        assert_eq!(data["VERSIONED_HASH_VERSION_KZG"], "1");
        assert_eq!(
            data["UNSET_DEPOSIT_REQUESTS_START_INDEX"],
            "18446744073709551615"
        );
    }

    #[tokio::test]
    async fn the_spec_carries_gloas_preset_and_constant_keys() {
        let json = get_spec_json().await;
        let data = &json["data"];

        assert_eq!(data["PTC_SIZE"], preset::PTC_SIZE.to_string());
        assert_eq!(
            data["MAX_PAYLOAD_ATTESTATIONS"],
            preset::MAX_PAYLOAD_ATTESTATIONS.to_string()
        );
        assert_eq!(
            data["MAX_BUILDERS_PER_WITHDRAWALS_SWEEP"],
            preset::MAX_BUILDERS_PER_WITHDRAWALS_SWEEP.to_string()
        );
        assert_eq!(data["DOMAIN_BEACON_BUILDER"], "0x0b000000");
        assert_eq!(data["DOMAIN_PTC_ATTESTER"], "0x0c000000");
        assert_eq!(data["DOMAIN_PROPOSER_PREFERENCES"], "0x0d000000");
        assert_eq!(data["DOMAIN_BUILDER_DEPOSIT"], "0x0e000000");
        assert_eq!(data["DEPOSIT_REQUEST_TYPE"], "0x00");
        assert_eq!(data["CONSOLIDATION_REQUEST_TYPE"], "0x02");
        assert_eq!(data["BUILDER_WITHDRAWAL_PREFIX"], "0xb0");
        assert_eq!(data["BUILDER_DEPOSIT_REQUEST_TYPE"], "0x03");
        assert_eq!(data["BUILDER_EXIT_REQUEST_TYPE"], "0x04");
        assert_eq!(data["BUILDER_INDEX_SELF_BUILD"], "18446744073709551615");
        assert_eq!(data["BUILDER_INDEX_FLAG"], "1099511627776");
        assert_eq!(
            data["BUILDER_PAYMENT_THRESHOLD_NUMERATOR"],
            constants::BUILDER_PAYMENT_THRESHOLD_NUMERATOR.to_string()
        );
        // A `Config` field, so it comes from the config half of the object.
        assert!(data["MIN_BUILDER_WITHDRAWABILITY_DELAY"].is_string());
    }

    #[test]
    fn no_key_is_reported_twice() {
        let config = Config::mainnet();
        let Value::Object(config_keys) = serde_json::to_value(&config).unwrap() else {
            panic!("Config should serialize as an object");
        };
        let extra: Vec<_> = extra_entries().map(|(key, _)| key).collect();

        for key in &extra {
            assert!(
                !config_keys.contains_key(*key),
                "{key} is both a Config field and an extra entry"
            );
        }
        let distinct: std::collections::HashSet<_> = extra.iter().collect();
        assert_eq!(
            distinct.len(),
            extra.len(),
            "an extra entry is listed twice"
        );
        assert_eq!(spec(&config).len(), config_keys.len() + extra.len());
    }
}
