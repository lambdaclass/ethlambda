//! `/eth/v1/config/spec` and `/eth/v1/config/deposit_contract`.
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
    Router::new()
        .route("/eth/v1/config/spec", get(get_spec))
        .route("/eth/v1/config/fork_schedule", get(get_fork_schedule))
        .route("/eth/v1/config/deposit_contract", get(get_deposit_contract))
}

/// `GET /eth/v1/config/fork_schedule`: every fork of the node's `Config`
/// that is scheduled, oldest first.
///
/// Validator clients compare this against their own schedule at startup (nimbus
/// refuses a node that cannot answer it).
async fn get_fork_schedule(State(store): State<Store>) -> Response {
    crate::json_response(serde_json::json!({ "data": fork_schedule(store.config().as_ref()) }))
}

/// The `Fork` objects (`previous_version`, `current_version`, `epoch`) for
/// phase0 and every later fork whose epoch is not `FAR_FUTURE_EPOCH`.
///
/// Phase0 is its own predecessor, as in the spec's genesis `Fork`. An
/// unscheduled fork is skipped without breaking the chain: the next scheduled
/// fork's `previous_version` is the last *scheduled* one's version.
fn fork_schedule(config: &Config) -> Vec<Value> {
    let forks = [
        (config.altair_fork_version, config.altair_fork_epoch),
        (config.bellatrix_fork_version, config.bellatrix_fork_epoch),
        (config.capella_fork_version, config.capella_fork_epoch),
        (config.deneb_fork_version, config.deneb_fork_epoch),
        (config.electra_fork_version, config.electra_fork_epoch),
        (config.fulu_fork_version, config.fulu_fork_epoch),
        (config.gloas_fork_version, config.gloas_fork_epoch),
    ];
    let fork = |previous: [u8; 4], current: [u8; 4], epoch: u64| {
        serde_json::json!({
            "previous_version": hex_string(previous),
            "current_version": hex_string(current),
            "epoch": epoch.to_string(),
        })
    };

    let genesis = config.genesis_fork_version;
    let mut schedule = vec![fork(genesis, genesis, 0)];
    let mut previous = genesis;
    for (version, epoch) in forks {
        if epoch == constants::FAR_FUTURE_EPOCH {
            continue;
        }
        schedule.push(fork(previous, version, epoch));
        previous = version;
    }
    schedule
}

/// `GET /eth/v1/config/deposit_contract`: the network's deposit contract, off
/// the same `Config` `/eth/v1/config/spec` reports it from (as
/// `DEPOSIT_CHAIN_ID` and `DEPOSIT_CONTRACT_ADDRESS`).
async fn get_deposit_contract(State(store): State<Store>) -> Response {
    let config = store.config();
    crate::json_response(serde_json::json!({
        "data": {
            "chain_id": config.deposit_chain_id.to_string(),
            "address": HexPrefixed(&config.deposit_contract_address).to_string(),
        }
    }))
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
        get_json("/eth/v1/config/spec").await
    }

    async fn get_json(uri: &str) -> serde_json::Value {
        let fixture = beacon_fixture(64);
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// The fixture's store is bootstrapped with `Config::mainnet()`, whose
    /// deposit contract is the one on Ethereum mainnet.
    #[tokio::test]
    async fn the_deposit_contract_is_mainnets() {
        let json = get_json("/eth/v1/config/deposit_contract").await;
        assert_eq!(json["data"]["chain_id"], "1");
        assert_eq!(
            json["data"]["address"],
            "0x00000000219ab540356cbb839cbe05303d7705fa"
        );
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

    /// What nimbus's validator client (`checkConfig` and
    /// `getConsensusForkConfig`, v26.10.0) reads off the spec before it will
    /// use a node: a missing or differing key marks the node incompatible.
    #[tokio::test]
    async fn the_spec_carries_every_key_nimbus_checks() {
        let json = get_spec_json().await;
        let data = &json["data"];

        let checked = [
            (
                "MAX_VALIDATORS_PER_COMMITTEE",
                preset::MAX_VALIDATORS_PER_COMMITTEE.to_string(),
            ),
            ("SLOTS_PER_EPOCH", preset::SLOTS_PER_EPOCH.to_string()),
            (
                "EPOCHS_PER_ETH1_VOTING_PERIOD",
                preset::EPOCHS_PER_ETH1_VOTING_PERIOD.to_string(),
            ),
            (
                "SLOTS_PER_HISTORICAL_ROOT",
                preset::SLOTS_PER_HISTORICAL_ROOT.to_string(),
            ),
            (
                "EPOCHS_PER_HISTORICAL_VECTOR",
                preset::EPOCHS_PER_HISTORICAL_VECTOR.to_string(),
            ),
            (
                "EPOCHS_PER_SLASHINGS_VECTOR",
                preset::EPOCHS_PER_SLASHINGS_VECTOR.to_string(),
            ),
            (
                "HISTORICAL_ROOTS_LIMIT",
                preset::HISTORICAL_ROOTS_LIMIT.to_string(),
            ),
            (
                "VALIDATOR_REGISTRY_LIMIT",
                preset::VALIDATOR_REGISTRY_LIMIT.to_string(),
            ),
            (
                "MAX_PROPOSER_SLASHINGS",
                preset::MAX_PROPOSER_SLASHINGS.to_string(),
            ),
            (
                "MAX_ATTESTER_SLASHINGS",
                preset::MAX_ATTESTER_SLASHINGS.to_string(),
            ),
            ("MAX_ATTESTATIONS", preset::MAX_ATTESTATIONS.to_string()),
            ("MAX_DEPOSITS", preset::MAX_DEPOSITS.to_string()),
            (
                "MAX_VOLUNTARY_EXITS",
                preset::MAX_VOLUNTARY_EXITS.to_string(),
            ),
        ];
        for (key, expected) in checked {
            assert_eq!(data[key], expected, "{key}");
        }
        for domain in [
            "DOMAIN_BEACON_PROPOSER",
            "DOMAIN_BEACON_ATTESTER",
            "DOMAIN_RANDAO",
            "DOMAIN_DEPOSIT",
            "DOMAIN_VOLUNTARY_EXIT",
            "DOMAIN_SELECTION_PROOF",
            "DOMAIN_AGGREGATE_AND_PROOF",
        ] {
            assert!(data[domain].as_str().unwrap().starts_with("0x"), "{domain}");
        }
        // One of the two keys that fix the slot time (it compares the one
        // present with its own and refuses a node that has neither, unless
        // it too runs the default).
        assert!(data["SECONDS_PER_SLOT"].is_string());
        // Each fork's version and epoch, altair's scheduled.
        for fork in [
            "ALTAIR",
            "BELLATRIX",
            "CAPELLA",
            "DENEB",
            "ELECTRA",
            "FULU",
            "GLOAS",
        ] {
            assert!(data[format!("{fork}_FORK_VERSION")].is_string(), "{fork}");
            assert!(data[format!("{fork}_FORK_EPOCH")].is_string(), "{fork}");
        }
        assert_ne!(
            data["ALTAIR_FORK_EPOCH"],
            constants::FAR_FUTURE_EPOCH.to_string()
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

    #[tokio::test]
    async fn the_fork_schedule_lists_scheduled_forks_with_quoted_epochs() {
        let fixture = beacon_fixture(64);
        let config = fixture.store.config();
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/eth/v1/config/fork_schedule")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let data = json["data"].as_array().unwrap();

        // Phase0 comes first and is its own predecessor.
        assert_eq!(data[0]["epoch"], "0");
        assert_eq!(data[0]["previous_version"], data[0]["current_version"]);
        assert_eq!(
            data[0]["current_version"],
            hex_string(config.genesis_fork_version)
        );
        // Each fork's predecessor is the previous entry's version, and epochs
        // never go down.
        let epoch = |v: &serde_json::Value| v["epoch"].as_str().unwrap().parse::<u64>().unwrap();
        for pair in data.windows(2) {
            assert_eq!(pair[1]["previous_version"], pair[0]["current_version"]);
            assert!(epoch(&pair[1]) >= epoch(&pair[0]));
        }
        for fork in data {
            assert_ne!(fork["epoch"], constants::FAR_FUTURE_EPOCH.to_string());
        }
    }

    #[test]
    fn an_unscheduled_fork_is_left_out_of_the_schedule() {
        let mut config = Config::mainnet();
        config.gloas_fork_epoch = constants::FAR_FUTURE_EPOCH;
        let schedule = fork_schedule(&config);
        let last = schedule.last().unwrap();
        assert_eq!(
            last["current_version"],
            hex_string(config.fulu_fork_version)
        );

        config.fulu_fork_epoch = constants::FAR_FUTURE_EPOCH;
        config.gloas_fork_epoch = 100;
        let schedule = fork_schedule(&config);
        let last = schedule.last().unwrap();
        // Gloas follows the last scheduled fork, electra.
        assert_eq!(
            last["previous_version"],
            hex_string(config.electra_fork_version)
        );
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
