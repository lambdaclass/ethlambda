//! EIP-8483 (post-quantum material registration): the two request handlers
//! `specs/_features/eip8483/beacon-chain.md` adds, transcribed from
//! consensus-specs #5809 at `5dcce0ab`.
//!
//! A validator's withdrawal address registers 64 bytes of opaque PQ material
//! for that validator, and a builder's execution address 32 bytes for that
//! builder. A validator must have execution (`0x01` or `0x02`) withdrawal
//! credentials, since a BLS one names no address. Invalid requests are ignored
//! rather than failing the block, and no validator or builder status is
//! checked. Each registered 32-byte part must
//! be unique (the material is public, so anyone could otherwise copy someone
//! else's), checked against every registration, the requester's own included,
//! before a later request overwrites an earlier one. Validator and builder
//! registrations are not checked against each other.
//!
//! [`process_validator_pq_registration_request`] and
//! [`process_builder_pq_registration_request`] are the specification's
//! functions, linear scans and all, and are what the fixture runner calls.
//! `apply_parent_execution_payload` goes through
//! [`process_validator_pq_registration_requests`] instead, which the
//! specification's own note invites ("clients SHOULD maintain a cache"): a
//! payload may carry 1,024 validator requests, and the literal version scans
//! the whole registry and the whole registration list for each. The builder
//! side keeps the literal loop, since a payload carries at most 16 builder
//! requests over a builder set of a few hundred.

use std::collections::{HashMap, HashSet};

use crate::beacon::containers::BeaconState;
use crate::beacon::containers::eip8483::{
    BuilderPQRegistration, BuilderPQRegistrationRequest, ValidatorPQRegistration,
    ValidatorPQRegistrationRequest,
};
use crate::beacon::error::Result;
use crate::beacon::helpers::electra::has_execution_withdrawal_credential;
use crate::beacon::primitives::{BlsPubkey, Bytes32, ValidatorIndex};

/// Whether `withdrawal_credentials[12:]` is `source_address`. Only meaningful
/// for an execution credential: a BLS (`0x00`) one holds hash bytes there,
/// which is why the specification checks the prefix first.
fn is_withdrawal_address(withdrawal_credentials: &Bytes32, source_address: &[u8; 20]) -> bool {
    withdrawal_credentials.0[12..] == source_address[..]
}

/// `process_validator_pq_registration_request` (EIP-8483 `beacon-chain.md`).
pub fn process_validator_pq_registration_request(
    state: &mut BeaconState,
    request: &ValidatorPQRegistrationRequest,
) -> Result<()> {
    let Some(validator_index) = state
        .iter_validators()
        .position(|validator| validator.pubkey == request.validator_pubkey)
    else {
        return Ok(());
    };
    let validator_index = validator_index as ValidatorIndex;
    let validator = state.validator(validator_index)?;

    // Verify the validator has execution withdrawal credentials.
    if !has_execution_withdrawal_credential(validator) {
        return Ok(());
    }

    // Verify the request comes from the validator's withdrawal address.
    if !is_withdrawal_address(&validator.withdrawal_credentials, &request.source_address.0) {
        return Ok(());
    }

    let registrations = state.validator_pq_registrations_mut()?;

    // Verify the PQ data is not already registered.
    let already_registered = registrations.iter().any(|registration| {
        registration.pq_data.first_half() == request.pq_data.first_half()
            || registration.pq_data.second_half() == request.pq_data.second_half()
    });
    if already_registered {
        return Ok(());
    }

    // Overwrite an existing registration for this validator.
    if let Some(registration) = registrations
        .iter_mut()
        .find(|registration| registration.validator_index == validator_index)
    {
        registration.pq_data = request.pq_data;
        return Ok(());
    }

    registrations.push(ValidatorPQRegistration {
        validator_index,
        pq_data: request.pq_data,
    });
    Ok(())
}

/// `process_builder_pq_registration_request` (EIP-8483 `beacon-chain.md`).
pub fn process_builder_pq_registration_request(
    state: &mut BeaconState,
    request: &BuilderPQRegistrationRequest,
) -> Result<()> {
    let Some(builder) = state
        .builders()?
        .iter()
        .find(|builder| builder.pubkey == request.builder_pubkey)
    else {
        return Ok(());
    };

    // Verify the request comes from the builder's execution address.
    if builder.execution_address != request.source_address {
        return Ok(());
    }

    let registrations = state.builder_pq_registrations_mut()?;

    // Verify the PQ data is not already registered.
    if registrations
        .iter()
        .any(|registration| registration.pq_data == request.pq_data)
    {
        return Ok(());
    }

    // Overwrite an existing registration for this builder.
    if let Some(registration) = registrations
        .iter_mut()
        .find(|registration| registration.builder_pubkey == request.builder_pubkey)
    {
        registration.pq_data = request.pq_data;
        return Ok(());
    }

    registrations.push(BuilderPQRegistration {
        builder_pubkey: request.builder_pubkey,
        pq_data: request.pq_data,
    });
    Ok(())
}

/// [`process_validator_pq_registration_request`] for every request of one
/// payload, in order, with the same result.
///
/// The literal version does two linear scans per request: the registry, to
/// resolve the public key, and the registration list, to check uniqueness and
/// find an entry to overwrite. Here the registry is walked once for every
/// requested key, and the registration list once into an index that each
/// accepted request then keeps current. Both are sound because nothing a PQ
/// request does touches the registry (keys and withdrawal credentials read
/// before the first request are the ones every later request would read), and
/// the registration list changes only through this loop.
pub fn process_validator_pq_registration_requests(
    state: &mut BeaconState,
    requests: &[ValidatorPQRegistrationRequest],
) -> Result<()> {
    if requests.is_empty() {
        return Ok(());
    }

    // The registry position of every requested key, first occurrence first,
    // as `validator_pubkeys.index(..)` finds it, with its withdrawal
    // credentials if they are execution ones and `None` if they are BLS.
    let wanted: HashSet<BlsPubkey> = requests
        .iter()
        .map(|request| request.validator_pubkey)
        .collect();
    let mut resolved: HashMap<BlsPubkey, (ValidatorIndex, Option<Bytes32>)> =
        HashMap::with_capacity(wanted.len());
    for (index, validator) in state.iter_validators().enumerate() {
        if wanted.contains(&validator.pubkey) {
            let credentials = has_execution_withdrawal_credential(validator)
                .then_some(validator.withdrawal_credentials);
            resolved
                .entry(validator.pubkey)
                .or_insert((index as ValidatorIndex, credentials));
        }
    }

    let registrations = state.validator_pq_registrations_mut()?;
    let mut index = RegistrationIndex::default();
    for (position, registration) in registrations.iter().enumerate() {
        index.insert(position, registration);
    }

    for request in requests {
        let Some(&(validator_index, Some(withdrawal_credentials))) =
            resolved.get(&request.validator_pubkey)
        else {
            continue;
        };
        if !is_withdrawal_address(&withdrawal_credentials, &request.source_address.0) {
            continue;
        }
        if index.is_registered(request) {
            continue;
        }
        let registration = ValidatorPQRegistration {
            validator_index,
            pq_data: request.pq_data,
        };
        match index.position_of(validator_index) {
            Some(position) => {
                index.forget_data(&registrations[position]);
                registrations[position].pq_data = request.pq_data;
                index.remember_data(&registration);
            }
            None => {
                index.insert(registrations.len(), &registration);
                registrations.push(registration);
            }
        }
    }
    Ok(())
}

/// What [`process_validator_pq_registration_requests`] reads of the
/// registration list: how many entries hold each first and each second half
/// (counts rather than a set, so an overwrite frees exactly one holder even in
/// a list built with repeats, as a fixture's pre-state may be), and the first
/// entry for each validator, the one the specification's overwrite loop finds.
#[derive(Default)]
struct RegistrationIndex {
    first_halves: HashMap<[u8; 32], usize>,
    second_halves: HashMap<[u8; 32], usize>,
    positions: HashMap<ValidatorIndex, usize>,
}

impl RegistrationIndex {
    fn insert(&mut self, position: usize, registration: &ValidatorPQRegistration) {
        self.positions
            .entry(registration.validator_index)
            .or_insert(position);
        self.remember_data(registration);
    }

    fn remember_data(&mut self, registration: &ValidatorPQRegistration) {
        *self
            .first_halves
            .entry(*registration.pq_data.first_half())
            .or_default() += 1;
        *self
            .second_halves
            .entry(*registration.pq_data.second_half())
            .or_default() += 1;
    }

    fn forget_data(&mut self, registration: &ValidatorPQRegistration) {
        for (halves, half) in [
            (&mut self.first_halves, registration.pq_data.first_half()),
            (&mut self.second_halves, registration.pq_data.second_half()),
        ] {
            if let Some(count) = halves.get_mut(half) {
                *count -= 1;
                if *count == 0 {
                    halves.remove(half);
                }
            }
        }
    }

    fn is_registered(&self, request: &ValidatorPQRegistrationRequest) -> bool {
        self.first_halves.contains_key(request.pq_data.first_half())
            || self
                .second_halves
                .contains_key(request.pq_data.second_half())
    }

    fn position_of(&self, validator_index: ValidatorIndex) -> Option<usize> {
        self.positions.get(&validator_index).copied()
    }
}

#[cfg(test)]
mod tests {
    //! The cases of consensus-specs #5809's
    //! `test_process_{validator,builder}_pq_registration_request.py`, one test
    //! each under the pyspec's own name, plus what that PR leaves to the
    //! client: the batched validator path, the per-payload limits, the
    //! EIP-8483 boundary rule and the upgrade.
    //!
    //! Every validator case runs through both
    //! [`process_validator_pq_registration_request`] and
    //! [`process_validator_pq_registration_requests`] from the same pre-state
    //! and asserts they agree, so the batch is checked against the
    //! specification's function on every case the specification itself names.

    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::constants;
    use crate::beacon::containers::eip8483::PQRegistrationRequests;
    use crate::beacon::containers::gloas;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::test_state::with_validators_at;
    use crate::beacon::preset;
    use crate::beacon::primitives::{Bytes64, ExecutionAddress, HashTreeRoot as _, Root};
    use crate::beacon::stf::gloas::{
        apply_parent_execution_payload, process_parent_execution_payload,
    };

    const VALIDATORS: usize = 8;
    const BUILDERS: u8 = 2;

    fn pubkey(index: u64) -> BlsPubkey {
        let mut bytes = [0u8; 48];
        bytes[..8].copy_from_slice(&(index + 1).to_le_bytes());
        BlsPubkey(bytes)
    }

    fn builder_pubkey(index: u8) -> BlsPubkey {
        BlsPubkey([0xb0 + index; 48])
    }

    fn builder_address(index: u8) -> ExecutionAddress {
        ExecutionAddress::from_slice(&[0xa0 + index; 20])
    }

    fn address(byte: u8) -> ExecutionAddress {
        ExecutionAddress::from_slice(&[byte; 20])
    }

    /// An EIP-8483 state with distinct validator keys (BLS withdrawal
    /// credentials, the all-zero default) and two builders.
    fn state() -> BeaconState {
        let mut state = with_validators_at(ForkName::Eip8483, VALIDATORS);
        for index in 0..VALIDATORS as u64 {
            state.validator_mut(index).unwrap().pubkey = pubkey(index);
        }
        let builders = state.builders_mut().unwrap();
        for index in 0..BUILDERS {
            builders.push(gloas::Builder {
                pubkey: builder_pubkey(index),
                execution_address: builder_address(index),
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            });
        }
        state.apply_pending_mutations();
        state
    }

    fn set_withdrawal_credentials(
        state: &mut BeaconState,
        index: ValidatorIndex,
        prefix: u8,
        address: ExecutionAddress,
    ) {
        let mut credentials = [0u8; 32];
        credentials[0] = prefix;
        credentials[12..].copy_from_slice(&address.0);
        state.validator_mut(index).unwrap().withdrawal_credentials = Bytes32::from(credentials);
        state.apply_pending_mutations();
    }

    fn set_execution_withdrawal_address(
        state: &mut BeaconState,
        index: ValidatorIndex,
        address: ExecutionAddress,
    ) {
        set_withdrawal_credentials(
            state,
            index,
            constants::ETH1_ADDRESS_WITHDRAWAL_PREFIX,
            address,
        );
    }

    fn data(first: u8, second: u8) -> Bytes64 {
        let mut bytes = [first; 64];
        bytes[32..].fill(second);
        Bytes64(bytes)
    }

    /// `prepare_validator_pq_registration_request`: from the validator's own
    /// withdrawal address unless `source_address` overrides it.
    fn validator_request(
        state: &BeaconState,
        index: ValidatorIndex,
        pq_data: Bytes64,
        source_address: Option<ExecutionAddress>,
    ) -> ValidatorPQRegistrationRequest {
        let validator = state.validator(index).unwrap();
        ValidatorPQRegistrationRequest {
            source_address: source_address.unwrap_or_else(|| {
                ExecutionAddress::from_slice(&validator.withdrawal_credentials.0[12..])
            }),
            validator_pubkey: validator.pubkey,
            pq_data,
        }
    }

    fn builder_request(
        state: &BeaconState,
        index: u8,
        pq_data: Bytes32,
        source_address: Option<ExecutionAddress>,
    ) -> BuilderPQRegistrationRequest {
        let builder = &state.builders().unwrap()[index as usize];
        BuilderPQRegistrationRequest {
            source_address: source_address.unwrap_or(builder.execution_address),
            builder_pubkey: builder.pubkey,
            pq_data,
        }
    }

    /// Runs `requests` in order through the specification's function and, from
    /// the same pre-state, through the batch, asserting the two agree.
    fn run_validator_requests(
        state: &BeaconState,
        requests: &[ValidatorPQRegistrationRequest],
    ) -> BeaconState {
        let mut literal = state.clone();
        for request in requests {
            process_validator_pq_registration_request(&mut literal, request).unwrap();
        }
        let mut batched = state.clone();
        process_validator_pq_registration_requests(&mut batched, requests).unwrap();
        literal.apply_pending_mutations();
        batched.apply_pending_mutations();
        assert_eq!(
            literal.validator_pq_registrations().unwrap(),
            batched.validator_pq_registrations().unwrap(),
            "the batch and the specification's function disagree"
        );
        assert_eq!(literal, batched);
        literal
    }

    /// `run_validator_pq_registration_request_processing`: the post-state of
    /// one request, checked against the batch.
    fn run_validator(state: &BeaconState, request: ValidatorPQRegistrationRequest) -> BeaconState {
        run_validator_requests(state, &[request])
    }

    /// The `valid=False` branch: the request is ignored, the state unchanged.
    fn assert_validator_ignored(state: &BeaconState, request: ValidatorPQRegistrationRequest) {
        assert_eq!(run_validator(state, request), *state);
    }

    fn run_builder(state: &BeaconState, request: BuilderPQRegistrationRequest) -> BeaconState {
        let mut post = state.clone();
        process_builder_pq_registration_request(&mut post, &request).unwrap();
        post
    }

    fn assert_builder_ignored(state: &BeaconState, request: BuilderPQRegistrationRequest) {
        assert_eq!(run_builder(state, request), *state);
    }

    fn validator_registrations(state: &BeaconState) -> Vec<(ValidatorIndex, Bytes64)> {
        state
            .validator_pq_registrations()
            .unwrap()
            .iter()
            .map(|registration| (registration.validator_index, registration.pq_data))
            .collect()
    }

    fn builder_registrations(state: &BeaconState) -> Vec<(BlsPubkey, Bytes32)> {
        state
            .builder_pq_registrations()
            .unwrap()
            .iter()
            .map(|registration| (registration.builder_pubkey, registration.pq_data))
            .collect()
    }

    // -- process_validator_pq_registration_request -------------------------

    #[test]
    fn validator_success() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        let request = validator_request(&state, 0, data(0x22, 0x22), None);

        let post = run_validator(&state, request);

        assert_eq!(validator_registrations(&post), vec![(0, data(0x22, 0x22))]);
    }

    #[test]
    fn validator_compounding_credentials() {
        let mut state = state();
        set_withdrawal_credentials(
            &mut state,
            0,
            constants::COMPOUNDING_WITHDRAWAL_PREFIX,
            address(0x11),
        );
        let request = validator_request(&state, 0, data(0x22, 0x22), None);

        let post = run_validator(&state, request);

        assert_eq!(validator_registrations(&post), vec![(0, data(0x22, 0x22))]);
    }

    #[test]
    fn validator_overwrites_registration() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        let first = validator_request(&state, 0, data(0x22, 0x22), None);
        let state = run_validator(&state, first);
        let request = validator_request(&state, 0, data(0x33, 0x33), None);

        let post = run_validator(&state, request);

        assert_eq!(validator_registrations(&post), vec![(0, data(0x33, 0x33))]);
    }

    #[test]
    fn validator_registrations_for_two_validators() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        set_execution_withdrawal_address(&mut state, 1, address(0x11));
        let first = validator_request(&state, 1, data(0x22, 0x22), None);
        let state = run_validator(&state, first);
        let request = validator_request(&state, 0, data(0x33, 0x33), None);

        let post = run_validator(&state, request);

        let indices: Vec<_> = validator_registrations(&post)
            .into_iter()
            .map(|(index, _)| index)
            .collect();
        assert_eq!(indices, vec![1, 0]);
    }

    #[test]
    fn validator_exited_validator() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        state.validator_mut(0).unwrap().exit_epoch = 2;
        state.apply_pending_mutations();
        let request = validator_request(&state, 0, data(0x22, 0x22), None);

        let post = run_validator(&state, request);

        assert_eq!(validator_registrations(&post).len(), 1);
    }

    #[test]
    fn validator_unknown_pubkey() {
        let state = state();
        let request = ValidatorPQRegistrationRequest {
            source_address: address(0x11),
            validator_pubkey: pubkey(VALIDATORS as u64),
            pq_data: data(0x22, 0x22),
        };
        assert_validator_ignored(&state, request);
    }

    /// The default credentials are BLS (`0x00`) ones, whose bytes `12..32`
    /// are a hash no address matches.
    #[test]
    fn validator_bls_withdrawal_credentials() {
        let mut state = state();
        let mut credentials = [0x5a; 32];
        credentials[0] = constants::BLS_WITHDRAWAL_PREFIX;
        state.validator_mut(0).unwrap().withdrawal_credentials = Bytes32::from(credentials);
        state.apply_pending_mutations();
        let request = validator_request(&state, 0, data(0x22, 0x22), Some(address(0x11)));
        assert_validator_ignored(&state, request);
    }

    /// The source address matches the credential's bytes, so only the
    /// prefix check refuses it (`__bls_credentials_matching_source_address`).
    #[test]
    fn validator_bls_credentials_matching_source_address() {
        let mut state = state();
        set_withdrawal_credentials(
            &mut state,
            0,
            constants::BLS_WITHDRAWAL_PREFIX,
            address(0x11),
        );
        let request = validator_request(&state, 0, data(0x22, 0x22), None);
        assert_eq!(request.source_address, address(0x11));
        assert_validator_ignored(&state, request);
    }

    #[test]
    fn validator_wrong_source_address() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        let request = validator_request(&state, 0, data(0x22, 0x22), Some(address(0x44)));
        assert_validator_ignored(&state, request);
    }

    #[test]
    fn validator_pq_data_already_registered() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        set_execution_withdrawal_address(&mut state, 1, address(0x44));
        let first = validator_request(&state, 0, data(0x22, 0x22), None);
        let state = run_validator(&state, first);
        let request = validator_request(&state, 1, data(0x22, 0x22), None);
        assert_validator_ignored(&state, request);
    }

    /// Uniqueness is checked against the requester's own registration too, so
    /// resubmitting it is ignored rather than an overwrite.
    #[test]
    fn validator_resubmitted_registration() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        let first = validator_request(&state, 0, data(0x22, 0x22), None);
        let state = run_validator(&state, first);
        let request = validator_request(&state, 0, data(0x22, 0x22), None);
        assert_validator_ignored(&state, request);
    }

    /// An overwrite frees the material it replaced.
    #[test]
    fn validator_overwritten_pq_data_can_be_registered() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        set_execution_withdrawal_address(&mut state, 1, address(0x44));
        let requests = [
            validator_request(&state, 0, data(0x22, 0x22), None),
            validator_request(&state, 0, data(0x33, 0x33), None),
            validator_request(&state, 1, data(0x22, 0x22), None),
        ];

        let post = run_validator_requests(&state, &requests);

        assert_eq!(
            validator_registrations(&post),
            vec![(0, data(0x33, 0x33)), (1, data(0x22, 0x22))]
        );
    }

    #[test]
    fn validator_first_part_already_registered() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        set_execution_withdrawal_address(&mut state, 1, address(0x44));
        let first = validator_request(&state, 0, data(0x22, 0x22), None);
        let state = run_validator(&state, first);
        let request = validator_request(&state, 1, data(0x22, 0x33), None);
        assert_validator_ignored(&state, request);
    }

    #[test]
    fn validator_second_part_already_registered() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        set_execution_withdrawal_address(&mut state, 1, address(0x44));
        let first = validator_request(&state, 0, data(0x22, 0x55), None);
        let state = run_validator(&state, first);
        let request = validator_request(&state, 1, data(0x33, 0x55), None);
        assert_validator_ignored(&state, request);
    }

    /// A builder's key is not a validator's, whatever address sends it.
    #[test]
    fn validator_builder_pubkey() {
        let state = state();
        let request = ValidatorPQRegistrationRequest {
            source_address: builder_address(0),
            validator_pubkey: builder_pubkey(0),
            pq_data: data(0x22, 0x22),
        };
        assert_validator_ignored(&state, request);
    }

    /// Validator and builder material are not checked against each other.
    #[test]
    fn validator_pq_data_registered_by_builder() {
        let mut state = state();
        set_execution_withdrawal_address(&mut state, 0, address(0x11));
        state
            .builder_pq_registrations_mut()
            .unwrap()
            .push(BuilderPQRegistration {
                builder_pubkey: builder_pubkey(0),
                pq_data: Bytes32::repeat_byte(0x22),
            });
        let request = validator_request(&state, 0, data(0x22, 0x33), None);

        let post = run_validator(&state, request);

        assert_eq!(validator_registrations(&post).len(), 1);
    }

    // -- process_builder_pq_registration_request ---------------------------

    #[test]
    fn builder_success() {
        let state = state();
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x22), None);

        let post = run_builder(&state, request);

        assert_eq!(
            builder_registrations(&post),
            vec![(builder_pubkey(0), Bytes32::repeat_byte(0x22))]
        );
    }

    #[test]
    fn builder_overwrites_registration() {
        let state = state();
        let state = run_builder(
            &state,
            builder_request(&state, 0, Bytes32::repeat_byte(0x22), None),
        );
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x33), None);

        let post = run_builder(&state, request);

        assert_eq!(
            builder_registrations(&post),
            vec![(builder_pubkey(0), Bytes32::repeat_byte(0x33))]
        );
    }

    #[test]
    fn builder_registrations_for_two_builders() {
        let state = state();
        let state = run_builder(
            &state,
            builder_request(&state, 1, Bytes32::repeat_byte(0x22), None),
        );
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x33), None);

        let post = run_builder(&state, request);

        let keys: Vec<_> = builder_registrations(&post)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        assert_eq!(keys, vec![builder_pubkey(1), builder_pubkey(0)]);
    }

    /// A validator's key is not a builder's.
    #[test]
    fn builder_unknown_pubkey() {
        let state = state();
        let request = BuilderPQRegistrationRequest {
            source_address: address(0x11),
            builder_pubkey: pubkey(0),
            pq_data: Bytes32::repeat_byte(0x22),
        };
        assert_builder_ignored(&state, request);
    }

    #[test]
    fn builder_wrong_source_address() {
        let state = state();
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x22), Some(address(0x99)));
        assert_builder_ignored(&state, request);
    }

    #[test]
    fn builder_pq_data_already_registered() {
        let state = state();
        let state = run_builder(
            &state,
            builder_request(&state, 0, Bytes32::repeat_byte(0x22), None),
        );
        let request = builder_request(&state, 1, Bytes32::repeat_byte(0x22), None);
        assert_builder_ignored(&state, request);
    }

    #[test]
    fn builder_pq_data_registered_by_validator() {
        let mut state = state();
        state
            .validator_pq_registrations_mut()
            .unwrap()
            .push(ValidatorPQRegistration {
                validator_index: 0,
                pq_data: data(0x22, 0x33),
            });
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x22), None);

        let post = run_builder(&state, request);

        assert_eq!(builder_registrations(&post).len(), 1);
    }

    /// A builder sharing a validator's key registers in its own list only.
    #[test]
    fn builder_shares_validator_pubkey() {
        let mut state = state();
        state.builders_mut().unwrap()[0].pubkey = pubkey(0);
        state
            .validator_pq_registrations_mut()
            .unwrap()
            .push(ValidatorPQRegistration {
                validator_index: 0,
                pq_data: data(0x22, 0x22),
            });
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x33), None);

        let post = run_builder(&state, request);

        assert_eq!(validator_registrations(&post).len(), 1);
        assert_eq!(
            builder_registrations(&post),
            vec![(pubkey(0), Bytes32::repeat_byte(0x33))]
        );
    }

    /// No builder status is checked: an exited builder still registers.
    #[test]
    fn builder_exited_builder() {
        let mut state = state();
        state.builders_mut().unwrap()[0].withdrawable_epoch = 0;
        let request = builder_request(&state, 0, Bytes32::repeat_byte(0x22), None);

        let post = run_builder(&state, request);

        assert_eq!(builder_registrations(&post).len(), 1);
    }

    // -- The batch against the specification's function --------------------

    /// A payload's worth of requests that overwrite, collide on either half,
    /// free material and reuse it, name unknown keys and wrong addresses, in
    /// one batch, starting from a list that already holds entries.
    #[test]
    fn a_mixed_batch_matches_the_specifications_function_request_by_request() {
        let mut state = state();
        for index in 0..VALIDATORS as u64 {
            set_execution_withdrawal_address(&mut state, index, address(0x10 + index as u8));
        }
        // Validator 5's address bytes stay, under a BLS prefix.
        set_withdrawal_credentials(
            &mut state,
            5,
            constants::BLS_WITHDRAWAL_PREFIX,
            address(0x15),
        );
        let seeded = [
            validator_request(&state, 6, data(0x60, 0x61), None),
            validator_request(&state, 7, data(0x70, 0x71), None),
        ];
        let state = run_validator_requests(&state, &seeded);

        let mut requests = Vec::new();
        for round in 0..4u8 {
            for index in 0..VALIDATORS as u64 {
                let byte = (index as u8).wrapping_mul(3).wrapping_add(round);
                requests.push(validator_request(
                    &state,
                    index,
                    data(byte, byte ^ 0x40),
                    None,
                ));
            }
        }
        requests.extend([
            // Collides with validator 7's first half, then its second.
            validator_request(&state, 0, data(0x70, 0x99), None),
            validator_request(&state, 1, data(0x98, 0x71), None),
            // Validator 6 moves off its material, and validator 2 takes it.
            validator_request(&state, 6, data(0xe0, 0xe1), None),
            validator_request(&state, 2, data(0x60, 0x61), None),
            // Wrong address, BLS credentials, and unknown key.
            validator_request(&state, 3, data(0xc0, 0xc1), Some(address(0xff))),
            validator_request(&state, 5, data(0xc2, 0xc3), None),
            ValidatorPQRegistrationRequest {
                source_address: address(0x10),
                validator_pubkey: pubkey(99),
                pq_data: data(0xd0, 0xd1),
            },
            // The same request twice in one payload.
            validator_request(&state, 4, data(0xf0, 0xf1), None),
            validator_request(&state, 4, data(0xf0, 0xf1), None),
        ]);

        let post = run_validator_requests(&state, &requests);
        assert!(validator_registrations(&post).len() >= seeded.len());
    }

    // -- apply_parent_execution_payload and the boundary rule --------------

    /// Gloas and heze from genesis and EIP-8483 at `eip8483_epoch`, on the
    /// mainnet preset's schedule.
    fn config(eip8483_epoch: u64) -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Heze, 0)
            .with_fork_epoch(ForkName::Eip8483, eip8483_epoch)
    }

    const PARENT_HASH: Root = Root::repeat_byte(0x0f);

    /// An EIP-8483 state at the first slot of epoch 1 whose parent block, and
    /// so the bid the state holds, is the last slot of epoch 0.
    fn state_with_parent_bid(requests_root: Root) -> BeaconState {
        let mut state = state();
        let parent_slot = preset::SLOTS_PER_EPOCH - 1;
        state.latest_block_header_mut().slot = parent_slot;
        let bid = state.latest_execution_payload_bid_mut().unwrap();
        bid.slot = parent_slot;
        bid.block_hash = PARENT_HASH;
        bid.execution_requests_root = requests_root;
        state
    }

    /// The child block's bid, building on the parent's payload or not.
    fn child_bid(full_parent: bool) -> gloas::ExecutionPayloadBid {
        gloas::ExecutionPayloadBid {
            parent_block_hash: if full_parent {
                PARENT_HASH
            } else {
                Root::repeat_byte(0xee)
            },
            ..Default::default()
        }
    }

    fn five_field(requests: &gloas::ExecutionRequests) -> gloas::ExecutionRequests {
        gloas::ExecutionRequests {
            pq_registrations: None,
            ..requests.clone()
        }
    }

    /// Requests a FULL parent's payload might carry: one consolidation-free
    /// withdrawal request for an unknown key, which processing ignores.
    fn requests_with_a_withdrawal(fork: ForkName) -> gloas::ExecutionRequests {
        let mut requests = gloas::ExecutionRequests::empty(fork);
        requests.withdrawals = vec![crate::beacon::containers::electra::WithdrawalRequest {
            source_address: address(0x01),
            validator_pubkey: pubkey(99),
            amount: 0,
        }]
        .into();
        requests
    }

    /// The first EIP-8483 block over a FULL heze parent carries seven fields,
    /// and the parent's bid committed to the five-field root.
    #[test]
    fn across_the_boundary_a_full_parent_is_checked_against_its_five_field_root() {
        let config = config(1);
        let requests = requests_with_a_withdrawal(ForkName::Eip8483);
        let mut state = state_with_parent_bid(five_field(&requests).hash_tree_root());

        process_parent_execution_payload(&mut state, &child_bid(true), &requests, &config)
            .expect("the five-field commitment matches");

        assert_eq!(state.latest_block_hash().unwrap(), &PARENT_HASH);
    }

    #[test]
    fn across_the_boundary_the_seven_field_root_is_not_the_commitment() {
        let config = config(1);
        let requests = requests_with_a_withdrawal(ForkName::Eip8483);
        let mut state = state_with_parent_bid(requests.hash_tree_root());

        assert!(
            process_parent_execution_payload(&mut state, &child_bid(true), &requests, &config)
                .is_err()
        );
    }

    /// A heze payload produced no PQ requests, so the first EIP-8483 block
    /// cannot claim any for it.
    #[test]
    fn across_the_boundary_a_full_parent_carries_no_pq_requests() {
        let config = config(1);
        let mut requests = requests_with_a_withdrawal(ForkName::Eip8483);
        requests
            .pq_registrations
            .as_mut()
            .unwrap()
            .builder_pq_registrations
            .push(BuilderPQRegistrationRequest::default());
        let mut state = state_with_parent_bid(five_field(&requests).hash_tree_root());

        assert!(
            process_parent_execution_payload(&mut state, &child_bid(true), &requests, &config)
                .is_err()
        );
    }

    /// Past the boundary the commitment is the seven-field root, as the
    /// specification states it.
    #[test]
    fn after_the_boundary_a_full_parent_is_checked_against_its_own_root() {
        let config = config(0);
        let requests = requests_with_a_withdrawal(ForkName::Eip8483);

        let mut state = state_with_parent_bid(requests.hash_tree_root());
        process_parent_execution_payload(&mut state, &child_bid(true), &requests, &config)
            .expect("the seven-field commitment matches");

        let mut state = state_with_parent_bid(five_field(&requests).hash_tree_root());
        assert!(
            process_parent_execution_payload(&mut state, &child_bid(true), &requests, &config)
                .is_err()
        );
    }

    /// An EMPTY parent's requests are the fork's own empty value, seven lists.
    #[test]
    fn an_empty_parent_carries_the_seven_field_empty_requests() {
        let config = config(1);
        let mut state = state_with_parent_bid(Root::ZERO);

        process_parent_execution_payload(
            &mut state,
            &child_bid(false),
            &gloas::ExecutionRequests::empty(ForkName::Eip8483),
            &config,
        )
        .expect("seven empty lists");
        assert!(
            process_parent_execution_payload(
                &mut state,
                &child_bid(false),
                &gloas::ExecutionRequests::default(),
                &config,
            )
            .is_err(),
            "the five-field empty value has another fork's shape"
        );
    }

    /// A heze state takes five fields only, EMPTY parent or not.
    #[test]
    fn a_heze_state_refuses_seven_field_requests() {
        let config = config(constants::FAR_FUTURE_EPOCH);
        let mut state = with_validators_at(ForkName::Heze, VALIDATORS);

        assert!(
            process_parent_execution_payload(
                &mut state,
                &child_bid(false),
                &gloas::ExecutionRequests::empty(ForkName::Eip8483),
                &config,
            )
            .is_err()
        );
    }

    /// A FULL parent's PQ requests reach both registries.
    #[test]
    fn a_full_parents_pq_requests_are_applied() {
        let config = config(0);
        let mut state = state_with_parent_bid(Root::ZERO);
        set_execution_withdrawal_address(&mut state, 3, address(0x33));
        let mut requests = gloas::ExecutionRequests::empty(ForkName::Eip8483);
        let pq = requests.pq_registrations.as_mut().unwrap();
        pq.validator_pq_registrations
            .push(validator_request(&state, 3, data(0x01, 0x02), None));
        pq.builder_pq_registrations.push(builder_request(
            &state,
            1,
            Bytes32::repeat_byte(0x03),
            None,
        ));
        state
            .latest_execution_payload_bid_mut()
            .unwrap()
            .execution_requests_root = requests.hash_tree_root();

        process_parent_execution_payload(&mut state, &child_bid(true), &requests, &config).unwrap();

        assert_eq!(validator_registrations(&state), vec![(3, data(0x01, 0x02))]);
        assert_eq!(
            builder_registrations(&state),
            vec![(builder_pubkey(1), Bytes32::repeat_byte(0x03))]
        );
    }

    #[test]
    fn a_payload_over_either_pq_limit_is_refused() {
        let config = config(0);

        let mut over_validators = gloas::ExecutionRequests::empty(ForkName::Eip8483);
        over_validators
            .pq_registrations
            .as_mut()
            .unwrap()
            .validator_pq_registrations =
            vec![
                ValidatorPQRegistrationRequest::default();
                preset::MAX_VALIDATOR_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD as usize + 1
            ]
            .into();
        let mut over_builders = gloas::ExecutionRequests::empty(ForkName::Eip8483);
        over_builders
            .pq_registrations
            .as_mut()
            .unwrap()
            .builder_pq_registrations =
            vec![
                BuilderPQRegistrationRequest::default();
                preset::MAX_BUILDER_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD as usize + 1
            ]
            .into();

        for requests in [over_validators, over_builders] {
            let mut state = state_with_parent_bid(Root::ZERO);
            assert!(apply_parent_execution_payload(&mut state, &requests, &config).is_err());
        }
    }

    /// The limits bound a payload, not the batch: exactly the limit passes.
    #[test]
    fn a_payload_at_the_validator_limit_is_applied() {
        let config = config(0);
        let mut state = state_with_parent_bid(Root::ZERO);
        let mut requests = gloas::ExecutionRequests::empty(ForkName::Eip8483);
        requests
            .pq_registrations
            .as_mut()
            .unwrap()
            .validator_pq_registrations = vec![
            ValidatorPQRegistrationRequest::default();
            preset::MAX_VALIDATOR_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD
                as usize
        ]
        .into();
        apply_parent_execution_payload(&mut state, &requests, &config).unwrap();
    }

    // -- upgrade_to_eip8483 -------------------------------------------------

    /// `test_fork_base_state`: every heze field carries over, the fork
    /// version moves on, both registries start empty.
    #[test]
    fn the_upgrade_keeps_every_heze_field_and_starts_both_registries_empty() {
        let config = config(1);
        let pre = with_validators_at(ForkName::Heze, VALIDATORS);
        let BeaconState::Heze(heze_pre) = &pre else {
            panic!("built as heze");
        };

        let post = crate::beacon::upgrade::upgrade_to_eip8483(&pre, &config).unwrap();

        let BeaconState::Eip8483(inner) = &post else {
            panic!("upgraded to EIP-8483");
        };
        assert_eq!(inner.fork.previous_version, heze_pre.fork.current_version);
        assert_eq!(inner.fork.current_version, config.eip8483_fork_version);
        assert_eq!(
            inner.fork.epoch,
            crate::beacon::helpers::misc::compute_epoch_at_slot(heze_pre.slot)
        );
        assert!(inner.validator_pq_registrations.is_empty());
        assert!(inner.builder_pq_registrations.is_empty());
        let mut expected = crate::beacon::containers::eip8483::BeaconState::from(heze_pre.clone());
        expected.fork = inner.fork;
        assert_eq!(*inner, expected);
    }

    #[test]
    fn only_a_heze_state_upgrades_to_eip8483() {
        let pre = with_validators_at(ForkName::Gloas, VALIDATORS);
        assert!(crate::beacon::upgrade::upgrade_to_eip8483(&pre, &config(1)).is_err());
    }

    /// Heze and EIP-8483 scheduled at one epoch over a gloas chain: the
    /// boundary step `process_slots` runs at an epoch's first slot applies
    /// both upgrades, in order. Called directly rather than through
    /// `process_slots`, whose epoch processing this minimal state cannot run
    /// (no balance-weighted PTC selection over it).
    #[test]
    fn the_fork_boundary_chains_the_heze_and_eip8483_upgrades_at_one_epoch() {
        let config = Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Heze, 2)
            .with_fork_epoch(ForkName::Eip8483, 2);
        let mut state = with_validators_at(ForkName::Gloas, VALIDATORS);
        let BeaconState::Gloas(inner) = &mut state else {
            panic!("built as gloas");
        };
        // Heze's upgrade asserts the eth1 bridge is retired (EIP-8015).
        inner.deposit_requests_start_index = inner.eth1_deposit_index;
        *state.slot_mut() = 2 * preset::SLOTS_PER_EPOCH;

        crate::beacon::stf::upgrade_at_fork_boundary(&mut state, &config).unwrap();

        assert_eq!(state.fork_name(), ForkName::Eip8483);
        assert_eq!(state.fork().previous_version, config.heze_fork_version);
        assert_eq!(state.fork().current_version, config.eip8483_fork_version);
        assert!(state.validator_pq_registrations().unwrap().is_empty());
    }

    /// An unscheduled EIP-8483 never upgrades a heze chain, whatever epoch it
    /// reaches.
    #[test]
    fn an_unscheduled_eip8483_leaves_a_heze_chain_on_heze() {
        let config = config(constants::FAR_FUTURE_EPOCH);
        let mut state = with_validators_at(ForkName::Heze, VALIDATORS);
        for epoch in [1, 2, 1_000] {
            *state.slot_mut() = epoch * preset::SLOTS_PER_EPOCH;
            crate::beacon::stf::upgrade_at_fork_boundary(&mut state, &config).unwrap();
            assert_eq!(state.fork_name(), ForkName::Heze);
        }
    }

    #[test]
    fn the_seven_field_empty_requests_are_what_an_eip8483_body_carries() {
        let body = crate::beacon::containers::heze::BeaconBlockBody::empty_at(ForkName::Eip8483);
        assert_eq!(
            body.parent_execution_requests,
            gloas::ExecutionRequests {
                pq_registrations: Some(PQRegistrationRequests::default()),
                ..Default::default()
            }
        );
    }
}
