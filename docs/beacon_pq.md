# The PQ fork

consensus-specs' `pq` branch (pinned here at
`a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c`) specifies an emergency fork that
replaces BLS with leanXMSS, a hash-based signature scheme believed secure
against a quantum adversary. It comes as two feature forks after gloas:

1. **EIP-8483** (`specs/_features/eip8483`): validators and builders register
   post-quantum material through two new execution-layer requests. A validator
   registers 64 bytes (an XMSS key and a VRF root), a builder 32 (an XMSS key).
   Nothing else changes.
2. **PQ** (`specs/_features/pq`): every validator and builder adopts the key it
   registered, BLS signatures become XMSS ones, sync committees and the light
   client protocol go, RANDAO reveals become VRF proofs, attestations lose their
   signatures to a block-wide STARK proof, voluntary exits move to the execution
   layer, and deposits carry a VRF root instead of a signature, guarded by
   preregistrations (EIP-8205).

Both are `ForkName`s (`Eip8483`, `Pq`), between `Gloas` and `Lean`, on-disk
selectors 8 and 9. Neither is scheduled on any network, and the node does not
follow either (`ForkName::is_followed`): the state transition and fork choice
implement them, and nothing else does yet.

## What is implemented

| Layer | Where | Status |
| --- | --- | --- |
| leanXMSS sign/verify | `ethlambda_crypto::lean_xmss` | KAT-pinned against consensus-specs and leanVM |
| Reference STARK | `ethlambda_crypto::stark` | the specification's concatenation encoding |
| Containers | `ethlambda_types::beacon::containers::{eip8483, pq}` | SSZ round trips, gaps per the spec; the maximal aggregate, attester slashing and bid encode to `pq.yaml`'s size bounds |
| Fork upgrades | `upgrade::{upgrade_to_eip8483, upgrade_to_pq}` | unit-tested |
| Block processing | `stf::{eip8483, pq}` | unit-tested with real XMSS keys |
| Epoch processing | `stf::epoch::pq` | unit-tested |
| Fork choice | `fork_choice` (`Attestation::Pq`, `AttesterSlashing::Pq`, `on_pq_payload_attestation_message`, no `notify_ptc_messages` for PQ blocks) | compiles, untested; no `on_execution_payload_envelope` for the EIP-8483 or PQ envelope types |
| Envelope verification | `stf::pq::verify_execution_payload_envelope_signature` | the signature only; gloas's `verify_execution_payload_envelope` takes gloas's envelope type |
| Spec-fixture runners | `tests/beacon_spec` | wired, but no fixtures exist yet |
| Gossip, req/resp, Beacon API, validator client | | refuse both forks |

## The XMSS scheme

The specification's `xmss` module is EthLib's leanXMSS: Keccak-256, two layers
of height-16 Merkle trees over WOTS+C one-time keys, a 32-byte public key (the
top root, then the public parameter) and a 2404-byte signature that starts with
its leaf index. It is **not** the XMSS lean consensus signs with
(`ethlambda_crypto::signature`), which is leanVM's own BLAKE2s scheme with
1208-byte signatures.

`ethlambda_crypto::lean_xmss` is a port of leanVM's Rust implementation of the
same note (`crates/signatures/src/lean_xmss`, leanVM `4af2cddd`, the commit
EthLib's README cites). Its tests pin:

- consensus-specs' `xmss_kat.json`: the signature verifies, the four negative
  cases of `test_xmss.py` do not, and the seed `00..1f` regenerates the
  vector's key and signature byte for byte;
- leanVM's own known answer, the vector EthLib's README pins too.

Full key generation takes about a second and a half in `release-fast` across
cores, so both full-key tests run in `make test`. `range_key` builds a key real
over a few leaves only, for tests.

`ethlambda_crypto::stark` is the specification's reference stand-in for a
recursive STARK: a proof is the signatures concatenated in statement order,
and verification checks each, plus the exact length. It is capped by
`MAX_STARK_PROOF_SIZE` (1 MiB), about 436 signatures per block.

### Leaves

XMSS is stateful: signing two messages at one leaf breaks the key. The fork
assigns every message a leaf:

| Leaves | Used by |
| --- | --- |
| `0 .. 2^15` (reserved) | voluntary exits, preregistrations (signed for the EL contracts) |
| `2^15 + epoch` | the attestation for target `epoch` |
| the next `2^30` | builder bids, any leaf once |
| `... + 8 * slot + offset` | per slot: proposal (0), aggregate (1), PTC vote (2), proposer preferences (3), envelope (4) |

A signature carries its leaf index, and every check requires the leaf its
message may use (`compute_xmss_leaf_index`, `is_builder_bid_leaf_index`).

## How the state holds XMSS keys

A PQ `Validator` has a 32-byte `XMSSPubkey` and a `vrf_root` where every
earlier fork's has a 48-byte BLS key. Every registry accessor on `BeaconState`
hands out the shared `Validator` record, and most of the state transition
reads only its balances, epochs and credentials. So the PQ registry element,
`pq::Validator`, holds the shared record with its key in the 48-byte form an
execution-layer request names an XMSS key by (16 zero bytes, then the key:
`XmssPubkey::to_request_key`) and the VRF root beside it. Its SSZ encoding and
merkleization are written by hand through the specification's nine-field
`ValidatorRecord`, so its bytes and roots are the PQ container's exactly.

That representation is also the one the specification compares request keys
in: after a request is checked not to be legacy (`is_legacy_pubkey`), the
specification's `XMSSPubkey(request.pubkey[16:]) in validator_pubkeys` is the
48-byte comparison electra's request processing already makes. That is why
the PQ withdrawal and consolidation requests are electra's, behind the legacy
check.

The builder registry gets the same treatment (`pq::Builders`, gloas's records
in memory, `BuilderRecord` on the wire).

## The gloas-family view

Gloas, EIP-8483 and PQ states are separate structs, since each derives its own
SSZ shape (EIP-7495 progressive containers, with the fields PQ removes left as
gaps in the merkle tree via `active_fields`). They share every field the
EIP-7732 machinery reads, at the same types. `GloasFamily` and
`GloasFamilyMut` (`containers/gloas_family.rs`) borrow those fields from any of
the three, and `helpers::gloas::gloas_state(_ref)` return them, so the gloas
state transition (withdrawals, bids, payments, the PTC window, attestation
participation) runs on all three without a copy per fork. The view carries
`fork`, for the few rules that differ.

## A newer gloas underneath

The `pq` branch is based on a consensus-specs `master` newer than this
repository's pin (`v1.7.0-beta.2`). Three gloas state-transition rules changed
in between, and the PQ text depends on them, so they apply from EIP-8483 on
while gloas keeps its pinned rules. Four fork-choice rules changed for every
fork too, and those are not applied to any fork yet, the PQ forks included. See
`docs/spec_deviations.md` for both lists.

## Committees

The PQ fork caps a slot's committees at `MAX_COMMITTEES_PER_SLOT_PQ` (16 on
mainnet, 4 on minimal), for every epoch a PQ state is asked about, including a
previous epoch that ran before the fork. The committee cache's `ShufflingKey`
carries the cap, since a state either side of the fork names the same epoch and
deciding block but a different shuffling.

Aggregators are no longer self-selected: each beacon committee has an
aggregation committee of up to `AGGREGATORS_PER_COMMITTEE` validators sampled
by effective balance, kept in the state's `aggregation_committee_window` for the
previous, current and lookahead epochs.

## Inclusion delay

A PQ block includes attestations from at least
`MIN_ATTESTATION_INCLUSION_DELAY_PQ` (2) slots before it, which gives the
proposer a slot to receive aggregates and merge their proofs into the block's.
The timely-head flag needs exactly that delay, and since the attested block can
then be the grandparent, its payload vote is checked against the availability
bit at its own slot (`get_latest_block_slot`) rather than the parent's. Gloas's
`process_attestation` and `get_attestation_participation_flag_indices` serve
PQ, and take the delay from the state's fork
(`helpers::pq::min_attestation_inclusion_delay`).

## Spec fixtures

No consensus-specs release ships fixtures for either fork. The pyspec on the
`pq` branch generates them:

```sh
git clone https://github.com/ethereum/consensus-specs && cd consensus-specs
git checkout a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c
make test reftests=true fork=eip8483 preset=minimal
make test reftests=true fork=pq preset=minimal
```

`reftests/` then holds `tests/minimal/{eip8483,pq}/...`, which unpack beside
the release's own forks under `consensus-spec-tests/tests/minimal/`. The
generator runs with XMSS inactive (key generation takes minutes in EthLib's
reference implementation), so the fixtures carry stub signatures and empty
proofs; the spec-test binary calls `helpers::pq::disable_xmss_verification`
for that reason, which accepts every XMSS signature and STARK proof the way
the pyspec's inactive stubs do. `GetLeafIndex` and the self-build empty
signature are still read from the bytes, as the pyspec's are.

The runners route both forks' cases already (operations, epoch processing,
fork choice, rewards; the new `validator_pq_registration_request`,
`builder_pq_registration_request`, `validator_preregistration_request`,
`builder_preregistration_request`, `voluntary_exit_request` and `randao`
handlers, and the `aggregation_committee_window` and `preregistration_expiry`
epoch steps), but have never run against fixtures: expect fixes once they are
generated.

## What remains

- Generate and run the fixtures above, and add the PQ containers to the
  `ssz_static` runner.
- Gossip validation for the PQ topics (XMSS signatures, aggregation
  committees, `ATTESTATION_SUBNET_COUNT_PQ`, the same superset rule for
  aggregates as earlier forks), and the PQ `SignedAggregateAndProof`.
- Envelopes of the EIP-8483 and PQ shapes: `verify_execution_payload_envelope`
  and fork choice's `on_execution_payload_envelope` over them, the chain
  actor's envelope pipeline, and an engine API path for their execution
  requests.
- Block production and the validator client (XMSS keys, VRF trees, leaf
  bookkeeping, STARK proof merging).
- The pubkey index cache keys a pubkey by bytes 1 to 9, all zero for a PQ
  key's request form: still correct (every candidate is verified, and a miss
  scans), but every PQ lookup scans.
