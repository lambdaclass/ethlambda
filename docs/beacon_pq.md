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
selectors 8 and 9. Neither is scheduled on a public network. **The node
follows PQ** (`ForkName::is_followed`): it imports PQ blocks and envelopes
from gossip and req/resp, applies PQ aggregates and payload attestations to
fork choice, and asks its execution client about PQ payloads. It was run
next to Lighthouse's PQ client on a PQ-at-genesis devnet
([`tooling/pq-devnet`](../tooling/pq-devnet/README.md)). Its validator
client runs every PQ duty (attest, aggregate, the PTC vote, propose and
reveal the payload), and the beacon node builds PQ blocks with their
attestations' proofs merged: see [Validator duties](#validator-duties). It
does not follow EIP-8483 yet: see [What remains](#what-remains).

Each builds on the fork before it, like every other fork. EIP-8483 is gloas
plus its two requests and PQ is EIP-8483 with BLS replaced, so a rule gated
`fork >= ForkName::Gloas` holds at both and one gated `>= ForkName::Eip8483`
holds at PQ. Each upgrade takes only its predecessor's state, so
`process_slots` reaches PQ through EIP-8483 even when the two share an epoch.
The same holds in the Beacon API wherever the question is which rules apply
at a slot: an attestation's payload flag, the head's payload status, the PTC
window, a state's builders. Where the question is which container a version
names, the two stay apart from gloas. PQ replaces every signed container and
EIP-8483 the block and envelope, but EIP-8483's attestations, aggregates,
attester slashings and bids are gloas's own: gossip decodes the first three
as gloas's, while the Beacon API refuses the `eip8483` version header, since
the node does not follow the fork. Gossip's bid rules judge a gloas bid
against a gloas state and a PQ bid against a PQ state, and leave EIP-8483's
states out, because they read the parent's envelope, whose shape EIP-8483
changes.

## What is implemented

| Layer | Where | Status |
| --- | --- | --- |
| leanXMSS sign/verify | `ethlambda_crypto::lean_xmss` | KAT-pinned against consensus-specs and leanVM |
| Attestation proofs | `ethlambda_crypto::stark` | the specification's reference concatenation by default; leanVM proofs through a `leanvm-sidecar` with `--pq-prover-socket` (see [Proofs](#proofs)) |
| Containers | `ethlambda_types::beacon::containers::{eip8483, pq}` | SSZ round trips, gaps per the spec; the maximal aggregate, attester slashing and bid encode to `pq.yaml`'s size bounds |
| Fork upgrades | `upgrade::{upgrade_to_eip8483, upgrade_to_pq}` | unit-tested |
| Block processing | `stf::{eip8483, pq}` | unit-tested with real XMSS keys |
| Epoch processing | `stf::epoch::pq` | unit-tested |
| Fork choice | `fork_choice` (`Attestation::Pq`, `AttesterSlashing::Pq`, `on_pq_payload_attestation_message`, no `notify_ptc_messages` for PQ blocks, `on_execution_payload_envelope` over any fork's envelope) | run on the devnet; no unit tests of its own |
| Envelopes | `containers::SignedExecutionPayloadEnvelope` (gloas, EIP-8483, PQ), `stf::gloas::verify_execution_payload_envelope` | each fork's signature and requests root; storage, req/resp, gossip, the chain actor and the engine take the fork-tagged envelope |
| Spec-fixture runners | `tests/beacon_spec` | wired, but no fixtures exist yet |
| PQ gossip | `gossip::pq`, `ethlambda_p2p::beacon::pq` | every reshaped topic's rules, XMSS signatures and STARK proofs unit-tested with real keys; an accepted aggregate's vote, a payload attestation and an envelope reach the chain actor, every Lighthouse message on the devnet was accepted |
| Engine | `beacon_engine::gloas_new_payload_request` | each fork's typed requests list to `engine_newPayloadV5`, `engine_forkchoiceUpdatedV4` for a PQ head |
| Genesis | `genesis_anchor_block` | the body carries the state's bid from gloas on, as the specification's genesis helper and ethpandaops' generator build it |
| EIP-8483 gossip | `gossip`, `ethlambda_p2p::beacon::decode` | attestations, aggregates and attester slashings decode and validate as gloas's; blocks, envelopes and columns are ignored |
| Block production | `pq_block_production`, `rpc::beacon::pq_proposal` | self-build; attestations packed from validated aggregates, their proofs merged under a deadline; no blobs. Every block it built on the devnet was canonical on Lighthouse |
| Validator client | `ethlambda_validator::pq` and the duty services | keys derived from each BLS key as ethereum-package's generator and Lighthouse derive them; attestations, aggregates, PTC votes, proposals and envelopes, each at its leaf; run on the devnet |
| Aggregation | `rpc::beacon::pq_aggregation`, `pools::{PqSignaturePool, PqAggregatePool}` | the node collects its aggregators' committees' signatures and proves ahead on the sidecar |
| Beacon API | `rpc::beacon::{pool, pq_proposal, ptc, proposal}` | PQ attestations, aggregates (in and out), payload attestations, blocks, envelopes and `POST /eth/v1/validator/pq_blocks/{slot}`; the other endpoints refuse PQ's signed containers |

## Gossip

A PQ digest's topics are `pq/p2p-interface.md`'s: gloas's set without
`voluntary_exit`, `bls_to_execution_change` and the sync committee topics
(`topics::PQ_TOPIC_KINDS`), and `ATTESTATION_SUBNET_COUNT_PQ` (16) attestation
subnets, of which the node backbones its own set
(`subnets::compute_subscribed_subnets_pq`, the specification's function over
16 subnets). `attnets` advertises that set while the current digest is PQ's.
The aggregator and sync committee subnets a validator client asks for come
from BLS duties, so they are never joined under a PQ digest.

Every reshaped topic decodes by its topic's digest into PQ's container
(`decode::decode_pq_gossip`, with the `MAX_*_SIZE_PQ` bounds) and is judged by
`state_transition::beacon::gossip::pq`:

| Topic | What PQ changes |
| --- | --- |
| `beacon_aggregate_and_proof` | the aggregator's XMSS signature at its slot's aggregate leaf; aggregators are the aggregation committee, not a selection proof; the aggregate's STARK proof proves its attesters' signatures |
| `beacon_attestation_{subnet_id}` | the XMSS signature at the target epoch's attestation leaf; the subnet is one of 16 |
| `proposer_slashing`, `attester_slashing` | XMSS header signatures; each indexed attestation's STARK proof |
| `payload_attestation_message` | the XMSS signature at the slot's PTC leaf |
| `execution_payload_bid`, `proposer_preferences` | gloas's rules over the PQ builder market, with XMSS signatures and the builder-exit key compared on its last 32 bytes |
| `execution_payload` | PQ's execution request limits and the envelope's XMSS signature |
| `beacon_block` | PQ's operation and request limits (`gossip::pq::block_cheap_checks`), behind the `is_followed` gate |

The rules are gloas's with only the `[Modified in PQ]` and `[New in PQ]` lines
applied; see `docs/spec_deviations.md`. A rule that needs a PQ state (every
stateful one) ignores the message when the state it reads is of another fork,
which on a live node is always: the node imports no PQ block. So the cheap
rules judge what arrives on a PQ digest a network schedules, and the rest end
in an ignore. An accepted message is relayed and recorded in the seen caches
the other forks share (bids and preferences in a PQ builder market of their
own, which block production never reads), and goes no further: no pool, event
stream or chain actor takes one. A message that does not decode as PQ's
container is ignored, not rejected, as on every topic of a fork the node does
not follow.

Blocks, data column sidecars and the topic set the node holds keep the shared
path. A block of a fork the node does not follow is ignored before any rule.

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

### Proofs

`ethlambda_crypto::stark` proves, merges and verifies the fork's attestation
proofs through one of two backends, chosen once per process:

- **Reference** (the default): the specification's stand-in for a recursive
  STARK. A proof is the signatures concatenated in statement order, and
  verification checks each, plus the exact length. It is capped by
  `MAX_STARK_PROOF_SIZE` (1 MiB), about 436 signatures per block. The
  specification's fixtures use it.
- **Sidecar** (`--pq-prover-socket`, `stark::install_sidecar`): real leanVM
  proofs, made and checked by a `leanvm-sidecar` process over a Unix socket,
  through leanVM's own client crate at `283686575c` (`sidecar::LEANVM_REV`),
  the revision Lighthouse's PQ branch pins. A statement list maps to leanVM
  claims as Lighthouse maps it: the sorted, deduplicated
  `(public key, message)` pairs, the empty proof for no claims, and merges
  folded sixteen children at a time. `bin/ethlambda/pq/ethlambda-pq` starts a
  sidecar and passes its socket.

The encodings are not interchangeable, so every node of a network must use
the same backend; the PQ devnet's Lighthouse accepts only the sidecar. A
leanVM proof does not attest the leaf a signature was made at, so the sidecar
backend checks that each key signed the message at *some* leaf
(`docs/spec_deviations.md`). Lighthouse's blocks replay through ethlambda's
state transition with every proof verified this way, state root for state
root.

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

## Validator duties

The validator client keeps its BLS keystores and derives each validator's PQ
material from the BLS signing key at startup, the way ethereum-package's
genesis generator and Lighthouse's PQ branch do: the leanXMSS key from
`sha256("leanxmss-seed" || sk)` and the VRF tree from `sha256("vrf-seed" ||
sk)` (`ethlambda_crypto::pq_keys`). The registry names a validator by its
key's 48-byte request form, which the client looks its validators up by and
maps back to the BLS key it holds, so a validator whose derived key is not
the registered one resolves to no index and gets no duties. Key generation
builds two bottom trees per key, which takes under a minute for 16
validators.

Each duty signs at the leaf the fork assigns it (see [Leaves](#leaves)): the
attestation at its target epoch's, the others at the slot's own offset. The
client refuses to sign two different roots at one leaf. That record is in
memory; across a restart, slashing protection still guards attestations and
proposals, the two that slashing punishes.

- **Attesting**: a `SingleAttestation` signed at the target epoch's leaf,
  published on one of PQ's 16 subnets.
- **The PTC vote**: as gloas's, signed at the slot's PTC leaf.
- **Proposing**: the client sends its VRF proof for the slot (the RANDAO
  reveal) to `POST /eth/v1/validator/pq_blocks/{slot}`, signs the block and
  the envelope revealing its self-built payload at their leaves, and publishes
  both. The beacon node builds the block while the execution client builds
  the payload, and meanwhile packs attestations: it picks, from the
  aggregates it validated, what `process_attestation` accepts at the slot and
  credits someone new, as `compute_on_chain_aggregate` shapes them, and merges
  their proofs in `process_stark`'s order on the sidecar. A merge must end
  three quarters of the way to the attestation deadline (Lighthouse's bound).
  One child needs no merge; when more do not finish in time, the block packs
  the most valuable single-committee attestation alone, whose proof is the
  block's as it is. On the devnet's VM a two-child merge takes about four
  seconds, for Lighthouse too, so blocks there carry one attestation each.
- **Aggregating**: a PQ aggregator is a member of its committee's
  aggregation committee, which the attester duties report as
  `is_aggregator`. Proving takes seconds, so the node proves ahead, as
  Lighthouse's PQ branch does: the client's committee subscriptions join the
  committee's subnet and register it, the node keeps the validated votes'
  signatures for registered committees, and halfway between the attestation
  and aggregate deadlines seals the slot and proves each committee before the
  aggregate deadline. `GET aggregate_attestation` then answers the proved
  aggregate and its proof, and the client signs the `AggregateAndProof` at the
  slot's aggregate leaf.

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
- The operation pool and the event stream for PQ gossip: slashings are
  relayed but never packed into a block, and accepted PQ messages raise no
  events. Attestations are pooled (see [Validator duties](#validator-duties)).
- Following EIP-8483 (`ForkName::is_followed` is false for it): its block's
  cheap gossip rules, its `execution_payload` topic's decode and rules (its
  envelope is its own container), its fetched envelopes' checks, and its
  execution request limits. The envelope, engine and storage paths already
  take its envelope.
- The ENR's `attnets` keeps the pre-PQ backbone across the PQ boundary: ethrex's
  `DiscoveryServer` cannot replace the served record at runtime (the same gap
  as its `eth2` entry, see `CLAUDE.md`).
- Blobs in PQ block production: a payload with blobs is refused, since the
  envelope's column sidecars are not built for PQ yet.
- Merging ahead of a proposal: the aggregates a slot-`N` block may pack are
  all known a slot earlier, so a node could merge during slot `N - 1` for a
  proposer it serves, where today a slow merge costs every attestation but
  one.
- A persistent leaf record for the aggregate, PTC and envelope leaves, which
  slashing protection does not cover.
- The pubkey index cache keys a pubkey by bytes 1 to 9, all zero for a PQ
  key's request form: still correct (every candidate is verified, and a miss
  scans), but every PQ lookup scans.
