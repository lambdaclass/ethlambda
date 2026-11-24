# The PQ fork

consensus-specs' `pq` branch (pinned here at the pq-devnet-0 spec,
`2f43bc0f989f47af81df390a90bc1f78e2436323`) specifies an emergency fork that
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
fork choice, and asks its execution client about PQ payloads. It has run
next to other clients' PQ branches on PQ-at-genesis devnets (see
[Running a devnet](#running-a-devnet)). Its validator
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
| Attestation proofs | `ethlambda_crypto::stark` | the specification's reference concatenation by default; leanVM proofs through a running `leanvm-sidecar` (`--pq-prover-socket`), which the image's `ethlambda-pq` supervisor starts (see [Proofs](#proofs)) |
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
| Block production | `pq_block_production`, `rpc::beacon::pq_proposal` | self-build; attestations packed from validated aggregates, their proofs merged under a deadline; blobs, their columns gossiped with the envelope. Every block it built on the devnet was canonical on Lighthouse |
| VRF tree | `ethlambda_crypto::vrf` | the specification's Keccak-256 tree over all `2^31` leaves, each `keccak256(vrf_seed \|\| le64(slot))`; known answers from ethereum-package's published state. Restorable from a compact state (root and leaf 0's branch), which the package publishes for its genesis validators and `ethlambda pq-keys` writes |
| Validator client | `ethlambda_validator::pq` and the duty services | seeds derived from each BLS key as ethereum-package's generator and Lighthouse derive them; attestations, aggregates, PTC votes, proposals and envelopes, each at its leaf; run on devnets next to other clients' (see [Running a devnet](#running-a-devnet)) |
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
as around the boundary into PQ. An accepted message is relayed, recorded in
the seen caches the other forks share, and handed on: an aggregate to fork
choice and to the pool PQ block production packs from
(`Store::pq_aggregate_pool`), an attestation's signature to the committees
this node's aggregators registered (`Store::pq_signature_pool`), a payload
attestation or an envelope to the chain actor, and a bid or preferences to
the PQ builder market, which PQ block production does not read yet (it
self-builds). Slashings are relayed only, and no accepted PQ message raises an
event. A message that does not decode as PQ's container is ignored, not
rejected, as on every topic of a fork the node does not follow.

Blocks, data column sidecars and the topic set the node holds keep the shared
path: a PQ block's columns are judged against its bid's commitments, as a
gloas block's are. A block of a fork the node does not follow is ignored
before any rule.

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
  through leanVM's own client crate at `c5ee9d239` (bindings v0.15.0,
  `sidecar::LEANVM_REV`), the release pq-devnet-0 runs for its signer,
  prover, verifier and sidecar. A statement list maps to leanVM
  claims as Lighthouse maps it: the sorted, deduplicated
  `(public key, message)` pairs, the empty proof for no claims, and merges
  folded sixteen children at a time.
- **Who starts the sidecar**: not the node, as for Lighthouse. The image's
  `ethlambda-pq` supervisor (`bin/ethlambda/pq/ethlambda-pq`, Lighthouse's
  `lighthouse-pq-bn` adapted) starts it on a private socket, waits for it to
  listen, and runs `ethlambda <flags> --pq-prover-socket <socket>`. The node
  exiting stops the sidecar. The sidecar exiting does not stop the node
  (Lighthouse's script stops it): the sidecar is started again on the same
  socket after a pause (one second, doubling to 32 while it keeps dying
  within a minute), and the node's client reconnects on its next request.
  Until then the node proves nothing, gossip aggregates it cannot verify are
  IGNOREd (`prover_unreachable`) rather than held against their senders, and
  a block whose proof it could not check fails import and is fetched again
  later (there is no bad-block cache). After `LEANVM_MAX_RESTARTS` (10) such
  quick exits in a row it stops the node too. `LEANVM_THREADS` sets the
  sidecar's proving threads, `LEANVM_SIDECAR` another executable. The image
  builds `leanvm-sidecar` from the commit in the root `leanvm-revision` file,
  or from
  `--build-arg LEANVM_REV` (the publish workflow's `leanvm_rev` input), and
  records the commit at `/usr/local/share/ethlambda/leanvm-revision`. The
  node's client refuses a sidecar whose hello names another protocol version
  or verifier tag; any other revision is accepted, and its proofs only have
  to verify with the other clients' verifiers (Teku's v0.16.0 sidecar and
  ethlambda's v0.15.0 one verified each other's on the interop devnet). A
  verifier-tag change needs `sidecar::LEANVM_REV` and the client crates
  moved with it.

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

## The VRF tree

XMSS signatures are not unique, so a RANDAO reveal signed with one could be
ground. A validator instead registers as its VRF root the root of a Merkle
tree of depth `VRF_TREE_DEPTH` (31), hashed with Keccak-256, whose leaf for a
slot is `compute_vrf_leaf(vrf_seed, slot) = keccak256(vrf_seed || le64(slot))`
(consensus-specs `pq` at `2f43bc0f`, the pq-devnet-0 spec). The reveal is the
leaf followed by its branch, and `process_randao` mixes the leaf in.

The root costs the whole tree: a leaf hashes its index, so no two leaves are
equal and no subtree can be reused, about two Keccak-256 calls for each of
`2^31` leaves (`vrf::tests::the_whole_tree_...`, `--ignored`).
ethereum-package publishes each genesis validator's root and leaf 0's branch,
which `ethlambda_crypto::vrf::tests::matches_ethereum_packages_published_state`
checks validator 0's against.

`is_valid_vrf_proof` folds the branch itself (`vrf::fold_vrf_branch`), not
through the SHA-256 `is_valid_merkle_branch`. It reads the slot's low 31 bits
only, so a proof for `slot` also opens `slot + 2^31`, as the specification
has it.

consensus-specs' later `b5d422b2` makes each leaf commit to a per-slot secret
and reveals the secret instead; branch `pq-devnet-0-b5d422b2` follows it.

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
seeds from the BLS signing key at startup, the way ethereum-package's genesis
generator and Lighthouse's PQ branch do: the leanXMSS key grows from
`sha256("leanxmss-seed" || sk)` and the VRF tree from the VRF seed
`sha256("vrf-seed" || sk)` (`ethlambda_crypto::pq_keys`). The specification
asks only that both seeds be secret; deriving them from the signing key is
the devnet's convention. The registry names a validator by its XMSS key,
which the Beacon API carries as its 32 bytes (a node from before that switch
sends the 48-byte request form instead; the client reads either). The client
looks its validators up by that key and maps it back to the BLS key it holds,
so a validator whose derived key is not the registered one resolves to no
index and gets no duties. It asks in two requests, the 48-byte ids (BLS keys
and request forms) and the 32-byte ones, since a node may refuse a whole
request holding the width it does not read: Lighthouse's PQ node refuses any
48-byte id. Key generation builds two bottom
trees per key, which takes under a minute for 16 validators.

The VRF tree takes minutes per key (see [The VRF tree](#the-vrf-tree)) and
only a proposal reads it, so the keys attest at once and a background thread
prepares the trees one after another, each from the first source that has
it:

1. The tree a previous start stored in
   `<validators-dir>/pq_vrf_trees/0x<bls pubkey>.bin`, checked against the
   seed and its stored root.
2. With `--vrf-state-url` (a URL or a path), the key's record in a file of
   precomputed states, read at its validator index: ethereum-package's
   `vrf_state_url` format, 1028 bytes a validator (the root, four zero
   bytes, then leaf 0's branch), which ethereum-package publishes for its
   genesis validators and `ethlambda pq-keys` writes. The record must fold
   the key's own leaf 0 to its root, so a record of another validator's, or
   of another VRF rule's, falls through to the next source.
   A proof then hashes only the leaves below the slot's highest bit, a few
   milliseconds on a young chain.
3. The whole tree, hashed. It keeps the `2^15` nodes 16 levels above the
   leaves (1 MiB), and a proof rebuilds one
   `2^16`-leaf subtree, about 30 ms. The hashing runs in a rayon pool of its
   own, one thread short of the cores: leanXMSS signing parallelizes on
   rayon's global pool, which runs a job from outside it only once a
   worker's queue is empty, so a tree hashed there held every attestation,
   aggregate and PTC vote signature until it was done.

Whatever the source, the tree is stored for the next start. A proposal that
falls before its key's tree is ready is missed (`the VRF tree is still being
hashed`).

Each duty signs at the leaf the fork assigns it (see [Leaves](#leaves)): the
attestation at its target epoch's, the others at the slot's own offset. The
client refuses to sign two different roots at one leaf, and keeps the record
in `<validators-dir>/pq_signed_leaves.bin`, each leaf written and synced
before its signature exists, so a restart cannot sign a leaf twice either.
A duty's keys sign as one batch: its leaves are written with one sync, then
the keys sign in parallel on rayon's global pool (leanVM signs on one
thread; a signature recomputes a 256th of its bottom tree, roughly 10 ms on
a core), on tokio's blocking pool rather than the duty's task.
A start drops the leaves of slots more than two epochs back, which nothing
asks for again.

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
  A payload with blobs keeps them on the node that built it, and the
  envelope's publication builds the data columns from them and gossips them
  with it (PQ keeps gloas's sidecar).
- **Proposer preferences**: from the epoch before a proposal, signed with
  leanXMSS at the proposal slot's preferences leaf, over gloas's signing root,
  and submitted under the `pq` header; the node judges them by gloas's rules
  over its PQ builder market and gossips them. A slot's leaf takes one
  message, so the client signs a slot's preferences once: a reorg that moves
  the dependent root leaves the slot without preferences rather than with
  two, as `pq/p2p-interface.md` asks.
- **Aggregating**: a PQ aggregator is a member of its committee's
  aggregation committee, which the attester duties report as
  `is_aggregator`. Every aggregator broadcasts at gloas's aggregate deadline
  (`AGGREGATE_DUE_BPS_GLOAS`, 6 s into a 12-second slot); `2f43bc0f` neither
  staggers them nor has them skip a covered aggregate (consensus-specs'
  later `4595f0fc` does both; branch `pq-devnet-0-b5d422b2` follows it).
  Proving takes seconds, so the node proves ahead, as Lighthouse's PQ branch
  does: the client's committee subscriptions join the committee's subnet and
  register it, the node keeps the validated votes' signatures for registered
  committees, and halfway between the attestation and aggregate deadlines
  seals the slot and proves each committee before the aggregate deadline.
  `GET aggregate_attestation` then answers the proved aggregate and its
  proof, or a 404 when the node proved none, and the client signs the
  `AggregateAndProof` at the slot's aggregate leaf.

## Running a devnet

ethpandaops/ethereum-package's `pq` branch runs PQ-at-genesis devnets with
ethlambda as beacon node, validator client or both (its
`.github/tests/cl-pq.yaml` names every client's `pq-devnet-0` image; the
pq-devnet-0 notes, `notes.ethereum.org/@ethpandaops/pq-devnet-0`, pin the
rest). Build the image from the repository root (`docker build -t
ethlambda:pq-local .`: it ships `leanvm-sidecar`, built from the commit in
`leanvm-revision`, and the `ethlambda-pq` supervisor), then `kurtosis run
--enclave pq <ethereum-package at pq> --args-file params.yaml` with, for
example, ethlambda next to Teku and Lodestar, and Silver's beacon node behind
ethlambda's validator client (Silver has no client of its own):

```yaml
participants:
  - el_type: geth
    cl_type: ethlambda
    cl_image: ethlambda:pq-local
    cl_extra_env_vars:
      LEANVM_THREADS: "2"
    vc_type: ethlambda
    vc_image: ethlambda:pq-local
    validator_count: 16
    supernode: true
  - el_type: geth
    cl_type: teku
    cl_image: ethpandaops/teku:pq-devnet-0
    vc_image: ethpandaops/teku:pq-devnet-0
    validator_count: 16
    supernode: true
  - el_type: geth
    cl_type: lodestar
    cl_image: ethpandaops/lodestar:pq-devnet-0
    vc_image: ethpandaops/lodestar:pq-devnet-0
    validator_count: 16
  - el_type: geth
    cl_type: silver
    cl_image: ethpandaops/silver:pq-devnet-0
    vc_type: ethlambda
    vc_image: ethlambda:pq-local
    validator_count: 16
network_params:
  preset: mainnet
  gloas_fork_epoch: 0
  pq_fork_epoch: 0
  genesis_delay: 240
```

What the package does for ethlambda on a PQ network:

- It runs the beacon node as `ethlambda-pq beacon <flags>`: the supervisor
  starts the sidecar on a private socket, waits for it to listen, and runs
  the node on it, restarting the sidecar if it exits (see [Proofs](#proofs)).
  `LEANVM_THREADS` (through `cl_extra_env_vars`) caps the sidecar's threads.
- It passes the validator client `--init-slashing-protection` and, for its
  default mnemonic, the leanXMSS tree caches and VRF tree states it
  publishes for that mnemonic's first 10000 validators (`--xmss-cache-url`,
  `--vrf-state-url`). The client refuses a flag given twice, so
  `vc_extra_params` must not repeat them.
- Its genesis generator gives each validator the leanXMSS key and VRF seed
  the validator client derives from the BLS key. For another mnemonic, or
  past the published 10000, `ethlambda pq-keys --mnemonic ... --count N
  --output-dir keys` writes the key file the generator reads
  (`xmss_pubkey_url`) and the VRF states (`vrf_state_url`); every root
  hashes a whole tree, minutes a validator, and the run is resumable.

Limits worth knowing:

- **At least 32 validators** on the mainnet preset: gloas's `compute_ptc`
  asserts every slot has an attester, so with fewer, epoch processing fails
  at the first epoch boundary (`compute_balance_weighted_selection: total >
  0`) and the chain stops. The specification does the same.
- **Memory.** Every `leanvm-sidecar` warms up by proving twice and stays
  large. In Docker Desktop's default 8 GB VM a second sidecar next to
  Lighthouse's has had the kernel kill Lighthouse's. Set `LEANVM_THREADS` on
  nodes that only verify.
- **Lighthouse's envelopes over req/resp.** Its `pq-devnet-0` image (last
  checked at `sha256:f571048f`) answered
  `execution_payload_envelopes_by_{range,root}` with a gloas-shaped envelope
  under the PQ digest, which ethlambda refuses, so an ethlambda node that
  fell behind could not catch up from Lighthouse alone (it can from another
  ethlambda node). Gossip is unaffected.

What shows interop working: the beacon APIs agree on the head and finality;
ethlambda's `lean_beacon_gossip_validation_total` is all `accept` (blocks,
envelopes, aggregates with their proofs checked through the sidecar,
attestations, payload attestations, proposer preferences);
`lean_beacon_aggregate_total{outcome="applied"}` rises; every envelope is
`VALID` (`Execution payload envelope verified ... status=Valid`); every block
ethlambda's validator client publishes (`Published a PQ block`) is canonical
on the other clients, and their rejected-gossip counters stay empty for
ethlambda's messages.

## Spec fixtures

No consensus-specs release ships fixtures for either fork. The pyspec on the
`pq` branch generates them:

```sh
git clone https://github.com/ethereum/consensus-specs && cd consensus-specs
git checkout 2f43bc0f989f47af81df390a90bc1f78e2436323
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
- Merging ahead of a proposal: the aggregates a slot-`N` block may pack are
  all known a slot earlier, so a node could merge during slot `N - 1` for a
  proposer it serves, where today a slow merge costs every attestation but
  one.
- PQ block production does not weigh builder bids: it self-builds, and the
  PQ builder market it would read is filled but unused.
- The pubkey index cache keys a pubkey by bytes 1 to 9, all zero for a PQ
  key's request form: still correct (every candidate is verified, and a miss
  scans), but every PQ lookup scans.
