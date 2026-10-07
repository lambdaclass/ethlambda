# The mainnet wire

`ethlambda beacon` follows the Ethereum Beacon Chain's gossip. This page
describes what it puts on the wire; [`discovery.md`](./discovery.md) covers the
discv5 stack it shares with lean, and [`cli.md`](./cli.md) the flags and the
startup order.

It follows, from its checkpoint anchor to the tip: a chain actor imports what
gossip announces and what range sync fetches, and the two block protocols serve
other peers from the same store. Fork choice learns its votes from block bodies
and from the aggregate topic, which is how it sees votes for the *current* head
rather than only ones at least a block old; see [Aggregate
attestations](#aggregate-attestations). It publishes nothing. It also custodies
and serves a slice of the fulu data column matrix, and backbones a slice of the
attestation subnets, both sized and selected by its own node id; see [Data
column sidecars](#data-column-sidecars).

## Running it

```bash
ethlambda beacon \
  --node-key ./node-key \
  --gossipsub-port 9001
```

No flag is required, but that is only true for a built-in network:
`ethlambda beacon` on its own follows mainnet, since `--network` defaults to
`mainnet`. Sepolia, Hoodi and Platåberget are built in too, and any other network is a
`--network` naming a directory of published files (`config.yaml` and
`genesis.ssz`, see [`cli.md`](./cli.md)):

```bash
ethlambda beacon --network hoodi --checkpoint-sync-url https://checkpoint-sync.hoodi.ethpandaops.io
ethlambda beacon --network ./my-network --node-key ./node-key
```

`genesis_time` and `genesis_validators_root`, and therefore the fork digest,
are derived from the resolved network: a built-in network (`mainnet`,
`sepolia`, `hoodi`, `plataberget`) carries the two values as constants beside
its published `config.yaml` and bootnode list, and no genesis state; for a
loaded network they are read off that directory's own `genesis.ssz`. Nothing
about startup touches the network to get there. discv5 is forced on and needs no flag either: published mainnet
bootnodes are largely seed-only, so a crawl is how a peer is reached.

## The fork digest

Computed from the resolved network's genesis state and fork schedule, never
hardcoded as a digest. Startup derives the first one and a running node follows
the schedule from there (see below):

```
epoch        = (now - genesis_time) / (SECONDS_PER_SLOT * SLOTS_PER_EPOCH)
fork_version = the resolved network's fork schedule at epoch
base         = compute_fork_data_root(fork_version, genesis_validators_root)
digest       = base[..4]                                    if epoch <  FULU_FORK_EPOCH
             = xor(base, sha256(le64(bp.epoch) ++
                                le64(bp.max_blobs)))[..4]   if epoch >= FULU_FORK_EPOCH
```

`bp` is the latest blob-schedule entry at or before `epoch`, falling back to
`(ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK_ELECTRA)`. The fulu branch is
EIP-7892's, which is why mainnet's digest is `8c9f62fe` rather than fulu's bare
`82fae541`.

Startup logs the next boundary's epoch, wall-clock time, fork and digest. A
running node crosses it without a restart (`beacon::transition` in
`ethlambda-p2p`, driven by `beacon::fork_schedule`). Both fork activations and
blob-parameter-only forks move the digest, so both are boundaries. Following the
spec's "Transitioning the gossip" rules, the next digest's topics are joined
`SUBSCRIBE_LEAD_EPOCHS` before its boundary and the previous digest's topics
are left `UNSUBSCRIBE_LAG_EPOCHS` after it. At the boundary the node
publishes and advertises the new digest, bumps its metadata sequence number
and moves its discv5 admission filter. While the window is open a gossip
message's fork comes from its own topic's digest, and a `Status` on either
digest is answered, but range sync starts only from a peer on the current
digest (or the next one, within clock skew of the boundary).

One gap: the ENR this node serves over discv5 keeps the `eth2` entry it started
with, because ethrex's `DiscoveryServer` offers no way to replace its record at
runtime. Peers already connected are unaffected; peers discovering the node
after a boundary read the stale digest and reject the record.

## Gossip

Seven global topics, `/eth2/{digest}/{name}/ssz_snappy`, plus two subnet
families this node's own node id selects a narrow slice of: the data column
subnets it custodies and the attestation subnets it backbones, both described
below. A gloas digest adds four more, `execution_payload`,
`payload_attestation_message`, `execution_payload_bid` and
`proposer_preferences`, which `BeaconTopics::for_fork` subscribes under gloas
digests and not under earlier ones (so one epoch before the fork, when the
digest is joined). An envelope is validated like a block
(its stateful half on the blocking pool) and goes to the chain actor on `Accept`
and on `Queue`, since the actor holds an envelope whose block is not imported
yet. A payload attestation is validated on the attestation permit pool and goes
to the actor on `Accept` only: a vote for a block not imported here is dropped,
since it is valid only within its own slot. Bids and preferences are the
builder market: they never reach the chain actor. Their rules live in
`state_transition::beacon::gossip::{execution_payload_bid, proposer_preferences}`,
the cheap half runs in p2p's triage (`p2p/src/beacon/builder_market.rs`) and the
stateful half on a permit pool of their own (`builder_validation_permits`), so
a bid burst cannot starve blocks, columns or attestations. Whatever is accepted
goes into the node's one shared `BuilderMarket`, which the Beacon API and block
production read. Neither is ever queued: a message whose parent or dependent
block is unknown is ignored. A bid is capped at 196,932 decompressed bytes
(`Reject(Malformed)` above that). The node publishes both: a bid on the digest of
its slot, preferences on the digest of the proposal slot, which in the epoch
before gloas is the gloas digest already joined. Envelopes the node publishes
itself are recorded as known payloads, since gossip never echoes them.

| Topic | Decoded as |
| --- | --- |
| `beacon_block` | `SignedBeaconBlock`, fork chosen by the block's slot |
| `beacon_aggregate_and_proof` | `SignedAggregateAndProof`, phase0, electra or gloas |
| `attester_slashing` | `AttesterSlashing`, phase0 or electra |
| `voluntary_exit` | `SignedVoluntaryExit` |
| `proposer_slashing` | `ProposerSlashing` |
| `bls_to_execution_change` | `SignedBLSToExecutionChange` |
| `sync_committee_contribution_and_proof` | `SignedContributionAndProof` |
| `beacon_attestation_{subnet_id}` | `Attestation`, phase0 or electra's `SingleAttestation` (gloas keeps the latter) |
| `execution_payload` | `SignedExecutionPayloadEnvelope`, gloas digests only |
| `payload_attestation_message` | `PayloadAttestationMessage`, gloas digests only |
| `execution_payload_bid` | `SignedExecutionPayloadBid`, gloas digests only |
| `proposer_preferences` | `SignedProposerPreferences`, gloas digests only |

`beacon_attestation_{0..63}` is no longer wholly unsubscribed. This node holds
`SUBNETS_PER_NODE` (2 on mainnet) long-lived subscriptions from that family,
chosen by `compute_subscribed_subnets(node_id, epoch)`, a public function of
this node's own discv5 node id in the same way `custody_columns` is, so any
peer can compute the set without asking. `p2p-interface.md` asks every beacon
node to hold them whether or not it runs validators: phase 0 has no shard
committees, so nothing else gives these subnets a stable membership for
validators to publish into. The subscription is therefore owed to the network
rather than to this node's head: this node verifies and relays what arrives on
it (see [Gossip validation](#gossip) below) but never applies it to fork
choice. A lighthouse node with no validators behaves the same way, subscribing
to its own node-id backbone and verifying what arrives on it while
`should_process_attestation` keeps it out of fork choice unless a local
aggregator duty or `--import-all-attestations` says otherwise.

One deliberate shortfall: the set is computed once at startup and kept for the
process's lifetime rather than rotating every `EPOCHS_PER_SUBNET_SUBSCRIPTION`
epochs. Lighthouse does the same, and reads that constant nowhere.

`sync_committee_{0..3}` stays unsubscribed and arrives with the work that reads
it. `blob_sidecar_{subnet_id}` stays absent permanently: it is deneb's format
for blobs, deprecated at fulu in favor of the column matrix below.

`data_column_sidecar_{0..127}` is no longer in that absent list. This node
subscribes to `sampling_size(CUSTODY_REQUIREMENT)` of them — the sampling size
floored by `SAMPLES_PER_SLOT` above `CUSTODY_REQUIREMENT` itself — chosen by
`custody_columns(node_id, …)`, a public function of this node's own discv5
node id (`das-core.md`), so any peer can compute the same set without asking.
`NUMBER_OF_CUSTODY_GROUPS` and `DATA_COLUMN_SIDECAR_SUBNET_COUNT` are equal
today, so a column is its own subnet with no reduction. That makes this
node's total subscription count the seven global topics plus its sampling size
plus `SUBNETS_PER_NODE`, still far short of a full subscription to every
attestation, sync-committee and data-column subnet, and narrower still than
`NUMBER_OF_CUSTODY_GROUPS` columns of custody, which is what a supernode
would carry alone. A sidecar decodes as
the fork-agnostic `DataColumnSidecar` enum, its fork taken from the topic's
digest (the bytes carry no tag): fulu's names its block by a signed header and
inclusion proof, gloas's by a slot and block root, with the commitments it is
checked against living in that block's bid. The checks it passes before this node keeps or
forwards it are described just below. How a kept sidecar is later served back
out over req/resp is under [Data column sidecars](#data-column-sidecars).

Every beacon message is held by gossipsub until it has a verdict
(`validate_messages()` is on for this wire only). Blocks, data column
sidecars, aggregates and subnet attestations are all validated by fulu's
gossip rules, or gloas's modified ones from the fork on (`ethlambda_state_transition::beacon::gossip`, one module per
topic family): the checks that need no state run inline in the p2p actor, the
rest on a bounded `spawn_blocking` task whose verdict comes back to the actor
(`crate::beacon::verdict`). Two permit pools bound how many of these run at
once, so a burst on one family cannot starve another:
`gossip_validation_permits` for blocks and columns,
`attestation_validation_permits` for aggregates and subnet attestations. A
mainnet slot carries up to `MAX_COMMITTEES_PER_SLOT *
TARGET_AGGREGATORS_PER_COMMITTEE` aggregates alone, arriving every slot rather
than only during a range sync, which is why that traffic needs a pool of its
own rather than sharing the block and column one. Accept propagates the
message; a message whose dependency is not ready yet is IGNOREd. See
[Aggregate attestations](#aggregate-attestations) for the two topics with
their own section.

Blocks and data column sidecars are, either way, handed to the chain actor,
which parks what it cannot import yet and imports the rest immediately, such
as a sidecar whose slot merely falls outside its parent state's proposer
lookahead. An aggregate reaches the chain actor only on `Accept`, carrying the
attesting indices gossip validation resolved. A subnet attestation never
reaches it at all, on any outcome: verifying and relaying it is the whole of
what this node owes the topic (see above), so there is nothing further for the
chain actor to do with one.

The rules above are fulu's, except that blocks, data columns, aggregates and
subnet attestations also have gloas rules. A gloas aggregate has electra's bytes
but its own progressive `Attestation`, so it decodes to its own
`SignedAggregateAndProof::Gloas` (the signed root differs); a gloas subnet
attestation is electra's `SingleAttestation` unchanged. In both, `data.index` is
the payload flag (0 or 1), and a vote for the full payload (1) is IGNOREd until
the block's envelope has been seen and its payload validated
(`verify_attestation_payload_status`). Gloas is a followed fork, so a block at
a gloas slot that fails to decode is REJECTed like one at any other followed
fork; `unsupported_fork` is kept for a fork the node does not follow
(`ForkName::is_followed`), none today. A gloas aggregate's aggregation bits are
an unbounded progressive bitlist, so one longer than electra's type bound is
REJECTed first, reading its length without expanding it, since expanding is
what the seen-set check does before any other.

Three deliberate departures from the gloas gossip rules, each for want of state
this node does not keep. Where the specification rejects a message whose block
failed validation, this node (having no bad-block cache) cannot tell that from
a block it has not finished importing, so it queues or ignores instead; the
matching `reject_block_failed_validation` vectors are in `SKIPPED`. An
`execution_payload` whose block state is not in the cache p2p reads (a parent
imported moments ago, say) is queued and forwarded to the chain actor, which
verifies every envelope itself, without being propagated. And a
`payload_attestation_message` is applied to fork choice after p2p verified its
signature, with the actor re-checking only the store-state conditions (known
block, current slot, committee seat).

The remaining five global topics are decoded, logged at `debug`, and IGNOREd,
since nothing consumes them; an undecodable payload on any topic is REJECTed.
Nothing is published on any topic, columns included: nothing this node can
produce today would be signature-valid.

## Aggregate attestations

`beacon_aggregate_and_proof` reaches fork choice. It is how a follower learns
votes for the *current* head rather than only the votes a block body carries,
which are always at least one block old. `beacon_attestation_{subnet_id}`,
covered in the same section below, never does: this node relays its backbone
subnets without ever applying what arrives on them.

Both topics are validated the same way blocks and columns are, in
`ethlambda_state_transition::beacon::gossip::{aggregate,attestation}`: cheap
conditions (seen cache, propagation window, `data.index == 0`, exactly one
committee named) run inline in the p2p actor; the rest run on a blocking
thread, in this order:

1. The vote's block is known (`Store::has_block`); if not, IGNORE.
2. **Committees, signatures and ancestry all resolve against the vote block's
   own cached post-state**
   (`store.cached_state(CacheKey::BlockState(beacon_block_root))`), not the
   specification's head state and not the target checkpoint's state either.
   Three reasons converge: it is the attested chain's own state, so its
   shuffling is the one the attesters were actually assigned, where the head
   (or a checkpoint reached by replaying a different branch) can name the
   wrong one; it is an `O(1)` cache read rather than a lookup or a replay; and
   its own `block_roots` answers both ancestry questions without a
   `Store::block_index` / `LiveChain` scan.
3. The signatures that need only a pubkey, before any committee derivation: an
   aggregate's selection proof and aggregator signature, an attestation's own
   signature. An unknown validator index REJECTs here rather than paying for a
   committee lookup first, since a forged message must not be able to reach a
   shuffling derivation.
4. The committees, through the `Store`-held cache both actors share; then
   `is_aggregator` (rewritten to take a committee length rather than a
   pre-fetched cache), committee membership, and, for a subnet attestation, the
   subnet match (`compute_subnet_for_attestation`).
5. An aggregate's own signature, over the indexed attestation built from that
   committee. The indices it verifies travel to the chain actor; it never
   rebuilds them.
6. Ancestry against the vote state's `block_roots`: the target is the vote
   block's ancestor at the target epoch (REJECT), and the finalized checkpoint
   is an ancestor of the vote block (IGNORE).

The seen caches (`SeenAggregates`, keyed both by `(target_epoch,
aggregator_index)` and by `(hash_tree_root(data), committee_index)`;
`SeenAttestations`, by `(target_epoch, attester_index)`) live in p2p now,
recorded only on `Accept` by `verdict::settle`, and are bounded by capacity
(an LRU, like the block and column seen caches) rather than pruned on
finality: a peer must not get to grow either one just by outlasting
finalization. Recording only after the signatures verify is still what keeps a
garbage aggregate from being able to censor a genuine one for the rest of the
epoch by claiming its `(epoch, aggregator)` pair first; lighthouse splits the
same way, reading its observed-sets in `verify_early_checks` and writing them
in `verify_late_checks`.

Only an aggregate that gossip `Accept`s reaches the chain actor, carrying the
attesting indices already resolved; the actor never re-derives a committee or
checks a signature for this topic. What is left for it:

- **A lighter, actor-local applied-bits gate**, a running union of aggregation
  bits already applied per `(target_epoch, hash_tree_root(data),
  committee_index)`. Not a spec seen-set (p2p owns that one now); it exists so
  a committee's other aggregators, each individually accepted by gossip
  because each is a first-seen, valid message, do not all pay for
  `apply_verified_aggregate` when the first one already covered their bits.
  Pruned by the store's own clock to the current and previous epoch, not by
  finality, so a stalled chain cannot make this grow without bound either.
- **The deferral queue.** `validate_on_attestation` requires
  `get_current_slot(store) >= data.slot + 1`, and aggregates are published two
  thirds of the way through the slot they vote for, so every one arrives too
  early. Without the queue this topic would apply approximately nothing. It
  drains once per beacon tick, between the clock advancing and the head being
  recomputed, so released votes are in fork choice before that tick's head is
  chosen. The specification licenses this directly ("consider scheduling it for
  later processing in such case") and lighthouse has the same queue. Held
  entries now carry their gossip-resolved attesting indices alongside them, so
  a drain applies them without recomputing anything.

A subnet attestation is fully verified by this same pipeline and then simply
dropped: nothing forwards it to the chain actor, on any outcome, matching a
lighthouse follower with no validators, which verifies and relays its own
backbone subnets while `should_process_attestation` keeps them out of its fork
choice.

## Request/response

| Protocol | Direction |
| --- | --- |
| `status/1`, `status/2` | both |
| `ping/1` | both |
| `metadata/1`, `metadata/2`, `metadata/3` | both |
| `goodbye/1` | inbound; the reason code is logged and the stream closed |
| `beacon_blocks_by_range/2` | both |
| `beacon_blocks_by_root/2` | both |
| `data_column_sidecars_by_root/1` | both |
| `data_column_sidecars_by_range/1` | both |
| `execution_payload_envelopes_by_range/1` | both |
| `execution_payload_envelopes_by_root/1` | both |

The two data column sidecar protocols are registered because this node
custodies the columns its node id selects and can answer for them out of
`Table::DataColumns` (see [data_storage.md](./data_storage.md)); see
[Data column sidecars](#data-column-sidecars) for what each serves and asks
for. The blob sidecar protocols stay absent: nothing here custodies a whole
blob, only the erasure-coded columns fulu derives it into, and a registered
protocol with no implementation behind it is an untested encoder peers can
reach.

Only version 2 of the two block protocols is registered. Version 1 is deprecated
by the spec, which lets a client answer it with an empty list, and its chunks
carry no `<context-bytes>`, so serving it would mean a second response encoder
for a shape no mainnet peer needs.

The `Status` this node sends is derived from its anchored store, so a peer
reading it has a reason to ask for the blocks the two block protocols serve.
There is one window where every checkpoint is still zero, before fork choice has
inserted the block `KEY_HEAD` names; lighthouse's relevance check exempts a zero
`finalized_root`, so that reads as "peer is syncing" rather than as a
conflicting chain. Either way it is answered in the version the stream asked
for: a v1 body on a v2 stream is eight bytes short and the codec refuses to
write it, which drops the connection of every peer that opens the handshake on
`status/2`.

### The two block protocols

Both request bodies have a shape that cannot be guessed from the response they
produce:

| Protocol | Request body | On the wire |
| --- | --- | --- |
| `beacon_blocks_by_range/2` | `(start_slot, count, step)` | 24 bytes, an SSZ **container** |
| `beacon_blocks_by_root/2` | `List[Root, MAX_REQUEST_BLOCKS]` | `32 * n` bytes, an SSZ **field** |

`step` is deprecated and must be 1, but it is still on the wire: altair says the
v2 request is unchanged from phase0's, and lighthouse pins this protocol's
request length to `min == max == 24 bytes`, so a two-field body is refused before
it is ever decoded. A body naming any other `step` is answered with
`INVALID_REQUEST`, not dropped: the field is carried up to the handler precisely
so the peer learns which rule it broke, where refusing at decode would close the
stream with nothing on it. Phase0 does permit answering a larger step with a
single block, but that leniency is for a transition that finished years ago, and
the spec's requirement on the requester is a MUST.

The root request is a bare list with no container around it, because the spec
says this body "MUST be encoded as an SSZ-field" where the range body is "an
SSZ-container". The difference shows up on the wire: a container holding one
variable-length field prefixes it with a four-byte offset.

**Neither of those differences reaches above the codec.** What a peer is asking
for is the same question on either chain, so `req_resp::messages` owns the
shared `BlocksByRangeRequest`, and each chain's encoder converts to and from its
own wire container: lean's has no `step` and fills it with 1 on the way in,
beacon's carries all three fields. The shared struct is deliberately not
SSZ-derived, so it cannot be written to either wire by accident. The root list
needs no conversion at all, since `beacon::primitives::Root` *is* `H256` and
both lists are `SszList<H256, 1024>`; only lean's container comes off.

Which chain a request arrived on is not on the message either: a node speaks one
wire for its whole life, so the dispatch reads `Wire::is_beacon` instead. The
same holds for the answer. `ResponsePayload::Blocks` is one variant for all four
block protocols, because `SignedBeaconBlock` already carries a `Lean` variant
and both stores hand blocks back in exactly that type. The narrowing to lean's
own `SignedBlock` happens once, where a fetched block is handed to the chain
actor, and `lean::encoding::write_blocks_response` refuses to put a block of any
other fork on a lean stream.

Two ceilings apply, and they are not the same number. `MAX_REQUEST_BLOCKS`
(1024) is what an inbound request is judged against, because it is the widest a
peer may ever legitimately have been built to ask for; a `count` above it is
refused as `INVALID_REQUEST`. `MAX_REQUEST_BLOCKS_DENEB` (128) is what an
outbound request is built to and what an answer is truncated to, since the spec
allows "Clients MAY limit the number of blocks in the response" and a peer
asking for more than 128 is running older logic rather than misbehaving.

A range answer comes off the canonical branch in ascending slot order, with
empty slots skipped: `BlockRoots` holds one root per slot on the branch ending
at the current head, so a sibling block at a slot the head does not descend from
is never read. A root answer follows the order the roots were asked in, and
leaves out any root this node does not hold.

### Context bytes

Every successful block chunk carries a four-byte `ForkDigest` between the result
byte and the payload:

```text
response_chunk ::= <result> | <context-bytes> | <encoding-dependent-header> | <encoded-payload>
```

The digest is the one that block's own epoch computes to, not the one this node
is running on, so a backfill labels each chunk with its own fork. On an error
chunk the field is empty, which is why the reader only reads it after a SUCCESS
byte. Serving history therefore needs `genesis_validators_root` as well as the
current digest, which is why `BeaconWire` and the codec both carry it.

Going the other way, the fork a chunk decodes under comes from the **slot inside
the payload**, through the same decode path gossip uses, and the context bytes
are then checked against the digest that slot implies. That is a stronger test
than using them as the decoder key: it catches a peer whose
`genesis_validators_root` or fork schedule differs from ours, which is exactly
what the digest exists to say and is not otherwise visible until a signature
fails. A mismatch ends the stream, logged at `warn` with both digests: the one way to
reach it in good faith is a blob schedule of ours that has fallen behind the
network's.

### Execution payload envelopes

Both gloas envelope protocols are registered `Full`: the server answers, and
the client (`req_resp/envelope_client.rs`) asks. A chunk carries one
`SignedExecutionPayloadEnvelope` under the fork digest of its block's epoch.
The envelope has no slot of its own, so the epoch comes from
`payload.slot_number`, which `verify_execution_payload_envelope` pins to the
block's slot. A chunk whose digest names no gloas-or-later scheduled fork, or
not the digest its slot implies, ends the stream.

| Protocol | Served from |
| --- | --- |
| `execution_payload_envelopes_by_root/1` | a point lookup per root in `Table::ExecutionPayloadEnvelopes`; unknown roots are left out, answers follow the order asked |
| `execution_payload_envelopes_by_range/1` | the canonical blocks of the window (`BlockRoots`), each envelope kept only when the next canonical block builds on its payload; the head's own envelope only when the head node is FULL (`Store::head_payload_status`, which pairs the status with the head root it describes, so a stale status reads as unknown and the envelope is withheld) |

Both are bounded by `MAX_REQUEST_PAYLOADS`: a by-root list over it fails to
decode, and a by-range `count` over it is truncated, which the specification's
"Clients MAY limit the number of payload envelopes in the response" allows.
A by-range request starting below `Store::anchor_slot` gets
`RESOURCE_UNAVAILABLE`, and a window before gloas is simply empty.

The client asks in two situations. By root: the chain actor's
`FetchRequest.needs_envelope` (a block whose child waits on its payload) starts
a lookup with the block fetch's dedup, peer choice and retry ladder; a give-up
is recovered by the actor's per-slot re-ask. By range: after a
`beacon_blocks_by_range/2` answer for a span that reaches gloas has been handed
to the actor, the same peer is asked for that span's envelopes, and range sync
holds the next block request until that answer is checked and forwarded (or has
failed). The pause exists because the actor keeps an envelope whose block has
not imported only briefly and in small numbers, so a batch's envelopes must
arrive before the next batch's blocks do. Everything fetched goes through the
same rules as an `execution_payload` gossip message
(`beacon/envelope_checks.rs`) before the actor sees it; a `Queue` verdict is
forwarded too.

### Data column sidecars

Both protocols are registered `Full`, since with the columns on disk this node
can serve every slot it has custodied:

| Protocol | Served from |
| --- | --- |
| `data_column_sidecars_by_root/1` | a point lookup per identifier: the slot is recovered from `BlockHeaders` off the named root, then each requested column is read straight out of `Table::DataColumns` |
| `data_column_sidecars_by_range/1` | a prefix scan over the slot range, restricted to each slot's canonical root (`BlockRoots`) and filtered to the requested columns |

Restricting the range answer to the canonical root matters because
`Table::DataColumns` is never pruned and gossip only asks that a sidecar's
block name a known, finalized-descendant parent, not a canonical one: a live
fork can leave both siblings' columns stored at the same slot, and an
unscoped scan would leak the losing side into every future range answer
covering it.

Both per-item lookups are lenient the way the block protocols are: a column
this node never custodied, or a root it holds no header for, is left out of
the answer rather than turned into an error, since the spec's own words are
"Clients MUST respond with at least one sidecar, if they have it." A
`data_column_sidecars_by_range/1` request starting before `Store::anchor_slot`
gets `RESOURCE_UNAVAILABLE` instead of a merely-empty answer, the same
distinction the block-range handler draws and for the same reason: an empty
window this node's canonical chain skipped is normal, but a window below where
this node's chain begins cannot be served from any point onward. That floor is
the same value `Status` advertises as `earliest_available_slot`, so the refusal
and the advertisement cannot disagree.
`max_request_data_column_sidecars()` (`MAX_REQUEST_BLOCKS_DENEB *
NUMBER_OF_COLUMNS`) bounds what one request may ask for; an answer over that
is truncated, not refused, matching how the block protocols treat a peer
built to an older, wider ceiling.

*Asking* happens on two paths, bulk and per block.

The bulk one rides with range sync: every `BeaconBlocksByRange` batch sends a
`data_column_sidecars_by_range/1` for the same slot span, covering this node's
whole custody set. The spec names this protocol for exactly that —
"`DataColumnSidecarsByRange` is primarily used to sync data columns that may
have been missed on gossip and to sync within the
`MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` window" — and it is what keeps a
follower backfilling from a checkpoint anchor from needing the per-block path
at all: the columns are normally already stored by the time their block reaches
the availability gate. Nothing waits on the answer, so a short, empty or
refused one costs nothing and is not retried; the per-block path is the
backstop.

Since the column request is aimed by custody, a batch whose last slot is fulu
or later is held back, blocks included, until every custody column has a known
custodian among the connected peers. Lighthouse's range sync holds its batches
the same way.
Right after startup, custody is known for almost no peer, since a peer's
custody arrives with its `metadata/3` answer after it connects. A mainnet
follower's first batch after a fresh checkpoint sync went out 5 s after
startup with two peers and at most one known custodian per column, and 121 of
the 122 holds it caused were missing every custody column. The
batch is re-checked after every metadata answer and every `Status` answer, and
it goes regardless once `RANGE_BATCH_CUSTODY_WAIT` has passed, because nothing
here searches for a custodian of a specific column; past that deadline the
uncovered columns go to a couple of peers whose custody is unknown, as before.

The per-block one starts at `hold_block_for_columns`, called when a
fulu block carrying commitments arrives short of the columns this node
custodies for it. Import holds the block — it stays out of fork choice, but
its header, body and proof are already written, the same way a block missing
its parent is held. What happens next depends on the block's age. A block
still at or ahead of the current slot asks for nothing yet: its columns are
published alongside it, so the rest are normally already in flight on gossip,
and a peer asked at that moment usually does not have them either; on mainnet
followers at the tip, gossip completed a held block within 0.3 s at p99. A
block already older than the current slot has no such gossip left to race,
since whatever delivered it did so long before this node held it, so it sends
`data_column_sidecars_by_root/1` immediately instead: a range-synced catch-up
hits this on every held block, and without it such a follower imported
roughly one block per slot, waiting out the redrive below for a request
gossip was never going to answer. Either way, `redrive_held_blocks` runs on
every slot tick: for each block still held it sends the same request for
exactly the columns still missing, with
`MAX_FETCH_RETRIES` attempts and backoff doubling from `INITIAL_BACKOFF_MS`, a
peer that has already failed this lookup excluded until the whole pool is
exhausted. A lookup that runs out of peers or
retries stops asking until the next tick asks again; see
`lean_data_column_fetch_failures_total` in [metrics.md](./metrics.md). The
block is released the moment its last missing column arrives, and dropped
along with any pending descendants once finality passes its slot, whichever
comes first — nothing else times out a hold, so a peer that claims commitments
and never answers pins the block only until finality clears it, not
indefinitely.

Both asking paths aim per column rather than per peer. A peer's custody set is
a public function of its node id and its advertised custody group count, so
this node computes it and sends each column to someone who actually holds it —
the spec's own observation that "due to the deterministic custody functions, a
node knows exactly what a peer should be able to respond to". The count comes
from `metadata/3`, requested once per connection right behind `Status`, and is
seeded from the ENR `cgc` for a peer this node dialed; a peer that has supplied
neither is not assumed to custody anything, and the by-root path falls back to
asking one at random for whatever no known custodian covers. At mainnet's
`CUSTODY_REQUIREMENT` a peer holds 8 of 128 columns, so this is the difference
between a request that can be answered and one that usually cannot.

What this node deliberately does not do with its own slice of the matrix: it
does not run `compute_matrix` or `recover_matrix` to reconstruct the rest of a
block's data from it, since reconstruction needs half of
`NUMBER_OF_CUSTODY_GROUPS` and this node never holds more than its own
sampling size; and, over req/resp, it does not cross-seed a verified column to
a peer that never asked for it: every sidecar this node sends over
`data_column_sidecars_by_{root,range}` leaves in direct answer to that peer's
own request. Gossip is the one path where the same column *is* an
unsolicited push by design: an Accept verdict (see [Gossip](#gossip) above)
both hands the sidecar to the chain actor and re-propagates it to every mesh
peer, whether or not any of them asked for it.

### What is not wired yet

Serving both protocols is live, off the checkpoint-anchored store, and so is
asking on both. A request
that reaches a node whose data directory is *not* a beacon one is refused with
`RESOURCE_UNAVAILABLE`, the spec's own code for a peer "unable to reply to block
requests", where `INVALID_REQUEST` would blame the asker for a request that was
fine. That guard is for a lean directory, not for the ordinary case.

*Asking* is now driven from two places. A peer's `Status` starts a range
session, which sends through `request_beacon_blocks_by_range`; and
`Handler<FetchBlock>` reaches `request_beacon_block_by_root` through
`fetch_block_from_peer`, which picks its protocol from the wire so a beacon
node cannot put a lean-framed `BlocksByRoot` on its beacon streams.

Both paths now import. A fetched block reaches the chain actor as
`BlockSource::Sync`, keeping every per-block range and root check on the way in,
and the by-root path is what resolves a gossiped block's missing parent.

Range sync is paced by `P2PServer::beacon_fetched_through`, the highest slot
handed to the actor, not by the store's head. Delivery is a message and import
is work, so the store trails a delivered batch by the whole actor mailbox.
Driven off the head, every resync tick re-requested the part still draining,
which on the live follower meant 11,213 blocks off the wire to import 100, each
duplicate paying a `hash_tree_root` before the store could reject it. Paced off
the watermark, the ratio was 1.7:1.

`Status` is store-derived: head from `Store::beacon_head`, the finalized
checkpoint from `Store::beacon_finalized_checkpoint`, and
`earliest_available_slot` from the anchor's own slot rather than
`finalized_epoch * SLOTS_PER_EPOCH`, since this node keeps only the unfinalized
window above its anchor and the epoch's first slot is not necessarily one it
holds. Naming that slot tells a peer not to ask for anything older; naming zero
would claim genesis is in reach. There is one window where `beacon_head` answers
`None`, between `init_beacon` seeding `KEY_HEAD` and fork choice inserting the
block that root names, and every field but the fork digest falls back to zero
there. That stays honest: lighthouse's relevance check exempts a zero
`finalized_root` from its finalized-root comparison, reading it as "this peer is
syncing" rather than as a conflicting chain.

## The ENR

| Entry | Value |
| --- | --- |
| `eth2` | the computed `ENRForkID` |
| `attnets` | 64 bits, with this node's `SUBNETS_PER_NODE` backbone subnets set |
| `cgc` | `CUSTODY_REQUIREMENT` |
| `quic` | `--gossipsub-port` |
| `tcp` | `--gossipsub-port`, the same number: TCP and UDP are separate namespaces |
| `udp` | `--discovery.port` |

Two of these advertise less, or more, than they look like:

- `attnets` names exactly the subnets this node subscribed to, which is the
  only honest value: claiming one it does not serve earns peer-score penalties
  for silence there, and claiming none while serving two loses the peers
  looking for precisely that. It used to be all-unset, which was honest while
  this node held no subscription at all.
- `cgc` advertises `CUSTODY_REQUIREMENT`, the floor below which peers may
  reject a record outright, not `sampling_size(CUSTODY_REQUIREMENT)`, the
  larger number of columns this node actually custodies, stores and serves
  (see [Data column sidecars](#data-column-sidecars)). That undersells rather
  than oversells: a request for more than `cgc`'s worth of columns still
  succeeds, since this node holds every column its own node id assigned it at
  the sampling size, not merely `cgc`'s worth.

The `tcp` entry is what makes us discoverable in return: lighthouse's discovery
predicate requires `enr.tcp4().is_some() || enr.tcp6().is_some()` and applies it
as a query filter, so a `quic`-only record is invisible to it.

## Metrics

| Metric | Meaning |
| --- | --- |
| `lean_beacon_gossip_messages_total{topic,result}` | Gossip received, by topic and by `decoded` / `decode_failed` / `decompress_failed` / `unsupported_fork` |
| `lean_beacon_gossip_validation_total{kind,outcome,reason}` | Gossip verdicts, now including `beacon_aggregate_and_proof` and `beacon_attestation`; see [metrics.md](./metrics.md#beacon-gossip-validation) |
| `lean_beacon_gossip_verdict_expired_total{kind}` | Verdicts that came too late to propagate anything; should stay at zero |
| `lean_beacon_status_digest_mismatch_total` | Handshakes seen from another fork digest |
| `lean_beacon_fork_digest{digest}` | The digest computed at startup, as a label |
| `lean_beacon_aggregate_decode_seconds` | Time spent decoding one aggregate off the wire |
| `lean_beacon_aggregate_mailbox_wait_seconds` | How long an aggregate sat in the chain actor's mailbox |
| `lean_beacon_aggregate_processing_seconds` | Time the chain actor spent applying one already-verified aggregate |
| `lean_beacon_aggregate_end_to_end_seconds` | Wire to fork choice, for aggregates applied on arrival |
| `lean_beacon_aggregate_total{outcome}` | Aggregates by `applied`, `invalid`, `known_subset` or `queue_full` |
| `lean_beacon_aggregates_deferred` | Aggregates held until their own slot has passed |

The four aggregate histograms no longer cover what they used to: gossip
validation (committees, all three signatures, the seen caches) runs in p2p now
and is folded into `lean_beacon_gossip_validation_seconds{kind="beacon_aggregate_and_proof"}`
instead. `decode` is p2p's own decode step; the other three, all in
`ethlambda-blockchain`, now measure only `apply_verified_aggregate` and the
actor's applied-bits gate, which is why `processing` reads far lower than it
used to. `mailbox_wait` is still the one that cannot be derived any other way,
and it is still the failure mode this path introduces: roughly a thousand
aggregates a slot (verified ones only, now) queueing behind block imports arrive too
late to move the head while every other timing still looks healthy.

The `lean_` prefix is the repo-wide convention and applies here too. Data
column sidecar metrics (`lean_data_columns_stored_total`,
`lean_data_columns_rejected_total`, `lean_data_column_kzg_verify_seconds`,
`lean_data_column_fetch_failures_total`, `lean_blocks_held_for_columns`) and
the disk-growth gauge for
`Table::DataColumns` (`lean_table_bytes{table="data_columns"}`) are documented
in full in [metrics.md](./metrics.md) rather than repeated here.

`ethlambda beacon` serves these on `--metrics-port`, alongside `/health` and
the `/debug/pprof` heap-profiling routes, through the same `start_rpc_server`
entry point `ethlambda node` uses: one HTTP call site in `run_node` serves both
chains. It also binds `--api-port` and mounts the `/lean/v0` API, off the empty
in-memory `Store` and the default `AggregatorController`, `SyncStatusController`
and `EventBus` this startup path hands it. Those routes answer for a chain that
is not running; treat `/metrics` as the only meaningful HTTP surface of a
`beacon` run until the follower gets an API of its own.

## Checking it against the live network

No unit test can assert "peers with mainnet", so this is the procedure.

```bash
openssl rand -hex 32 > /tmp/beacon-node-key
RUST_LOG=info,ethlambda_p2p=debug \
cargo run --profile release-fast -p ethlambda --bin ethlambda -- beacon \
  --node-key /tmp/beacon-node-key \
  --gossipsub-port 9001
```

Within 5 seconds:

```
Derived the mainnet wire parameters  genesis_time=1606824023 genesis_validators_root=0x4b363db9… epoch=… fork=fulu fork_digest=8c9f62fe
No fork or blob-schedule boundary is scheduled
Custodying data columns  columns=[…]
Backboning attestation subnets  subnets_per_node=2 subnets=[…]
Advertising cgc=4 while subscribing to no sync committee subnet, and publishing nothing
Beacon P2P node started  socket=0.0.0.0:9001 fork_digest=8c9f62fe topics=17 columns=8 attestation_subnets=[…]
HTTP server listening  addr=127.0.0.1:5054
Starting discv5 discovery  discovery_addr=0.0.0.0:9002 seeds=17 total_bootnodes=17
Local ENR  enr=enr:-…
```

The `Advertising cgc=…` line names what is still true: this node subscribes to
no sync-committee subnet and publishes nothing of its own. Storing and serving
the columns it custodies (see [Data column
sidecars](#data-column-sidecars)) is no longer part of that gap, and neither is
the attestation subnet backbone.

`seeds=17` proves the built-in list parsed; a lower number means a bootnode
ENR was skipped with a warning. `topics=17` proves the subscription set: the 7
global topics, the 8 column subnets this run's (randomly generated) node id
selected, and the 2 attestation subnets the same id selected; `columns=8` and
`attestation_subnets=[…]` confirm the two families directly.

Within 30 seconds:

```
External IP detected via PONG voting, updating local ENR  old_ip=0.0.0.0 new_ip=…
Beacon block decoded  slot=… proposer=… fork=fulu block_root=… bytes=…
Beacon aggregate attestation decoded  slot=… aggregator=… attesters=… target_epoch=… target_root=… bytes=…
```

A measured run on 2026-08-31, from a laptop behind NAT with no port forwarding,
reached its first decoded block 16 seconds after start and its first aggregate
at 24 seconds, then took a block every slot. `bytes` on mainnet is typically
100 KB to 310 KB for a block and about 500 for an aggregate, and `attesters`
sits in the low hundreds. Peer lifecycle lines (`Peer connected`, `Beacon
handshake complete`) are at `trace`: at mainnet peer counts they are what
drowned the log, so raise the level to see them.

What each failure looks like:

| Symptom | Cause |
| --- | --- |
| `Peer said goodbye reason=129` right after a connection | nothing local: 129 is lighthouse's `TooManyPeers` |
| `fork_digest` is not what a live crawl reports | the blob-schedule branch, or the schedule itself |
| connections but no `Beacon handshake complete` | the `Status` encoding, or answering the wrong version |
| `Handshake answered from another fork digest` | the digest |
| `Beacon gossip decode failed` for `beacon_block` | the fork selection or the slot offset |
| the same for `beacon_aggregate_and_proof` alone | the electra boundary in `decode_gossip`; the block path is fine |
| connected peers above zero, no gossip at all | the topic hash: almost always the digest's hex formatting or `compute_message_id` |
| every candidate rejected as `missing or undecodable eth2 entry` | see below |

### Both transports, not just QUIC

ethlambda used to dial QUIC only, against the `quic` port a peer's ENR
advertises. Most mainnet beacon nodes are reachable over TCP and advertise a
`quic` entry that does not answer, either because the node is behind a NAT that
forwards only TCP or because QUIC is disabled behind an advertised port. The
result was a long run of `Handshake with the remote timed out` against otherwise
valid, correctly admitted peers.

The node now listens on and dials both transports, and admission accepts a peer
advertising either, so a dead `quic` entry falls back to TCP within the same
dial rather than ending it. The TCP transport offers mplex alongside yamux
because mainnet peers answer `na` to a yamux-only proposal; see the `muxers`
module in `crates/net/p2p/src/lib.rs` for that measurement.

A node behind NAT with no inbound UDP can only ever be the dialer, and peers
fill up: expect to wait for a peer that stays, and expect a first connection to
be refused with a `Goodbye`.

A run where discv5 finds contacts but every one is rejected for a missing `eth2`
entry means the records reaching the dial loop are not the ones the peers
published. discv5 hands back a full `NodeRecord` per NODES response, so an
`eth2` entry that was there on the wire and absent here is a record-plumbing
problem in the discovery layer rather than anything in `admit`, which is
covered by unit tests against records carrying every entry. Bootnode records are
a poor control: mainnet's advertise the phase0 digest and are *supposed* to be
rejected, just as `fork digest mismatch` rather than as `missing`.
