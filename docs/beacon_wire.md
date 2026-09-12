# The mainnet wire

`ethlambda beacon` follows the Ethereum Beacon Chain's gossip. This page
describes what it puts on the wire; [`discovery.md`](./discovery.md) covers the
discv5 stack it shares with lean, and [`cli.md`](./cli.md) the flags and the
startup order.

It follows and imports nothing. A checkpoint-anchored store sits behind it, and
the two block protocols serve from it, but there is no chain actor: a block that
arrives on gossip, or that this node fetched, is checked and then dropped.

## Running it

```bash
ethlambda beacon \
  --node-key ./node-key \
  --gossipsub-port 9001
```

No flag is required: `ethlambda beacon` on its own is a complete invocation.
`genesis_time` and `genesis_validators_root`, and therefore the fork digest,
come from mainnet's genesis `BeaconState`, which is built into the binary as
`bin/ethlambda/assets/mainnet/genesis.ssz` (`eth-clients/mainnet`'s file,
byte for byte, decoded at startup in about 4 ms). Nothing about startup touches the
network. discv5 is forced on and needs no flag either: published mainnet
bootnodes are largely seed-only, so a crawl is how a peer is reached.

## The fork digest

Computed once at startup from the built-in genesis state, never hardcoded as a
digest:

```
epoch        = (now - genesis_time) / (SECONDS_PER_SLOT * SLOTS_PER_EPOCH)
fork_version = the mainnet schedule at epoch
base         = compute_fork_data_root(fork_version, genesis_validators_root)
digest       = base[..4]                                    if epoch <  FULU_FORK_EPOCH
             = xor(base, sha256(le64(bp.epoch) ++
                                le64(bp.max_blobs)))[..4]   if epoch >= FULU_FORK_EPOCH
```

`bp` is the latest blob-schedule entry at or before `epoch`, falling back to
`(ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK_ELECTRA)`. The fulu branch is
EIP-7892's, which is why mainnet's digest is `8c9f62fe` rather than fulu's bare
`82fae541`.

Startup logs the next boundary's epoch and wall-clock time. The digest is
computed once, so crossing one strands the node on topic names nobody publishes
to; restart it to pick up the new digest.

## Gossip

Seven topics, `/eth2/{digest}/{name}/ssz_snappy`:

| Topic | Decoded as |
| --- | --- |
| `beacon_block` | `SignedBeaconBlock`, fork chosen by the block's slot |
| `beacon_aggregate_and_proof` | `SignedAggregateAndProof`, phase0 or electra |
| `attester_slashing` | `AttesterSlashing`, phase0 or electra |
| `voluntary_exit` | `SignedVoluntaryExit` |
| `proposer_slashing` | `ProposerSlashing` |
| `bls_to_execution_change` | `SignedBLSToExecutionChange` |
| `sync_committee_contribution_and_proof` | `SignedContributionAndProof` |

No subnet family is subscribed: not `beacon_attestation_{0..63}`, not
`sync_committee_{0..3}`, not `data_column_sidecar_{0..127}`, not
`blob_sidecar_{subnet_id}`. That is 7 subscriptions rather than 203, and it
drops roughly 30k BLS verifications per epoch. Each family arrives with the work
that reads it.

Blocks and aggregate attestations are logged at `info`, one line each; the other
five topics are counted and logged at `debug`, since nothing distinguishes one
voluntary exit from the next at a glance. Nothing is published: nothing this
node can produce today would be signature-valid.

## Request/response

| Protocol | Direction |
| --- | --- |
| `status/1`, `status/2` | both |
| `ping/1` | both |
| `metadata/1`, `metadata/2`, `metadata/3` | both |
| `goodbye/1` | inbound; the reason code is logged and the stream closed |
| `beacon_blocks_by_range/2` | both |
| `beacon_blocks_by_root/2` | both |

The sidecar protocols are not registered, so a peer asking for one gets a
stream-negotiation refusal rather than an answer this node cannot back up.
Nothing custodies a blob or a data column, and a registered protocol with no
implementation behind it is an untested encoder peers can reach.

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

### What is not wired yet

Serving both protocols is live, off the checkpoint-anchored store. A request
that reaches a node whose data directory is *not* a beacon one is refused with
`RESOURCE_UNAVAILABLE`, the spec's own code for a peer "unable to reply to block
requests", where `INVALID_REQUEST` would blame the asker for a request that was
fine. That guard is for a lean directory, not for the ordinary case.

*Asking* is now driven from two places. A peer's `Status` starts a range
session, which sends through `request_beacon_blocks_by_range`; and
`Handler<FetchBlock>` reaches `request_beacon_block_by_root` through
`fetch_block_from_peer`, which picks its protocol from the wire so a beacon
node cannot put a lean-framed `BlocksByRoot` on its beacon streams.

The by-root path has no caller in practice on this branch, since reaching it
needs a chain actor asking for a missing parent and the follower still sets
`chain: None`. The range path does run, and **the blocks it fetches are counted
and dropped**, exactly as gossiped beacon blocks are, since there is no actor to
import them into. That is deliberate: the range and root checks are what make an
answer trustworthy and are what an importer would otherwise repeat, and the
watermark that paces the session is the piece that has to be right before an
importer exists. It does mean this branch spends a peer's bandwidth on blocks it
discards.

Range sync is paced by `P2PServer::beacon_fetched_through`, not by the store's
head. Nothing here imports, so the head never moves and a head-driven session
would re-request the same range forever. The reasoning holds once an importer
does exist: delivery is a message and import is work, so the store trails a
delivered batch by the whole actor mailbox, which on the live follower meant
11,213 blocks off the wire to import 100.

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
| `attnets` | 64 bits, all unset |
| `cgc` | `CUSTODY_REQUIREMENT` |
| `quic` | `--gossipsub-port` |
| `tcp` | `--gossipsub-port`, the same number: TCP and UDP are separate namespaces |
| `udp` | `--discovery.port` |

Two of these advertise less, or more, than they look like:

- `attnets` all-unset is exactly what a node subscribing to no attestation
  subnet serves. It costs only that subnet-gap-filling peers rank us lower.
- `cgc` advertises the custody requirement while this node custodies and serves
  nothing, because peers may reject a lower value outright. This is the widest
  gap between what is advertised and what is served, and startup warns about it.

The `tcp` entry is what makes us discoverable in return: lighthouse's discovery
predicate requires `enr.tcp4().is_some() || enr.tcp6().is_some()` and applies it
as a query filter, so a `quic`-only record is invisible to it.

## Metrics

| Metric | Meaning |
| --- | --- |
| `lean_beacon_gossip_messages_total{topic,result}` | Gossip received, by topic and by `decoded` / `decode_failed` / `decompress_failed` |
| `lean_beacon_status_digest_mismatch_total` | Handshakes seen from another fork digest |
| `lean_beacon_fork_digest{digest}` | The digest computed at startup, as a label |

The `lean_` prefix is the repo-wide convention and applies here too.

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
Advertising cgc=4 while custodying nothing, …
Beacon P2P node started  socket=0.0.0.0:9001 fork_digest=8c9f62fe topics=7
HTTP server listening  addr=127.0.0.1:5054
Starting discv5 discovery  discovery_addr=0.0.0.0:9002 seeds=17 total_bootnodes=17
Local ENR  enr=enr:-…
```

`seeds=17` proves the built-in list parsed; a lower number means a bootnode ENR
was skipped with a warning. `topics=7` proves the subscription set.

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
