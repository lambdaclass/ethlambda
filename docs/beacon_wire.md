# The mainnet wire

`ethlambda beacon` follows the Ethereum Beacon Chain's gossip. This page
describes what it puts on the wire; [`discovery.md`](./discovery.md) covers the
discv5 stack it shares with lean, and [`cli.md`](./cli.md) the flags and the
startup order.

It follows and nothing more: there is no store, no state transition and no fork
choice behind it. A decoded block is logged and dropped.

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

The block and sidecar protocols are not registered, so a peer asking for one
gets a stream-negotiation refusal rather than an answer this node cannot back
up. That costs peer score, which is the accepted price of following before
serving.

The `Status` this node sends carries the computed fork digest and zeroes for
every checkpoint, which is the honest answer for a node holding no chain.
Lighthouse's relevance check exempts a zero `finalized_root`, so this reads as
"peer is syncing" rather than as a conflicting chain. It is answered in the
version the stream asked for: a v1 body on a v2 stream is eight bytes short and
the codec refuses to write it, which drops the connection of every peer that
opens the handshake on `status/2`.

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
