# Peer discovery (discv5)

ethlambda can find peers over
[discv5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md)
instead of relying only on the static bootnode list. The implementation reuses
[ethrex](https://github.com/lambdaclass/ethrex)'s discovery stack, with discv4
disabled.

Discovery is **off by default**. Nothing else on the lean network speaks discv5
today: not leanSpec, not ream's lean network, not zeam. Enabling it currently
only finds other ethlambda nodes.

## Enabling it

```bash
ethlambda \
  --gossipsub-port 9000 \    # libp2p QUIC (UDP)
  --discovery.enable \
  --discovery.port 9010      # discv5 (UDP)
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--discovery.enable` | `false` | Run the discv5 server and the dial loop |
| `--discovery.port` | `9000` | UDP port for the discv5 socket |
| `--discovery.advertise-ip` | bind address (`0.0.0.0`) | IP address to advertise in the ENR |

Both `--discovery.port` and `--gossipsub-port` default to 9000 and both bind
UDP, so they cannot share a port. Enabling discovery without changing one of
them is rejected at startup.

The discv5 socket always binds the wildcard `0.0.0.0`, since that is where we
listen, not where peers should dial us. Without `--discovery.advertise-ip` the
published ENR inherits that same `0.0.0.0`, which is not a dialable address:
set the flag to `127.0.0.1` for a local devnet or to the host's public address
so the ENR is usable as soon as it is published. discv5's PONG-based IP voting
may still replace the advertised address later, once a peer's response tells
the node what its external address looks like.

## The ENR

The layout follows the discovery domain of the beacon-chain
[phase0 p2p interface spec](https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md).

| Entry | Value |
| --- | --- |
| `id` | `v4` |
| `ip` | `--discovery.advertise-ip`, or the bind address (`0.0.0.0`) if unset |
| `udp` | `--discovery.port` |
| `quic` | `--gossipsub-port`, the libp2p QUIC listener |
| `tcp` | `--gossipsub-port`, the libp2p TCP listener |
| `secp256k1` | compressed public key from `--node-key` |
| `eth2` | SSZ `ENRForkID`, 16 bytes |
| `attnets` | subscribed attestation subnet bitfield |

`tcp` and `quic` share the same port number: TCP and UDP are separate
namespaces, so `build_swarm` binds both without a collision. Advertising both
is what lets a peer whose `quic` port does not answer still reach this node
over TCP.

Read the local ENR from `GET /lean/v0/node/identity`, which reports it as `enr`
(`null` when discovery is disabled). It is also logged once at startup.

## Which peers get dialed

A discovered peer is admitted only if:

- its ENR carries a decodable `eth2` entry, **and**
- that entry's `fork_digest` equals ours, **and**
- it advertises a `quic` port, a `tcp` port, or both.

A differing `next_fork_version` or `next_fork_epoch` is *not* grounds for
rejection: the spec permits connecting to a peer that is incompatible with an
upcoming fork but compatible now. Rejected peers are marked unwanted in the peer
table and are not reconsidered.

A peer's dial list carries every address it advertises, QUIC first then TCP.
libp2p races every address in one dial attempt, so a peer whose `quic` does not
answer can still connect over `tcp` without a separate retry.

Admitted peers are ranked by how many attestation subnets they advertise that no
currently connected peer covers, so discovery preferentially fills gaps in subnet
coverage. A peer advertising no `attnets` is ranked last but never dropped.

Dialing stops once 16 peers are connected, and resumes if that drops.

## Bootnodes

The three entries a bootnode ENR can carry are read independently, because
they answer different questions:

| Entry | Absent means |
| --- | --- |
| `quic` | Not part of the static dial list over QUIC |
| `tcp` | Not part of the static dial list over TCP |
| `udp` | Not seeded into the discv5 routing table |

A bootnode is dropped only when it has none of the three: neither transport to
dial nor a `udp` port to seed discv5 from. Any other combination is kept,
including one with only `quic`, only `tcp`, only `udp`, or any pair. The ENRs
`lean-quickstart` generates today carry `ip`/`quic`/`secp256k1` and no `udp`,
so they stay reachable but contribute nothing to discovery. Not every
published beacon-chain bootnode advertises `quic`, but some advertise `tcp`,
which is what makes them statically dialable now that the swarm speaks both
transports; the rest carry only `udp` and remain discv5-seed-only. A record
missing an `ip` or a `secp256k1` key is dropped regardless of its transports.

The ENR reported by `GET /lean/v0/node/identity` is only useful to a peer if
the node that published it was started with a real `--discovery.advertise-ip`.
Copying an ENR built from the default `0.0.0.0` into another node's bootnode
list produces a `udp`/`quic` target that cannot be dialed, since `0.0.0.0`
names no reachable host. Set `--discovery.advertise-ip` before pointing other
nodes at this one's ENR: `127.0.0.1` on a local devnet, or the host's public
address otherwise.

## Probing a live network

`cargo run -p ethlambda-p2p --example discv5_probe -- --network mainnet` joins a
discv5 network and reports every contact it finds and what [admission](#which-peers-get-dialed)
says about it, without dialing anything. It drives the same `parse_enrs` →
`spawn_discovery` → `get_contacts_to_initiate` path a real node does, so it
separates "the discv5 stack is broken" from "the discv5 stack works and these
peers are correctly refused". Pass `--enrs <file>` for a network other than
mainnet; one ENR per line, with `- ` prefixes and `#` comments tolerated.

Against Ethereum mainnet it reaches ~1300 contacts in 60 seconds, ~250 of them
with a full ENR, and admits none of them. The digests it reports are a useful
sanity check that the crawl is real: the plurality carry mainnet's current
`8c9f62fe` (Fulu + the epoch-419072 blob-schedule fork), a tail carry
`ad532ceb` (Electra) or the long-stale `b5303f2a` (phase0, from bootnode
records never re-published), and roughly half carry no `eth2` entry at all —
those are execution-layer nodes, which share the DHT and answer FINDNODE just
the same.

### Proving the discovered peers are real

`cargo run -p ethlambda-p2p --example mainnet_gossip --profile release-fast`
takes the same crawl one step further: it dials the mainnet consensus clients
it finds, completes the beacon `Status` handshake, subscribes to
`/eth2/<digest>/beacon_block/ssz_snappy`, and snappy-decompresses the first
block that arrives. Typical run: a block within ~30 seconds of startup, one
second after its own slot, from two connected peers and one mesh slot.

That binary was a probe, and what it proved is now shipped:
[the mainnet wire](./beacon_wire.md) puts the same topic names, protocol ids and
`Status` handshake behind the `ethlambda beacon` subcommand. What the probe
shares with both is the layer underneath: discv5, ENR parsing and verification,
and the `ssz_snappy` framing.

Two details from it are worth keeping in mind:

- The probe learned the fork digest by plurality vote over discovered ENRs.
  `ethlambda beacon` computes it from the fork schedule instead, which is
  correct across a boundary rather than merely current. Bootnode records remain
  poor witnesses either way: mainnet's still advertise the phase0 digest, and
  three of them a pre-genesis one.
- Gossip message ids follow Altair's function, which inserts the topic length
  and topic bytes between the domain and the payload. Phase0's shorter form
  produces ids no peer agrees with, which breaks IWANT/IHAVE silently.
  `compute_message_id` in `crates/net/p2p/src/lib.rs` is already the Altair form
  and is shared by both wires.

## Known limitations

### One lean devnet is not separated from another

The spec's `fork_digest` is derived from genesis, so it separates one chain from
another. ethlambda's is the hardcoded cross-client dummy `0x12345678`, and lean
defines no fork schedule, so every `ENRForkID` field is a constant. The `eth2`
check therefore separates lean from non-lean but **not one lean devnet from
another**: two devnets running this code will peer with each other. Closing that
gap requires lean adopting a genesis-derived fork digest, which is a
cross-client change to gossip topic names.

### The record ethrex serves is not the record we report

`GET /lean/v0/node/identity` reports the ENR built by `build_local_enr`, which
carries every entry in the table above. ethrex's `DiscoveryServer` builds its
own copy from the local `Node` and offers no way to seed the consensus entries,
so the record it answers discv5 queries with carries `ip`, `udp` and
`secp256k1` but **not** `eth2`, `attnets` or `quic`.

Discovery is therefore one-sided: we find lean peers and admit them, but a lean
peer applying [the same admission rules](#which-peers-get-dialed) to what ethrex
serves rejects us for a missing `quic` entry. Copying our reported ENR into
another node's bootnode list still works, since that is the complete record.

Closing this needs a way to hand ethrex's `DiscoveryServer::spawn` a prepared
record instead of having it build one. Until then, discovery finds peers but
cannot be found by them.

### A beacon-chain client still cannot discover a *lean* node, but `tcp` is no longer why

There used to be two independent blockers here. Lighthouse's discovery
predicate is stricter than the spec text: alongside the `fork_digest`
comparison it requires `enr.tcp4().is_some() || enr.tcp6().is_some()`, and it
applies that as a discv5 query filter, so a `tcp`-less record was dropped
before lighthouse's dial logic ever saw it. Now that the local ENR advertises
`tcp` (see the entry table above), that filter no longer excludes us.

The other blocker remains and is unrelated to transport: the lean network's
`fork_digest` is the hardcoded cross-client dummy `0x12345678`, which never
matches a real beacon network's digest. A lighthouse node still would not
admit a lean node, but for the same reason it would not admit any other
foreign network — not because of a missing transport entry.

### `attnets` is not a fixed-width SSZ `Bitvector`

The spec's `attnets` is `Bitvector[ATTESTATION_SUBNET_COUNT]`, a constant every
conformant client shares, which is what makes an undelimited bitfield decodable.
ethlambda derives the width from `attestation_committee_count`, which is runtime
configuration, so two nodes can legitimately exchange bitfields of different
lengths. The bit-packing convention is identical to the spec's; only the width
is negotiable. Readers tolerate a foreign length by treating bits past the end
as unset, and a peer's advertised subnets are clamped to the local committee
count before they influence anything.

## Metrics

`lean_discovered_peers_dialed_total` counts dials initiated by discovery.
Connection outcomes are covered by the existing peer connect/disconnect metrics.
