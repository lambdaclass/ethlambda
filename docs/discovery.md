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
| `secp256k1` | compressed public key from `--node-key` |
| `eth2` | SSZ `ENRForkID`, 16 bytes |
| `attnets` | subscribed attestation subnet bitfield |

There is no `tcp` entry: the spec defines it as the libp2p TCP listening port
and ethlambda speaks QUIC only.

Read the local ENR from `GET /lean/v0/node/identity`, which reports it as `enr`
(`null` when discovery is disabled). It is also logged once at startup.

## Which peers get dialed

A discovered peer is admitted only if:

- its ENR carries a decodable `eth2` entry, **and**
- that entry's `fork_digest` equals ours, **and**
- it advertises a `quic` port.

A differing `next_fork_version` or `next_fork_epoch` is *not* grounds for
rejection: the spec permits connecting to a peer that is incompatible with an
upcoming fork but compatible now. Rejected peers are marked unwanted in the peer
table and are not reconsidered.

Admitted peers are ranked by how many attestation subnets they advertise that no
currently connected peer covers, so discovery preferentially fills gaps in subnet
coverage. A peer advertising no `attnets` is ranked last but never dropped.

Dialing stops once 16 peers are connected, and resumes if that drops.

## Bootnodes

Bootnode ENRs are still dialed statically over QUIC exactly as before, whether
or not discovery is on. A bootnode additionally seeds the discv5 routing table
only if its ENR advertises a `udp` port. The ENRs `lean-quickstart` generates
today carry only `ip`/`quic`/`secp256k1`, so they remain reachable but
contribute nothing to discovery.

The ENR reported by `GET /lean/v0/node/identity` is only useful to a peer if
the node that published it was started with a real `--discovery.advertise-ip`.
Copying an ENR built from the default `0.0.0.0` into another node's bootnode
list produces a `udp`/`quic` target that cannot be dialed, since `0.0.0.0`
names no reachable host. Set `--discovery.advertise-ip` before pointing other
nodes at this one's ENR: `127.0.0.1` on a local devnet, or the host's public
address otherwise.

## Known limitations

### One lean devnet is not separated from another

The spec's `fork_digest` is derived from genesis, so it separates one chain from
another. ethlambda's is the hardcoded cross-client dummy `0x12345678`, and lean
defines no fork schedule, so every `ENRForkID` field is a constant. The `eth2`
check therefore separates lean from non-lean but **not one lean devnet from
another**: two devnets running this code will peer with each other. Closing that
gap requires lean adopting a genesis-derived fork digest, which is a
cross-client change to gossip topic names.

### A beacon-chain client cannot discover us, and `tcp` is why

Beyond the fork digest never matching a real beacon network, there is a second,
independent blocker. Lighthouse's discovery predicate is stricter than the spec
text: alongside the `fork_digest` comparison it requires
`enr.tcp4().is_some() || enr.tcp6().is_some()`, and it applies that as a
discv5 query filter, so a `tcp`-less record is dropped before lighthouse's dial
logic ever sees it. Our records deliberately carry no `tcp`, so they would be
filtered out even if the digests did match. That is the right trade for a
QUIC-only client, but it means the omission is a real interop cost and not a
free simplification.

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
