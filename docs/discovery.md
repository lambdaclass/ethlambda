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
ethlambda --discovery.enable
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--discovery.enable` | `false` | Run the discv5 server and the dial loop |
| `--discovery.port` | `9000` | UDP port for the discv5 socket |
| `--discovery.advertise-ip` | bind address (`0.0.0.0`) | IP address to advertise in the ENR |
| `--discovery.target-peers` | `200` | Connected-peer count above which dialing stops |

`--discovery.port` and `--gossipsub-port` (default `9001`, libp2p QUIC) are both
UDP and so cannot share a port. `--gossipsub-port` also binds a libp2p TCP
listener on the same number, which collides with neither: TCP and UDP are
separate namespaces. The defaults are one apart, so `--discovery.enable`
works on its own; overriding either onto the other is rejected at startup.

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
| `quic` | `--gossipsub-port`, the libp2p QUIC listener; omitted when `0` |
| `tcp` | `--gossipsub-port`, the libp2p TCP listener; omitted when `0` |
| `secp256k1` | compressed public key from `--node-key` |
| `eth2` | SSZ `ENRForkID`, 16 bytes |
| `attnets` | subscribed attestation subnet bitfield |

`tcp` and `quic` share the same port number: TCP and UDP are separate
namespaces, so `build_swarm` binds both without a collision. Advertising both
is what lets a peer whose `quic` port does not answer still reach this node
over TCP. It also gets us past lighthouse's discovery predicate, which requires
`enr.tcp4().is_some() || enr.tcp6().is_some()` on top of the spec's
`fork_digest` comparison; the lean fork digest is still the cross-client dummy
`0x12345678`, so a beacon-chain client rejects us on that instead.

Both ports come from configuration rather than from the bound listeners, so a
`--gossipsub-port 0` would name neither of the two real OS-assigned ports.
Startup rejects that combination when discovery is enabled, and the writer omits
a `0` either way, matching every reader's rule that `0` means absent.

The local ENR is logged once at startup.

This same record is handed to ethrex's `DiscoveryServer`, so it is what answers
discv5 queries: what we report and what peers see are the same bytes. If IP
voting later changes our external address, ethrex edits and re-signs that record
rather than rebuilding one, so the consensus entries survive the bump; only the
sequence number and `ip` move, which the reported ENR then lags.

## Which peers get dialed

A discovered peer is admitted only if:

- its ENR carries a decodable `eth2` entry, **and**
- that entry's `fork_digest` equals ours, **and**
- it advertises a `quic` port, a `tcp` port, or both.

A differing `next_fork_version` or `next_fork_epoch` is *not* grounds for
rejection: the spec permits connecting to a peer that is incompatible with an
upcoming fork but compatible now.

These checks are handed to ethrex's peer table as a `PeerFilter`, so each record
is judged the moment it arrives and a peer that fails is not offered for dialing.
No rejection is final: the peer table runs the filter again as soon as the peer
publishes a higher-`seq` ENR, so a node that adds a `quic` entry, or gains an
address through discv5's IP voting, is reconsidered without a restart.

A peer's dial list carries every address it advertises, `quic` and `tcp` both,
in one dial attempt. libp2p races them: it starts up to `dial_concurrency_factor`
handshakes at once and keeps whichever completes first, dropping the other. So a
peer whose `quic` port does not answer still connects over `tcp` with no separate
retry and no connect timeout waited out first.

The list order is not a preference, and nothing should be read into it: the
default concurrency factor exceeds the two addresses a lean peer can offer, so
both are always attempted. The cost of that is the thing to know, since it is
paid on every dial rather than only on a failure: two sockets and two handshakes
per peer, on both ends, until one wins.

Admitted peers are ranked by how many attestation subnets they advertise that no
currently connected peer covers, so discovery preferentially fills gaps in subnet
coverage. A peer advertising no `attnets` is ranked last but never dropped.

Dialing stops once `--discovery.target-peers` peers are connected, and resumes
if that count drops. That is all the flag does: it is the dial loop's cutoff, and
nothing in ethrex's peer table or discv5's own pacing enforces it (see
[below](#discv5-lookups-run-at-the-startup-rate)).

## Bootnodes

The three entries a bootnode ENR can carry are read independently, because they
answer different questions:

| Entry | Absent means |
| --- | --- |
| `quic` | Not part of the static dial list over QUIC |
| `tcp` | Not part of the static dial list over TCP |
| `udp` | Not seeded into the discv5 routing table |

A bootnode is dropped only when it has none of the three: neither transport to
dial nor a `udp` port to seed discv5 from. Any other combination is kept,
including one with only `quic`, only `tcp`, only `udp`, or any pair. The ENRs
`lean-quickstart` generates today carry `ip`/`quic`/`secp256k1` and no `udp`,
so they stay reachable but contribute nothing to discovery. A beacon-chain
bootnode is close to the mirror image, `udp` and `tcp` but no `quic`, and the
`tcp` entry is what now makes it statically dialable rather than a discv5 seed
only. A record missing an `ip` or a `secp256k1` key is dropped regardless of
its transports.

The ENR a node logs at startup is only useful to a peer if that node was
started with a real `--discovery.advertise-ip`.
Copying an ENR built from the default `0.0.0.0` into another node's bootnode
list produces a `udp`/`quic`/`tcp` target that cannot be dialed, since `0.0.0.0`
names no reachable host. Set `--discovery.advertise-ip` before pointing other
nodes at this one's ENR: `127.0.0.1` on a local devnet, or the host's public
address otherwise.

## Known limitations

### Static bootnodes bypass admission and are redialed indefinitely

Everything under [Which peers get dialed](#which-peers-get-dialed) applies to
*discovered* peers. A static bootnode reaches the swarm by a different path:
`parse_enr` reads `ip`, `secp256k1` and the three port entries and never looks at
`eth2`, so a `--bootnodes` list is dialed as given. Now that a `tcp`-only record
is dialable, a beacon-chain ENR is a valid static target, and the noise+yamux
handshake to a lighthouse node succeeds: the peer occupies a
`--discovery.target-peers` slot, contributes no attestation subnets, and is
eventually dropped by the remote for sharing no protocols. Each drop re-arms the
redial timer, which runs at a flat interval with no backoff and no cap for the
life of the process.

Accepted rather than fixed. Bootnodes are operator-supplied, so a list naming
another network's infrastructure is a configuration mistake, and the unbounded
redial is what keeps a devnet's own bootnode reachable across its restarts.
Splitting the flag into initial peers, dialed once, and bootnodes, seeded into
discv5, is the real fix and is left to a follow-up.

### An upgrade's new ENR entries are invisible to peers that stayed up

The record is signed at ethrex's `INITIAL_ENR_SEQ`, a constant. A peer
identifies a record by (node id, seq) and accepts a replacement only at a
strictly higher seq, and ethrex's WHOAREYOU responder does not even send the
record when the requester's `enr_seq` already matches. So when an ethlambda
release changes which entries it publishes, as adding `tcp` did, a peer holding
the previous record under the same seq keeps it: the new entries reach only
peers that meet this node for the first time.

A fixed local floor above `INITIAL_ENR_SEQ` does not close this. ethrex re-signs
the record at `seq + 1` whenever discv5's IP voting moves the advertised
address, so a node behind NAT may already be serving a seq above any constant
the code could pick, which is exactly the case the floor was meant to cover.
Closing it needs a seq that grows without bound across restarts: a persisted
counter bumped on every content change, or one derived from the wall clock at
startup, which is what several beacon clients do.

### One lean devnet is not separated from another

The spec's `fork_digest` is derived from genesis, so it separates one chain from
another. ethlambda's is the hardcoded cross-client dummy `0x12345678`, and lean
defines no fork schedule, so every `ENRForkID` field is a constant. The `eth2`
check therefore separates lean from non-lean but **not one lean devnet from
another**: two devnets running this code will peer with each other. Closing that
gap requires lean adopting a genesis-derived fork digest, which is a
cross-client change to gossip topic names.

### discv5 lookups run at the startup rate

ethrex paces its discv5 iterative lookups by how full its own peer table is,
easing from one lookup every 500ms at startup to one every 10s once the table
reaches its target. That table only counts peers registered through
`NewConnectedPeer`, which carries an RLPx connection; ethlambda connects over
libp2p and registers nothing, so the count is permanently zero and the pacing
never eases off the startup rate. A lean node therefore keeps looking up every
500ms rather than settling at 10s, roughly 20x the intended steady-state
`FindNode` traffic, for the life of the process.

`--discovery.target-peers` deliberately does *not* feed that computation, since a
target of `0` would make it divide by zero and re-fire the lookup timer with no
delay at all. Closing the gap properly means ethrex learning about non-RLPx
connections, which is an upstream change.

### `attnets` is not a fixed-width SSZ `Bitvector`

The spec's `attnets` is `Bitvector[ATTESTATION_SUBNET_COUNT]`, a constant every
conformant client shares, which is what makes an undelimited bitfield decodable.
ethlambda derives the width from `attestation_committee_count`, which is runtime
configuration, so two nodes can legitimately exchange bitfields of different
lengths. The bit-packing convention is identical to the spec's; only the width
is negotiable. Readers tolerate a foreign length by treating bits past the end
as unset, and a peer's advertised subnets are clamped to the local committee
count before they influence anything.
