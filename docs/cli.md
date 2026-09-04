# Command line

`ethlambda` follows one of two chains, selected by a subcommand:

| Invocation | Chain |
|---|---|
| `ethlambda node <flags>` | The lean consensus protocol this repository implements |
| `ethlambda beacon <flags>` | The Ethereum Beacon Chain, as a gossip follower |
| `ethlambda <flags>` | `node`: the subcommand is injected |

`ethlambda benchmark` is the third subcommand and follows no chain: it is the
offline block-building harness, run through `make bench`. Everything below is
about the two that do.

## `node` is the default

clap has no native default subcommand, so the binary rewrites its own argv
before parsing. If the first argument is not `node`, `beacon`, `benchmark`,
`help`, `-h`, `--help`, `-V`, or `--version`, then `node` is inserted ahead of
it. The function is `inject_default_subcommand` in
`bin/ethlambda/src/command.rs`. Every subcommand has to be listed there: a
missing one would have `node` inserted ahead of it and become unreachable.

```
ethlambda --genesis c.yaml ...              ->  ethlambda node --genesis c.yaml ...
ethlambda node --genesis c.yaml ...         ->  unchanged
ethlambda beacon --gossipsub-port 9001 ...  ->  unchanged
ethlambda benchmark synthetic ...           ->  unchanged
ethlambda --help | --version | -h | -V      ->  unchanged, no injection
```

This is what keeps every existing caller working with no edit: the Docker
`ENTRYPOINT`, `lean-quickstart`'s `client-cmds/ethlambda-cmd.sh`, the Hive lean
client shim, `preview-config.nix`, and the `docker run` blocks in the
devnet-runner skill all pass bare flags.

`ethlambda` with no arguments at all is left alone, so it prints the subcommand
listing rather than a missing-flag error for `node`.

## Common flags

Taken by both subcommands, with the same meaning and the same defaults, from
one `CommonOptions` struct flattened into each.

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir` | `./data` | RocksDB directory. `beacon` keeps no chain, so it writes nothing here today |
| `--gossipsub-port` | `9001` | Port for libp2p gossip: UDP for QUIC and TCP for the noise+yamux fallback, same number on both, since they are separate namespaces. Binding TCP puts it in the HTTP servers' namespace, so it must differ from `--api-port` and `--metrics-port` as well as from `--discovery.port` |
| `--http-address` | `127.0.0.1` | Bind address for both HTTP servers |
| `--api-port` | `5052` | API server port. `beacon` binds it too, and answers the `/lean/v0` routes off an empty store |
| `--metrics-port` | `5054` | Metrics and debug server port. Equal to `--api-port` merges the routers onto one listener |
| `--node-key` | generates an ephemeral key | Hex file holding the secp256k1 key that is this node's libp2p and discv5 identity. When omitted, a fresh key is generated in memory each start (logged as a warning), so the PeerId and ENR differ on every restart |
| `--bootnodes` | see below | Bootnode ENR list: one `enr:...` per line, as a YAML block sequence, a YAML flow sequence, or a plain list (`#` comments and leading `- ` are both tolerated) |
| `--checkpoint-sync-url` | see below | Lean API base URLs, tried in order until one answers. Accepted but unused on `beacon` |
| `--discovery.port` | `9000` | discv5 UDP port; must differ from `--gossipsub-port`. See [Peer discovery](./discovery.md) |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |
| `--discovery.target-peers` | `200` | Connected-peer count above which discovery stops dialing |

Three of those have no clap default, because the two chains answer them
differently. A single `default_value` can only say one thing, so the flag
carries none and each chain resolves an absent value itself:

| Flag | Absent on `node` | Absent on `beacon` |
|---|---|---|
| `--node-key` | ephemeral in-memory key, warned about | same |
| `--bootnodes` | no bootnodes: peers only via discv5, warned about | falls back to the built-in mainnet ENR list |
| `--checkpoint-sync-url` | start from a resumable DB, else from genesis | nothing: this chain's genesis is built into the binary |

There is no `--discovery.enable`. discv5 is always on, on both chains, on
`DEFAULT_DISCOVERY_PORT` (9000) unless `--discovery.port` says otherwise.
`beacon` never had the choice, since published mainnet bootnode ENRs carry no
`quic` entry and so are not statically dialable; a lean node handed no
`--bootnodes` file has no other way to reach a peer either. The two defaults are
one apart because both sockets are UDP; pointing either flag at the other's port
is rejected at startup, before the node touches its data directory.

## `node` flags

On top of the common flags above.

| Flag | Default | Meaning |
|---|---|---|
| `--genesis` | required | Chain genesis config, e.g. `config.yaml` |
| `--validators` | required | Validator registry, e.g. `annotated_validators.yaml` |
| `--validator-config` | required | `validator-config.yaml`, the node-name registry |
| `--hash-sig-keys-dir` | required | Directory of per-validator XMSS keys |
| `--node-id` | required | The key in `annotated_validators.yaml` naming this node, e.g. `ethlambda_0` |
| `--is-aggregator` | `false` | Seed the runtime aggregator flag |
| `--aggregate-subnet-ids` | this node's subnets | Subnets to aggregate on; requires `--is-aggregator` |
| `--attestation-committee-count` | from `validator-config.yaml`, else `1` | Committees per slot |
| `--enable-proposer-aggregation` | `false` | Merge same-data proofs when building a block |
| `--max-attestations-per-block` | `3` | Proposer-side self-limit |
| `--disable-duty-sync-gate` | `false` | Track sync state without suppressing duties |

A `shadow-integration` build adds the `--shadow-xmss-*` flags; they are absent
from a normal build.

## `beacon` flags

None of its own: every flag this chain takes is a common one. Two of them mean
something specific here.

`--checkpoint-sync-url` does nothing here. `genesis_validators_root` and
`genesis_time`, which the fork digest that keys every gossip topic, the ENR
`eth2` entry and discv5 admission is computed from, come from mainnet's genesis
`BeaconState`, built into the binary as
`bin/ethlambda/assets/mainnet/genesis.ssz` (`eth-clients/mainnet`'s file,
byte for byte, the same repo the built-in bootnode list is copied from). `beacon` therefore takes no network configuration at all: a bare
`ethlambda beacon` is a complete invocation, and a run no longer depends on a
checkpoint provider being up. The flag stays *accepted* rather than rejected,
because it is declared once for both subcommands and because the anchor work
will want a finalized beacon state from exactly this kind of URL.

`--api-port` is bound here too, and the `/lean/v0` routes answer off an empty
in-memory store: one HTTP call site serves both chains rather than two, at the
cost of endpoints that report on a chain this process is not running. Treat
`/metrics` on `--metrics-port` as the only meaningful HTTP surface of a
`beacon` run.

## What `ethlambda beacon` does today

It follows mainnet's gossip and nothing above it. There is no store, no state
transition, no fork choice, and no block import: the node joins the network,
decodes what arrives, and logs it. See [`beacon_wire.md`](./beacon_wire.md) for
what goes on the wire and how to check a run against the live network.

### One entry point, two chains

Both sub-commands run through `run_node` in `bin/ethlambda/src/main.rs`. Each
parses into a single `cli::Options`, whose `network` field is `Network::Lean` or
`Network::Mainnet` and carries that chain's own flags. `run_node` does what is
not chain-specific, branches once, and shares the shutdown:

| step | lean | mainnet |
|---|---|---|
| validate the discv5 port | shared | shared |
| register metrics, print the banner, log the version | shared | shared |
| raise `RLIMIT_NOFILE` | shared | shared |
| `HIVE_LEAN_TEST_DRIVER` early return | yes | no: those endpoints are lean's |
| resolve `--node-key`, read `--bootnodes` | shared | shared |
| build the aggregator, sync-status and event handles | shared | shared |
| **the one `match`**: produce a `ChainSetup` | genesis config, validator keys, RocksDB, checkpoint sync, subnets | `beacon::wire_params`: fetch genesis metadata, derive the epoch and fork digest |
| build the swarm, spawn P2P, start discv5 | shared | shared |
| start the HTTP server | shared | shared |
| spawn the chain actor and wire it to P2P | yes | no: it imports nothing |
| ctrl-c, stop and join the actors | shared | shared |

`ChainSetup` is what the `match` produces: the wire configuration, the ENR
entries that describe it, the store the req/resp handlers answer from, the
node-name roster, and an `Option` holding the validator keys and
`BlockChainConfig`. The operator-supplied half of the discv5 configuration (node
key, ports, bootnodes, peer target) is the same on either chain, so it is filled
in once below the match. That `Option` being `None` is what ends the mainnet path:
`run_node` returns straight into the shared shutdown after starting the wire.

`beacon::wire_params` reads `genesis_time` and `genesis_validators_root` off the
built-in genesis state (inflate, then decode as a phase0 `BeaconState`), derives
the wall-clock epoch and fork digest from them, and logs the next boundary that
would move the digest. It builds nothing: one `build_swarm` serves both chains, dispatching on
the `WireConfig` variant for the topics, the req/resp protocol set, the
gossipsub `seen_ttl`, the identify version and the connection limits.

The chain actor is the one thing mainnet has none of, so `RunningNode`
carries it as an `Option` and the shared shutdown skips it.

Not implemented here: the anchor, the beacon store, block import, and fork
choice. A decoded block is logged and dropped.
