# Command line

`ethlambda` follows one of two chains, selected by a subcommand:

| Invocation | Chain |
|---|---|
| `ethlambda lean <flags>` | The lean consensus protocol this repository implements |
| `ethlambda beacon <flags>` | The Ethereum Beacon Chain, as a follower |
| `ethlambda <flags>` | `lean`: the subcommand is injected |

## `lean` is the default

clap has no native default subcommand, so the binary rewrites its own argv
before parsing. If the first argument is not `lean`, `beacon`, `help`, `-h`,
`--help`, `-V`, or `--version`, then `lean` is inserted ahead of it. The
function is `inject_default_subcommand` in `bin/ethlambda/src/cli.rs`.

```
ethlambda --genesis c.yaml ...              ->  ethlambda lean --genesis c.yaml ...
ethlambda lean --genesis c.yaml ...         ->  unchanged
ethlambda beacon --checkpoint-sync-url ...  ->  unchanged
ethlambda --help | --version | -h | -V      ->  unchanged, no injection
```

This is what keeps every existing caller working with no edit: the Docker
`ENTRYPOINT`, `lean-quickstart`'s `client-cmds/ethlambda-cmd.sh`, the Hive lean
client shim, `preview-config.nix`, and the `docker run` blocks in the
devnet-runner skill all pass bare flags.

`ethlambda` with no arguments at all is left alone, so it prints the subcommand
listing rather than a missing-flag error for `lean`.

## Common flags

Taken by both subcommands, with the same meaning and the same defaults.
`--node-key` is deliberately not here even though it fits the description:
it is required on `lean` and optional on `beacon`, and a flattened struct has
one requiredness — see each subcommand's own table below.

| Flag | Default | Meaning |
|---|---|---|
| `--data-dir` | `./data` | RocksDB directory |
| `--gossipsub-port` | `9000` | Port for libp2p gossip: UDP for QUIC and TCP for the TCP transport, same number on both, since they are separate namespaces |
| `--http-address` | `127.0.0.1` | Bind address for both HTTP servers |
| `--api-port` | `5052` | API server port |
| `--metrics-port` | `5054` | Metrics and debug server port. Equal to `--api-port` merges the routers onto one listener |

## `lean` flags

| Flag | Default | Meaning |
|---|---|---|
| `--node-key` | required | Hex file holding the secp256k1 key that is this node's libp2p and discv5 identity |
| `--genesis` | required | Chain genesis config, e.g. `config.yaml` |
| `--validators` | required | Validator registry, e.g. `annotated_validators.yaml` |
| `--bootnodes` | required | YAML list of bootnode ENRs |
| `--validator-config` | required | `validator-config.yaml`, the node-name registry |
| `--hash-sig-keys-dir` | required | Directory of per-validator XMSS keys |
| `--node-id` | required | The key in `annotated_validators.yaml` naming this node, e.g. `ethlambda_0` |
| `--checkpoint-sync-url` | none | Peer API base URLs, used only when there is no resumable state on disk. See [Checkpoint Sync](./checkpoint_sync.md) |
| `--is-aggregator` | `false` | Seed the runtime aggregator flag |
| `--aggregate-subnet-ids` | this node's subnets | Subnets to aggregate on; requires `--is-aggregator` |
| `--attestation-committee-count` | from `validator-config.yaml`, else `1` | Committees per slot |
| `--enable-proposer-aggregation` | `false` | Merge same-data proofs when building a block |
| `--max-attestations-per-block` | `3` | Proposer-side self-limit |
| `--disable-duty-sync-gate` | `false` | Track sync state without suppressing duties |
| `--discovery.enable` | `false` | Enable discv5. See [Peer discovery](./discovery.md) |
| `--discovery.port` | `9000` | discv5 UDP port; must differ from `--gossipsub-port` when discovery is on |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |

A `shadow-integration` build adds the `--shadow-xmss-*` flags; they are absent
from a normal build.

## `beacon` flags

| Flag | Default | Meaning |
|---|---|---|
| `--node-key` | generates an ephemeral key | Hex file holding the secp256k1 key that is this node's libp2p and discv5 identity. When omitted, a fresh key is generated in memory each start (logged as a warning): the PeerId and ENR differ on every restart |
| `--checkpoint-sync-url` | required | Beacon API base URLs supplying the anchor state |
| `--bootnodes` | built-in mainnet ENRs | Override the built-in list |
| `--discovery.port` | `--gossipsub-port` + 1 | discv5 UDP port |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |

`--checkpoint-sync-url` is required here, unlike on `lean`, because the anchor
state is the only source of `genesis_validators_root` and `genesis_time`, and
the fork digest that keys every gossip topic, the ENR `eth2` entry, and discv5
admission is computed from them.

There is no `--discovery.enable`: published mainnet bootnode ENRs carry no
`quic` entry, so none of them is statically dialable and a discv5 crawl is the
only way to reach a peer. Discovery is always on, which is also why the discv5
port defaults one above the QUIC port instead of colliding with it.

## What `ethlambda beacon` does today

It parses its flags, logs the resolved configuration, and exits with an error.
The mainnet wire, the checkpoint-synced anchor, and the fork choice arrive in
later plans of `docs/superpowers/specs/2026-08-10-mainnet-network-design.md`.
