# Command line

`ethlambda` follows one of two chains, selected by a subcommand:

| Invocation | Chain |
|---|---|
| `ethlambda node <flags>` | The lean consensus protocol this repository implements |
| `ethlambda beacon <flags>` | The Ethereum Beacon Chain, as a gossip follower |
| `ethlambda <flags>` | `node`: the subcommand is injected |

Four subcommands follow no chain. `ethlambda replay-era` replays real chain
history from `.era` files and checks it against the states stored in them; see
[`era_replay.md`](./era_replay.md) for its flags and checks. `ethlambda benchmark` is the offline
benchmarking harness, covering block building (`benchmark synthetic`, run
through `make bench`) and block import (`benchmark import fetch` /
`benchmark import replay`). See [`benchmarking.md`](./benchmarking.md) for
what each workload measures; `benchmark import`'s flags are in
[their own section](#benchmark-import-flags) below. `ethlambda validator` is
the validator client: a separate process that holds keys and performs duties
against a beacon node over the standard REST API, documented in
[its own section](#validator-flags) below. `ethlambda voluntary-exit` signs one
validator's voluntary exit and hands it to a beacon node; see
[its section](#voluntary-exit) below. `ethlambda slashing-protection`
moves that client's EIP-3076 history in and out of its directory, offline; see
[its section](#slashing-protection) below.

## `node` is the default

clap has no native default subcommand, so the binary rewrites its own argv
before parsing. If the first argument is not `node`, `beacon`, `benchmark`,
`replay-era`, `validator`, `help`, `-h`, `--help`, `-V`, or `--version`, then `node` is
inserted ahead of it. The function is `inject_default_subcommand` in
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
| `--data-dir` | `./data` | RocksDB directory. Both sub-commands open one here now: `node`'s live chain state, and `beacon`'s checkpoint-synced (or resumed) anchor |
| `--gossipsub-port` | `9001` | Port for libp2p gossip: UDP for QUIC and TCP for the noise+yamux fallback, same number on both, since they are separate namespaces. Binding TCP puts it in the HTTP servers' namespace, so it must differ from `--api-port` and `--metrics-port` as well as from `--discovery.port` |
| `--http-address` | `127.0.0.1` | Bind address for both HTTP servers |
| `--api-port` | `5052` | API server port. `beacon` binds it too, off its own anchored store rather than an empty one; the lean-shaped `/lean/v0` routes still don't answer for it (see [`beacon` flags](#beacon-flags) below) |
| `--metrics-port` | `5054` | Metrics and debug server port. Equal to `--api-port` merges the routers onto one listener |
| `--node-key` | `<data-dir>/node.key` | Hex file holding the secp256k1 key that is this node's libp2p and discv5 identity. When omitted, the key stored in `--data-dir` as `node.key` is used, generated and stored there (mode `0600`) on the directory's first start, so the PeerId and ENR stay the same across restarts until the directory is wiped |
| `--checkpoint-sync-url` | see below | API base URLs, tried in order until one answers. Supplies `node`'s starting state on the lean API, and `beacon`'s anchor on a standard Beacon API; required on a fresh `beacon` data directory only for a built-in network, since a loaded network anchors at its own `genesis.ssz` instead. See [`checkpoint_sync.md`](checkpoint_sync.md) |
| `--discovery.port` | `9000` | discv5 UDP port; must differ from `--gossipsub-port`. See [Peer discovery](./discovery.md) |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |
| `--discovery.target-peers` | `200` | Connected-peer count above which discovery stops dialing |
| `--telemetry.clickhouse-url` | off | ClickHouse HTTP endpoint for per-block `block_events` rows; also read from `ETHLAMBDA_TELEMETRY_CLICKHOUSE_URL`, the place for a URL with a password. See [Block telemetry](./telemetry.md) |
| `--telemetry.client-name` | `--node-id` / `ethlambda@<hostname>` | `meta_client_name` on those rows; requires the URL |

Two of those have no clap default, because the two chains answer them
differently. A single `default_value` can only say one thing, so the flag
carries none and each chain resolves an absent value itself:

| Flag | Absent on `node` | Absent on `beacon` |
|---|---|---|
| `--node-key` | `<data-dir>/node.key`, generated on the directory's first start | same |
| `--checkpoint-sync-url` | start from a resumable DB, else from genesis | start from a resumable DB, else anchor at the resolved network's own genesis (loaded network only), else abort |

`--bootnodes` is taken by both too, but not with one meaning, so it is listed
under each sub-command instead: on `node` it names a file of ENRs, and on
`beacon` it is a list of ENRs and multiaddrs added to the network's own
bootnodes.

Whether discv5 runs is not a common flag. `beacon` always runs it, since
published mainnet bootnode ENRs carry no `quic` entry and so are not statically
dialable; `node` runs it only with `--discovery.enable` (see below). Where it
runs, it binds `DEFAULT_DISCOVERY_PORT` (9000) unless `--discovery.port` says
otherwise. The two defaults are one apart because both sockets are UDP; pointing
either flag at the other's port is rejected at startup, before the node touches
its data directory. Without discovery neither that check nor the ban on
`--gossipsub-port 0` applies, since nothing binds the discovery port and no ENR
is published.

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
| `--bootnodes` | none, warned about | Path to a bootnode ENR file: one `enr:...` per line, as a YAML block sequence, a YAML flow sequence, or a plain list (`#` comments and leading `- ` are both tolerated). An unusable entry is skipped with a warning. Without the flag the node starts with no bootnodes, since a lean network has no built-in list, and reaches peers only via discv5 (with `--discovery.enable`) or by being dialed |
| `--discovery.enable` | `false` | Run discv5 peer discovery; off, the node peers from `--bootnodes` alone. See [Peer discovery](./discovery.md) |
| `--aggregate-subnet-ids` | this node's subnets | Subnets to aggregate on; requires `--is-aggregator` |
| `--attestation-committee-count` | from `validator-config.yaml`, else `1` | Committees per slot |
| `--enable-proposer-aggregation` | `false` | Merge same-data proofs when building a block |
| `--max-attestations-per-block` | `3` | Proposer-side self-limit |
| `--disable-duty-sync-gate` | `false` | Track sync state without suppressing duties |

A `shadow-integration` build adds the `--shadow-xmss-*` flags; they are absent
from a normal build.

## `beacon` flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--custody-group-count` | `CUSTODY_REQUIREMENT` (4) | How many custody groups this node custodies, advertised as the ENR's `cgc` |
| `--execution-endpoint` | none | Base URL of the execution client's Engine API endpoint, e.g. `http://127.0.0.1:8551`. Must be given together with `--execution-jwt-secret` |
| `--execution-jwt-secret` | none | File holding the 32-byte hex JWT secret shared with the execution client |
| `--ethrex.*` | see [Embedded ethrex](./ethrex.md#flags) | Only in a build with the `include-ethrex` feature: configure the ethrex that build runs in-process when `--execution-endpoint` is not given (data directory, network, sync mode, devp2p ports and bootnodes, the optional execution JSON-RPC and metrics servers), and are refused together with it |
| `--safe-slots-to-import-optimistically` | the specification's own value | How far behind the wall clock a block must be before it may be imported optimistically on age alone |
| `--always-prepare-payload` | off | Publish the `payload_attributes` event for every slot, not only for proposers a validator client registered through `prepare_beacon_proposer`. For an external block builder reading this node's event stream (ethereum-package's buildoor). With `--execution-endpoint` it also has the execution client start a payload build for every slot, a third of a slot ahead, whether or not anything is subscribed to the event stream. For a proposer no validator client registered, that build pays the fee recipient of the proposer's signed preferences on gloas, else `--fallback-fee-recipient`, else the zero address. Lighthouse's flag of the same name |
| `--fallback-fee-recipient` | none | Execution address (20 bytes of hex, `0x` optional) a locally built payload pays when no validator client named a fee recipient for the proposer through `prepare_beacon_proposer` or a builder registration (and, on gloas, no signed proposer preferences name one). Without it such a payload pays the zero address and its fees are lost. The zero address itself is accepted but reported at error at startup, since a proposal that falls back to it logs only at debug. It does not register the proposer: `payload_attributes` events still need `prepare_beacon_proposer` or `--always-prepare-payload`. Lighthouse's beacon-node `--suggested-fee-recipient` |
| `--builder` | none | Base URL of a builder API endpoint, normally MEV-Boost (e.g. `http://127.0.0.1:18550`). Without it every block is built locally |
| `--builder-header-timeout` | `1000` | Milliseconds block production waits for the builder's bid; also sent to the builder as `X-Timeout-Ms`. Requires `--builder` |
| `--builder-follow-redirects` | off | Follow the builder's 307 and 308 redirects, up to ten per call, never from https to http. A 301, 302 or 303 is not followed even then, since following one resends a POST as a GET without its body. Off, every redirect fails the call with an error naming its target, so registrations and signed blocks go only where `--builder` points; on, so does any redirect it does not follow. Requires `--builder` |
| `--builder-fallback-skips` | `3` | Build locally when more than this many consecutive slots right before the proposal had no block (the circuit breaker). Requires `--builder` |
| `--builder-fallback-skips-per-epoch` | `8` | Build locally when more than this many of the slots in the epoch's worth before the proposal had no block. Requires `--builder` |
| `--builder-fallback-epochs-since-finalization` | `3` | Build locally when the proposal is more than this many epochs past the finalized checkpoint. Requires `--builder` |

Accepted range is `CUSTODY_REQUIREMENT` to `NUMBER_OF_CUSTODY_GROUPS` (4 to
128), enforced at parse time rather than clamped: serving a different set than
the operator asked for is the failure hardest to notice.

**It is not the number of columns custodied.** That is `sampling_size`, the
larger of this and `SAMPLES_PER_SLOT`, so the default still custodies 8 columns
and the two only converge once the flag is raised past 8. A node at 128 is a
supernode, custodying every column; raising the value costs storage and
bandwidth in proportion and makes this node useful to more peers, which on a
network where a `cgc=4` peer holds 4 of 128 columns is what decides whether a
lookup finds a custodian at all.

Changing it changes which columns this node custodies, since the custody set is
a function of the node id *and* the count. Sidecars already on disk belong to
the old set: nothing is corrupted, but the node advertises a set it has not
finished filling until it backfills the difference.

With neither execution flag, what happens depends on the build. A build with
the `include-ethrex` feature starts its embedded ethrex and validates payloads
through it (see [Embedded ethrex](./ethrex.md)). Any other build contacts no
execution client and imports blocks without validating their payloads, which is
what it did before those flags existed. It then answers `attestation_data`,
`aggregate_attestation` and block production with `503`, so a validator
client cannot use it. Supplying one without the other is refused at startup: an
Engine API endpoint always requires authentication. See
[the execution layer pairing](./beacon_engine.md) for what each verdict does and
for the limitations that go with the retry ladder.

`beacon` takes two more flags of its own, and two common flags also mean
something specific here.

| Flag | Default | Meaning |
|---|---|---|
| `--network` | `mainnet` | A built-in network name (`mainnet`, `sepolia`, `hoodi` or `plataberget`), or a path to a directory of published network files. A value containing a slash is always a path, so `mainnet` is the built-in and `./mainnet` is a directory. The directory must hold `config.yaml` and `genesis.ssz`, and may hold `bootstrap_nodes.yaml` or `bootstrap_nodes.txt` |
| `--bootnodes` | none: the network's own list alone | Extra bootnodes: ENRs and multiaddrs, comma-separated, and the flag may be repeated. Added to the resolved network's own list, never replacing it. A bad entry is a startup error, and a file path is no longer accepted. See [Bootnodes on `beacon`](#bootnodes-on-beacon) |

`genesis_validators_root` and `genesis_time`, which the fork digest that keys
every gossip topic, the ENR `eth2` entry and discv5 admission is computed from,
come from the resolved network:

| `--network` | genesis values | config | bootnodes |
|---|---|---|---|
| `mainnet` (default), `sepolia`, `hoodi`, `plataberget` | two constants in `network::built_in`; no genesis state is carried (a built-in network never anchors at genesis, and the states run from 5 MB to 150 MB) | `bin/ethlambda/assets/<name>/config.yaml`, byte for byte from `eth-clients/<name>` (Platåberget: `ethpandaops/glamsterdam-devnets`' `network-configs/devnet-8`) | `bin/ethlambda/assets/<name>/bootstrap_nodes.yaml`, from the same repo |
| a directory | read off the directory's own `genesis.ssz` | the directory's `config.yaml` | the directory's `bootstrap_nodes.yaml`/`.txt` |

The genesis constants are checked twice at runtime: checkpoint sync verifies the
downloaded anchor state against both, and a resumed data directory is checked
the same way, so a wrong constant fails at startup rather than following the
wrong chain.

`beacon` therefore takes no genesis config, validator registry, or bootnode file
of its own the way `node` does: those are read off the resolved network instead
of being separate operator input, and `beacon`'s `--bootnodes` only adds entries
to the network's list (see [Bootnodes on `beacon`](#bootnodes-on-beacon)). A
`config.yaml` (a directory's, or a built-in network's embedded one) is read
permissively: absent keys fall back to mainnet's values,
numbers are accepted quoted or bare, and unrecognised keys (on a current
config, the heze schedule this build does not claim) are dropped
with one warning line naming each. Its `PRESET_BASE` (`mainnet` or `minimal`)
selects the preset the process runs, before anything is decoded against it; a
missing or unknown one is a hard startup error. The validator client adopts
the preset its beacon node's `/eth/v1/config/spec` reports. With its optional
`--network`, resolving the network selects that network's `PRESET_BASE`
first, and only a node reporting the same preset can be the one the client
adopts it from (see [the chain check](#several-beacon-nodes-the-chain-check)).
Sepolia's config schedules gloas, which this build follows, so
it parses and runs like any other fork. A scheduled fork the build claims but
does not follow gets a separate, explicit warning at startup, since the chain
follower would stop tracking the chain there regardless of what parsed
cleanly; none exists today. The keys this
build runs on compile-time constants for (the custody and subnet counts, the
`MAX_REQUEST_*` limits, `MAX_PAYLOAD_SIZE`, the snappy message domains and
`MAXIMUM_GOSSIP_CLOCK_DISPARITY`) must equal those
constants, or startup fails naming each key that differs: the node cannot
follow a network that sets them otherwise, and `/eth/v1/config/spec` would
report values it does not use. For a directory, both checks run before its
`genesis.ssz` is decoded, so a directory built for the other preset fails with
the preset error rather than an SSZ one.

Resuming a data directory under a `config.yaml` whose `CONFIG_NAME` differs
from the stored one only logs a warning; the stored name is kept. Any changed
chain value (a fork epoch or version, the slot time, `PRESET_BASE`) is still a
hard error.

`--checkpoint-sync-url` now supplies the beacon anchor: a finalized
`BeaconState` and its anchor block, fetched from a standard Beacon API server
and verified against the genesis identity above plus the anchor's own internal
consistency (see [`checkpoint_sync.md`](checkpoint_sync.md)). The full anchor
precedence is: a resumable data directory, then `--checkpoint-sync-url`, then,
for a loaded network only, that directory's own `genesis.ssz`, then abort. The
URL is therefore **required** on a fresh data directory only for a built-in
network: no built-in network carries a genesis state, and anchoring one at genesis
would leave the follower replaying a chain that has been live for years. A loaded network's own genesis
state is a legitimate anchor instead, since a freshly started devnet has no
checkpoint provider at slot 0 and this is the only way to join one. A
directory already anchored from a previous run resumes without the flag
either way, the same way `node`'s does.

`--api-port` is bound here too, off `beacon`'s own anchored store: one HTTP call
site serves both chains, but it picks the router by the store's chain, so a
`beacon` run serves the Beacon API under `/eth/v1` and `/eth/v2` and answers a
`/lean/v0/...` path with a 404. See [`rpc.md`](./rpc.md).

### Bootnodes on `beacon`

`beacon`'s `--bootnodes` is a list, not a file, modeled on Lighthouse's
`--boot-nodes`. Entries are comma-separated and the flag may be repeated, all
of its values combined; each entry is trimmed, and an empty one is ignored. An
entry is either an ENR, written with or without its `enr:` prefix, or a
multiaddr, which starts with `/`:

```sh
ethlambda beacon --network hoodi --checkpoint-sync-url <URL> \
  --bootnodes enr:-Iq4Q…,/ip4/203.0.113.7/tcp/9000/p2p/16Uiu2HAm… \
  --bootnodes /ip4/203.0.113.8/udp/9000/p2p/16Uiu2HAk…
```

A multiaddr is `/ip4/<ip>` or `/ip6/<ip>`, then one transport, then
`/p2p/<peer-id>`. The transport decides what the entry is used for:

| Transport | The peer is |
|---|---|
| `tcp/<port>` | dialed over TCP |
| `udp/<port>/quic-v1` | dialed over QUIC |
| `udp/<port>` | not dialed directly: the port is the peer's discv5 port, so the entry seeds discovery, which is how Lighthouse reads a UDP multiaddr too |

QUIC is `quic-v1` only; the older draft `/quic` is refused. The
`/p2p/<peer-id>` is required, and DNS multiaddrs (`/dns`, `/dns4`, `/dns6`,
`/dnsaddr`) are refused, so write the address as `/ip4` or `/ip6`. Those two are
departures from Lighthouse; [Peer discovery](./discovery.md#multiaddrs) lists
them with the rest.

The entries are added to the resolved network's own list (a built-in network's
embedded one, or a loaded directory's `bootstrap_nodes.yaml`/`.txt`), never put
in its place, which is Lighthouse's behavior too. Giving the flag used to
replace that list; now the network's bootnodes are always used, and the flag
only adds to them. Nothing turns them off: each one with a QUIC or TCP port is
dialed at startup and redialed 12 seconds after every failed dial or
disconnect, even on a host that cannot reach it. To run on other bootnodes
alone, load the network from a directory whose `bootstrap_nodes.yaml` lists
only those.

An IPv6 entry is dialed like an IPv4 one, but discv5 binds the IPv4 wildcard
and an IPv4 socket cannot reach an IPv6 address, so an IPv6 entry that is only
a discv5 contact (`/ip6/<ip>/udp/<port>`, or an ENR whose only address is `ip6`
and whose only port is `udp`) is refused. The check reads the address discovery
binds rather than assuming IPv4, so it lifts on its own once discovery binds
IPv6 ([#853](https://github.com/lambdaclass/ethlambda/issues/853)).

Every entry is checked at startup. One that does not parse, or that is
unusable (an ENR with no `quic`, `tcp` or `udp` port, a port of `0`, and so
on), is a startup error naming the entry: an operator who typed it meant to
reach that peer, and skipping it would leave the node running on a list it was
not given. The network's own list keeps the old rule, a bad entry there being
skipped with a warning, as `node` skips one in its file.

**A file path is no longer accepted.** Startup fails on one, with a hint that
`--bootnodes` now takes a list; so does a missing path ending in `.yaml`,
`.yml` or `.txt`. A launch script that passed `beacon` a bootnode file must
pass the records it lists joined with commas instead (without a YAML list's
`- ` markers or any comments), or, for a network loaded from a directory, list
them in that directory's `bootstrap_nodes.yaml`.

## What `ethlambda beacon` does today

It follows the resolved network as a non-validating follower. It anchors a
RocksDB-backed store at a checkpoint-synced (or resumed) finalized state, joins
the network's gossip and req/resp, and the chain actor imports blocks from there
(phase0 through gloas), runs fork choice, and, with `--execution-endpoint`,
asks an execution client about payloads. It never proposes or attests. See [`beacon_wire.md`](./beacon_wire.md) for what goes on the wire and
how to check a run against the live network.

### One entry point, two chains

Both sub-commands run through `run_node` in `bin/ethlambda/src/main.rs`. Each
parses into a single `cli::Options`, whose `network` field is `Network::Lean` or
`Network::Mainnet` and carries that chain's own flags. `run_node` does what is
not chain-specific, branches once, and shares the shutdown:

| step | lean | mainnet |
|---|---|---|
| validate the ports (discv5 rules only where it runs) | shared | shared |
| register metrics, print the banner, log the version | shared | shared |
| raise `RLIMIT_NOFILE` | shared | shared |
| `HIVE_LEAN_TEST_DRIVER` early return | yes | no: those endpoints are lean's |
| resolve `--network` into a `NetworkSource` | n/a: lean has no `--network` | classify the value (built-in name vs. directory); parse the `config.yaml` (embedded, or the directory's), select the preset its `PRESET_BASE` names, and check the constant-backed keys against their constants; for a directory, then decode `genesis.ssz` |
| read `--bootnodes` | a file of ENRs; absent means no bootnodes, warned about | a comma-separated list of ENRs and multiaddrs, added to the resolved network's own list; a bad entry is a startup error (see [Bootnodes on `beacon`](#bootnodes-on-beacon)) |
| build the aggregator, sync-status and event handles | shared | shared |
| open `--data-dir`'s RocksDB backend | shared | shared |
| resolve `--node-key`, else load `<data-dir>/node.key`, generating it on first start (after the open, so RocksDB's lock covers the write) | shared | shared |
| **the one `match`**: produce a `ChainSetup` | genesis config, validator keys, checkpoint sync or resume onto the shared backend, subnets | `beacon::wire_params` (genesis metadata, epoch, fork digest), then checkpoint sync or resume onto the same backend |
| build the swarm, spawn P2P, start discv5 | shared; discv5 only with `--discovery.enable` | shared |
| start the HTTP server | shared | shared |
| spawn the chain actor and wire it to P2P | yes | yes: `BlockChain::spawn_beacon` |
| ctrl-c or SIGTERM, stop and join the actors | shared | shared |

`ChainSetup` is what the `match` produces: the wire configuration, the ENR
entries that describe it, the store the req/resp handlers answer from, the
node-name roster, and a `ChainActor` saying what to spawn: lean's validator keys
and `BlockChainConfig`, or beacon's marker. The operator-supplied half of the discv5 configuration (node
key, ports, bootnodes, peer target) is the same on either chain, so it is filled
in once below the match; everything after it, including the chain actor spawn
and the shutdown, is shared.

`beacon::wire_params` reads `genesis_time` and `genesis_validators_root` off
the resolved network (a built-in network's two constants, or a loaded
network's own `genesis.ssz`, decoded at whatever fork its own schedule names
for epoch 0), derives the wall-clock epoch
and fork digest from them, and logs the next boundary that would move the
digest. It builds nothing: one `build_swarm` serves both chains, dispatching on
the `WireConfig` variant for the topics, the req/resp protocol set, the
gossipsub `seen_ttl`, the identify version and the connection limits.

Both chains run a chain actor, so `RunningNode` carries a plain `BlockChain`.

## `validator` flags

`ethlambda validator` is not a node. It binds no libp2p port, opens no chain
database, runs no discovery and follows no chain: it holds validator keys and
performs duties against a beacon node's standard REST API. It works against any
conformant beacon node, this repository's `beacon` subcommand or another
implementation's, so none of the [common flags](#common-flags) apply to it.

> **Slashing protection** lives in `--validators-dir/slashing_protection.json`,
> locked to one process, so `--validators-dir` must be writable: a read-only
> mount of the keys (a Kubernetes Secret, a `:ro` volume) fails at startup, as
> does a record that is a symlink (say, onto another volume) rather than a
> regular file, since a dangling one would read as "no record"; and
> the directory should be a local disk, since every signature waits for the
> record to be flushed to it, and the lock that keeps a second process off it
> is an `flock`, which a network filesystem may not honour. Unix only. Run the
> client under a supervisor that restarts it (systemd's `Restart=on-failure`,
> a Kubernetes pod): if a bug ever panics while the record is held, the record
> is unusable for the rest of that process and no attestation or block can be
> signed, so the client stops at once and exits with a failure, after letting
> a keymanager request in flight finish, and the restart rereads the record
> from disk. A key with no record is refused at startup unless
> `--init-slashing-protection` is passed. A key moving here from another client
> brings its history with [`slashing-protection import`](#slashing-protection),
> or in the same keymanager API request that imports the key. See
> [Spec Deviations](./spec_deviations.md#the-validator-client-keeps-eip-3076s-minimal-watermarks-not-full-history).

### Several beacon nodes: the chain check

The client learns its chain, the preset, genesis, slot duration and fork
schedule, from `--beacon-nodes` at startup: the reference is the first node in
list order that answers both `/eth/v1/beacon/genesis` and
`/eth/v1/config/spec`. While none does, the client warns, naming what each node
said, and asks them all again every 2 seconds, as Lighthouse's validator client
does, rather than exiting: a client started beside its beacon node otherwise
exits before the node's API is up. Only when every node answered, each with a
preset this client cannot run on or a spec it cannot read, does startup fail; a
body that is not JSON at all (a proxy's page while the node boots) is waited out.

With `--network`, the reference must also be on the network it names, compared
on the fields that never move over a network's life: `PRESET_BASE`,
`genesis_time`, `genesis_validators_root`, the slot duration and
`GENESIS_FORK_VERSION`. A node that differs in one is never the reference and is
not used, and a node on another network counts as a final answer: when every
node answered, each on another network, on a preset this client cannot run on,
or with a spec it cannot read, startup fails naming why each is off; otherwise it
waits for one on the network. The fork schedule is not held to the network's,
since the beacon nodes or the network's config (this binary's, for a built-in
network; the directory's `config.yaml` otherwise) may predate a change to it:
the client still follows the nodes' schedule (below), and warns once an epoch,
naming both values, when it differs from the network's config. Nor does the
network's schedule pick the reference among nodes on the network that disagree
on a fork: list order does, as without `--network`, since preferring the node
that matches a stale config would follow the stale schedule and drop the
upgraded node at the old epoch. Without `--network` the first
node to answer sets the chain, whatever it is.

A response without the slot
duration, `GENESIS_FORK_VERSION`, or the epoch and version of any fork from
altair to fulu is refused rather than filled in from mainnet; only gloas may be
absent, meaning unscheduled.

Every other node is compared with the reference, and one that differs is not
used: not for a duty, not for failover, not for a subscription. The comparison
names the first field that differs: `PRESET_BASE`, `genesis_time`,
`genesis_validators_root`, the slot duration, `GENESIS_FORK_VERSION`, or the
epoch or version of a fork. A fork may differ only while it is still in the
future under both schedules, which is how a node upgraded ahead of the others
stays in use. A node that did not answer at startup is not used until a check
has verified it. The warning names the node and the field, when the state
changes and then at most once per epoch. If no node is usable, every request
fails with an error that says no configured node is on the client's chain.

A background task, separate from the duty loop, repeats the check for every node
at the start of every slot, so a node upgraded partway through an epoch for a fork
at the next one is read while that fork is still ahead. Each node's answer is
judged the moment it arrives, at the epoch read then, so a node that hangs until
its request timeout holds back only its own answer, and a fork whose epoch passed
while a node was answering counts as arrived rather than as still ahead.

As each answer arrives, a fork the compatible nodes schedule and the client does
not have yet is adopted by the slot clock and every signing domain together, and
the client logs at `warn` which fields moved. Only nodes that answered one of
their last three checks have a say in this. A fork the client does not have is
taken only when every one of them schedules it, at the same epoch and with the
same version:
one node, misconfigured or not, cannot put a fork on the client's schedule that
the others do not have. So while a node not yet upgraded still answers, the fork
waits; it is taken once that node is upgraded, or once it stops answering
(restarting for the upgrade, say) for three slots and so loses its say. One missed
check does not cost a node its say, so a single timeout of a correct node does not
leave a misconfigured one to move the schedule alone. A warning names the nodes
that disagree, once per epoch, and a node without the client's epoch stops being
used when the fork's epoch arrives. Once the client has a fork scheduled, it
moves only when every node with a say that schedules it agrees on the new epoch
and version, so one node cannot pull it elsewhere, and it is never unscheduled:
a node reporting it unscheduled may only be the one not upgraded yet, while the
upgraded one is restarting. A fork the network cancels therefore needs a
restart. A node that stops answering loses its say after three slots, so it cannot
hold a fork at an epoch the network has postponed (unless the postponement comes in
the fork's last three slots); the duty offsets are still read from the first node
through a round it misses. A merge that would put a fork before the one it follows
is refused whole and warned about. A fork that is already active is never moved: a
node that reports another epoch or version for it is on another chain.
The client does not need a restart for a fork the network schedules after it
started.

A send that has to reach every node (proposer preferences) counts as delivered
everywhere once every node in use took it: a node skipped for being on another
chain is not a refusal. When a check lets a skipped node back in, the client
sends it what it missed: the proposer preferences at the next poll, and the
epoch's attestation subnet subscriptions, sync committee subscriptions and
builder registrations at the next slot.

Offsets into the slot (`*_DUE_BPS`) above 10000 basis points are held to the
slot's end, so a node serving a wrong one cannot park a duty past its slot.

| Flag | Default | Meaning |
|---|---|---|
| `--beacon-nodes` | required | Base URLs of the beacon nodes to use, comma-separated or repeated. Every node on this client's chain is asked `/eth/v1/node/syncing` once a slot and ranked by the answer, list order breaking ties. The first that answers serves the request, so the order is a preference, not load balancing. A node on another chain, or not checked yet, is skipped: see [the chain check](#several-beacon-nodes-the-chain-check), [The per-slot sync check](#the-per-slot-sync-check) and [Ranking and broadcast](#ranking-and-broadcast) |
| `--network` | none | The network every beacon node must be on: a built-in name (`mainnet`, `sepolia`, `hoodi`, `plataberget`) or a directory of published network files, resolved as `beacon --network` resolves it (a directory's `genesis.ssz` is decoded and its bootnodes file read, at startup). A node on another network (preset, genesis, slot duration or genesis fork version) is not used. Startup fails once every configured node has answered and none is on it, and waits while one has not answered. The fork schedule still comes from the beacon nodes and is only warned about when it differs from the network's, so a rescheduled fork needs the beacon nodes upgraded for the client to follow it. Nor does it pick which node the client starts from, since the network's config may be the stale side. Without it the client runs on the first answering node's chain. See [the chain check](#several-beacon-nodes-the-chain-check) |
| `--broadcast` | none | Signed messages to send to every beacon node on this client's chain at once instead of the first that accepts them, comma-separated: `attestations` (attestations, aggregates, payload attestations), `blocks` (blocks and envelopes, never a blinded block), `sync-committee` (messages and contributions). `subscriptions` and `none` are accepted, as Lighthouse takes them, and change nothing, since subscriptions, fee recipients, builder registrations and proposer preferences always go to every node. See [Ranking and broadcast](#ranking-and-broadcast) |
| `--validators-dir` | required | Directory holding the EIP-2335 keystores and `validator_definitions.yml`, which also lists the keys a remote signer holds (see [Remote signing](#remote-signing-web3signer)). Without that file, keystores in the Lighthouse layout (`<0xpubkey>/voting-keystore.json`, password in `--secrets-dir/<0xpubkey>`) are discovered and the file is written |
| `--secrets-dir` | required | Directory holding one password file per keystore, named after the validator's public key |
| `--http-address` | `127.0.0.1` | Bind address for the metrics and keymanager servers |
| `--metrics-port` | `5064` | Prometheus metrics port |
| `--keymanager-port` | `5062` | Keymanager API port. Only bound with `--enable-keymanager` |
| `--suggested-fee-recipient` | none | Execution address to receive block rewards, `0x`-prefixed, for every validator the keymanager API gives no address of its own. Optional, and startup warns when it is absent: without it the beacon node pays its own fallback address (on ethlambda, `beacon --fallback-fee-recipient`), which is the zero address unless its operator set one, and may not be yours. The addresses reach each beacon node as one `prepare_beacon_proposer` request every slot, listing each validator that has an index on chain and an address, as Lighthouse's validator client sends it. The zero address is accepted, as every other client accepts it, but reported at error at startup: it burns the rewards, and builder registrations and proposer preferences sign it for the builder to pay |
| `--gas-limit` | `60000000` | The gas limit every validator targets, unless the keymanager API gives it its own. Before gloas it goes into builder registrations (with `--builder-proposals`). From gloas it goes into the proposer preferences, which are published for every proposal, and the beacon node builds this client's own payloads toward it as well, so a network whose gas limit is not 60M needs it set, or every proposal pulls the limit toward 60M. **Sepolia and Platåberget schedule `200000000`** (their `config.yaml`'s `GAS_LIMIT_SCHEDULE`, which this client does not read yet, [#795](https://github.com/lambdaclass/ethlambda/issues/795)), so on either pass `--gas-limit 200000000`. Must be positive |
| `--graffiti` | none | Text for the graffiti field of proposed blocks, for every validator the keymanager API gives no graffiti of its own. Conflicts with `--graffiti-file`, as in Lighthouse. At most 32 bytes as UTF-8, right-padded with zeros. Refused rather than truncated if longer. Without it a block request carries no graffiti and the beacon node applies its own default; an ethlambda beacon node appends both clients' versions to whatever the graffiti is (see [`rpc.md`](rpc.md#validator-endpoints)). See [Graffiti](#graffiti) |
| `--graffiti-file` | none | A file of per-validator graffiti in Lighthouse's format (`default: <text>`, `<0xpubkey>: <text>`), read again before every proposal and ahead of the keymanager API's per-validator graffiti. Conflicts with `--graffiti`, as in Lighthouse. A file that does not parse refuses startup; once running, a bad read logs a warning and the validator's own graffiti applies, else none. See [Graffiti](#graffiti) |
| `--enable-keymanager` | off | Serve the keymanager API: keystores, remote keys, plus each validator's own fee recipient, graffiti and gas limit. Off by default because it mutates key material |
| `--keymanager-token-file` | `api-token.txt` in `--validators-dir` | File to read the keymanager API's bearer token from instead, for a token shared with other tooling, such as the one ethereum-package gives every validator client. Never written or created, so a missing file, or one shorter than 16 characters once trimmed or holding a character an `Authorization` header cannot carry (anything but visible ASCII, spaces and tabs), is a startup error. Only read with `--enable-keymanager`; set without it, startup warns. See [The keymanager API](#the-keymanager-api) |
| `--web3signer-url` | none | Base URL of a Web3Signer (`https://signer:9000`): the signer a remote key imported through `POST /eth/v1/remotekeys` without a `url` of its own is assigned to. Checked for shape at startup. Keys whose definitions entry names a signer need no default |
| `--builder-proposals` | off | Propose builder blocks before gloas: register each validator with the beacon node's builder (an ethlambda node: `--builder`) and accept a blinded block when the builder's bid wins. Registrations and blinded blocks are fulu and earlier only. From gloas the builder market works through proposer preferences and p2p bids, and neither needs this flag: the preferences are published, and p2p bids compete with the local payload under `--builder-boost-factor` and `--builder-min-bid`, with or without it, as in Lighthouse, Teku and Nimbus. Conflicts with `--self-build-only` |
| `--builder-boost-factor` | `100` | How a builder's bid is weighed against the local payload: the local payload wins iff `local >= factor * bid / 100`. `0` prefers the local payload unless it cannot be built. From gloas it is sent in `produceBlockV4`'s body with or without `--builder-proposals`, so by default a pooled p2p bid competes at par and wins when it pays more than the local payload, or when the local payload cannot be built. Before gloas it is sent only with `--builder-proposals`, and the factor is `0` without it; on a network that schedules no gloas, a factor other than `100`, `--prefer-builder-proposals` or a `--builder-min-bid` set without `--builder-proposals` is warned of at startup, since it does nothing yet. Conflicts with `--prefer-builder-proposals` and `--self-build-only` |
| `--prefer-builder-proposals` | off | Take the builder's block whenever there is a valid bid: this client sends `builder_boost_factor = u64::MAX`. The beacon node still keeps its local payload when its execution client sets `shouldOverrideBuilder`. From gloas with or without `--builder-proposals`; before gloas only with it. Conflicts with `--builder-boost-factor` and `--self-build-only` |
| `--builder-min-bid` | `0` | The smallest builder bid, in gwei, a gloas block may be built on: sent as `produceBlockV4`'s `min_bid`, so the node takes no p2p bid whose value plus execution payment is below it, however the boost factor weighs it. Gloas only, and taken with or without `--builder-proposals`. Worth setting with `--prefer-builder-proposals`, which otherwise takes a 1-gwei bid over the local payload. `0` sets no floor. Conflicts with `--self-build-only` |
| `--self-build-only` | off | Never sign a block built on a builder's payload (Lodestar's `executiononly`). From gloas each block request asks for no bid (`builder_boost_factor` `0`, `min_bid` `2^64 - 1`), and a block whose bid names a builder anyway, from a node that ignores `min_bid`, is refused before slashing protection records the slot. When the beacon node cannot build the payload itself, the slot is missed rather than built on a bid. Before gloas nothing changes: without `--builder-proposals` a blinded block is already refused. Conflicts with `--builder-proposals`, `--builder-boost-factor`, `--prefer-builder-proposals` and `--builder-min-bid` |
| `--init-slashing-protection` | off | Register every loaded key with no slashing-protection record as never having signed, instead of refusing to start. Dangerous: only for keys that have signed nothing anywhere for at least two epochs, and even then it rules out a double vote only, not a surround of an older vote; a key with a history should bring it instead. Never lowers an existing record; remove it once the keys are registered, and startup warns while it is set for nothing |
| `--enable-doppelganger-protection` | off | Sign no attestation or block for a validator until the beacon node has seen it stay silent for a full epoch, and stop if it sees one act meanwhile. Applies at every start and to every key the keymanager API imports, and costs two to three epochs of attestations each time. See [Doppelganger protection](#doppelganger-protection) |
| `--disable-event-stream` | off | Read no beacon node's event stream, so every attestation, sync committee message and payload timeliness committee vote waits for its offset into the slot. One flag for what Lighthouse splits between `--disable-beacon-head-monitor` and `--disable-payload-available-monitor`; Prysm's nearest is `--disable-attest-timely`. For a node whose stream is broken, or a proxy in front of it that holds events back. See [Duties start on the block](#duties-start-on-the-block) |

### What it does today

Attestations, block proposals and attestation aggregation, and from gloas on
the self-built payload envelope and the payload timeliness committee vote.

Each epoch it resolves its validators' indices, fetches their attester duties
for this epoch and the next, fetches this epoch's proposer duties, subscribes
to the committee subnets the attester duties need, and registers each
validator's fee recipient with the beacon node. The subscription also tells the
node which committees this client will aggregate for, which it has to know in
advance so it can collect the votes.

With `--builder-proposals`, before gloas, it also signs a builder registration
(fee recipient and gas limit) for each validator the node resolved and sends
them to every node: the full set after each epoch's refresh, in batches, and
every slot only the registrations whose fee recipient or gas limit changed
through the keymanager API. A block request then carries a
`builder_boost_factor`, and when the node answers with a blinded block it is
signed like a full one and published to `blinded_blocks` on the node that
produced it, with no failover. A publish that node does not confirm is logged
at error and counted as unconfirmed, not as a missed proposal, since the relay
may still publish the block.

From the epoch before gloas on, it also signs a proposer preferences message
(fee recipient and target gas limit) for each of its proposal slots in the
current and next gloas epoch, and sends them to every node. This happens every
slot, whether or not `--builder-proposals` is set: from gloas the preferences
are what carry a proposal's fee recipient, and a node ignores builders' bids
for a slot with none. It reads those duties from the v2 proposer duties
endpoint, whose dependent root the preferences must carry, and publishes each
`(slot, dependent root)` until every node has accepted it, sending the message
as first signed to all of them again each slot until then, and again after a
reorg changes the root. After that it sends each one, as first signed, once
more every epoch while its slot is ahead, at the epoch's second-to-last slot
(or the next poll after it, if a slow node made the client skip that one),
since a node that restarts loses what it accepted. A node restarted mid-epoch
thus lacks the preferences of the slots before that re-send and holds the
later ones; one restarted after it lacks the next epoch's too, all but its
last slot's, which the next epoch's re-send covers. A re-send covers only the
slots that have not started when its duties fetch returns, so slow nodes
ahead of the one that answers can leave the next epoch's first slots out.
Each preference is its own request, and a poll sends all of them, for both
epochs, to every node at once, so a node that does not answer delays the end
of the poll by one request timeout, not the other nodes' delivery. The duties
are fetched from one node at a time, so each node that does not answer,
listed ahead of the one that does, delays every send by a request timeout.
Duties outside their epoch, and all but the first for a slot, are dropped
before anything is signed. A validator with no fee recipient is skipped, with
one warning per epoch naming the count. A preference cannot be replaced for the same slot and root, so a
fee recipient changed through the keymanager API applies from the next
dependent root.

Each slot it wakes at the boundary. If one of its validators proposes that
slot, it signs the RANDAO reveal, asks the beacon node for a block, checks that
the block is for the slot and proposer it asked about, signs it and publishes
it. When the slot's block becomes a beacon node's head, or one third into the
slot at the latest (see [Duties start on the block](#duties-start-on-the-block)),
it fetches the attestation data, checks that it is
for the slot it asked about and that its `index` is one the slot's fork allows
(0 before gloas, 0 or 1 from it, where it is the payload signal), signs for
every validator due that slot, and submits the batch. A node whose answer fails
either check is passed over for the next one in `--beacon-nodes`, before
anything is recorded or signed. Two thirds in, for any duty it
was selected to aggregate, it asks the node for the aggregate covering that
committee's votes on the data it just signed, wraps it with the selection proof
and publishes it.

Aggregation is not a choice. A validator signs the slot under a dedicated
domain, and whether the hash of that signature divides evenly by a modulus from
the committee's size decides it. Signatures are deterministic, so a validator
gets one answer per slot, cannot search for a better one, and cannot decline:
the beacon node checks the same thing when the aggregate arrives.

Proposals are bounded by that one-third mark rather than by the end of the
slot. The specification defines no block-production deadline; the nearest thing
it defines is the point attesters stop waiting for a block, which is the same
instant. A proposal still running then has already lost most of the block's
value, and every second past it comes out of this client's own attestations, so
it is abandoned and the slot's attesters still vote. A blinded block that was
already signed is the exception: its publish runs on its own task, since the
beacon node may wait several seconds on the relay, so an overrun after signing
is logged at info and not counted as a failed proposal, and the task counts the
real outcome (a refusal as a failed proposal, success with its publication
delay).

Electra is the earliest fork it will propose under. A deneb block body has one
field fewer than an electra one, so it would need a container pair of its own,
and it would buy nothing: the attestations this client submits are electra's
`SingleAttestation`, which has no earlier form, so a pre-electra chain is one it
cannot serve whatever it does with blocks. A block from any earlier fork is
refused by name rather than failing to decode.

Blocks are fetched as SSZ by preference and published as SSZ. Signing a block
means computing its `hash_tree_root`, which only the typed container can give;
a hand-written JSON mapping of an execution payload would be a large surface on
which a single wrong field silently produces a signature over the wrong block.
`produceBlockV3` (electra and fulu) is still asked for
`application/octet-stream;q=1.0,application/json;q=0.9`, and a JSON answer is
decoded into the same containers through their serde support in
`ethlambda-types`, the one an ethlambda beacon node writes that answer with.
That is for ethereum-package's blobber, which sits between the client and its
node, rewrites `Accept` to `application/json` on block production, and relays
the node's answer unchanged. Gloas's `produceBlockV4`, which blobber does not
intercept, stays SSZ-only.

From gloas on a proposal is two messages. The client asks for the block with
`include_payload=true` (`produceBlockV4`), publishes the block bare, then signs
the envelope with the proposer's own key under the builder domain and publishes
it with its blobs and cell proofs (`Eth-Blob-Data-Included: true`). Both go out as
SSZ. The envelope shares the proposal's budget (the attester offset, below), so
a proposal that overruns it is abandoned wherever it is. A failure to publish
the envelope is logged at error and counted, and does not fail the proposal. A
block that commits to a builder's bid is signed and published, and its envelope
left to that builder; with `--self-build-only` such a block is refused before
slashing protection records the slot or the block is signed (only the RANDAO
reveal, which is not slashable, was signed before the request).

Each epoch it also fetches the payload timeliness committee duties for the
validators it holds, for this epoch and the next when they are gloas ones. The
gloas fork epoch's are the exception: a node cannot know them before the fork,
so they are fetched at the fork epoch's first slot rather than as the previous
epoch's lookahead. When an epoch's schedule could not be fetched, the client
asks again after each slot's duties until it has one. A member waits for a
node's `execution_payload_available` for the slot, or for
`PAYLOAD_ATTESTATION_DUE_BPS` of the slot at the latest, asks the node for the
payload attestation data, signs it under the PTC domain and submits it. A `204`
(the node knows no block for the slot) means no vote, and so does a node whose
last sync probe said syncing or optimistic: the data is not asked of it, so
no vote is cast over an optimistic head. So a gloas slot runs in this order:
propose at the boundary, attest on the block or at
`ATTESTATION_DUE_BPS_GLOAS`, aggregate at `AGGREGATE_DUE_BPS_GLOAS`, and the
committee vote on the payload or at its deadline, beside the other two rather
than after them, since a payload that arrives early can come before the
aggregation. The attestation and the committee vote are each bounded by the
end of the slot.

Sync committee duties run beside the attester and committee work, not after it.
Each epoch the client fetches its sync duties for the current period and the
next (`POST /eth/v1/validator/duties/sync/{epoch}`, asked at the period's first
epoch) and posts `sync_committee_subscriptions` for the current period's seats,
until the period's end, so the node joins the subnets. The next period's are
added once its boundary is within four epochs. A member waits for the slot's
block, or for `SYNC_MESSAGE_DUE_BPS` (`SYNC_MESSAGE_DUE_BPS_GLOAS` from gloas)
at the latest, reads
`/eth/v1/beacon/blocks/head/root`, signs it and submits one message per
validator. It refuses to sign when the node reports the head optimistic, and
never reads the head from a node whose last sync probe said syncing or
optimistic, since a syncing node answers its stale head with no flag set. A
member selected by the selection-proof hash for a subnet then waits for
`CONTRIBUTION_DUE_BPS` (`CONTRIBUTION_DUE_BPS_GLOAS`), fetches the node's
contribution for that subnet and publishes it wrapped and signed. A subnet whose
contribution cannot be fetched is skipped without stopping the others. Duties
for wall slot `S` are those of the period containing `S + 1`, since members
assigned to slot `S` sign for `S - 1`. Both halves are bounded by the end of the
slot.

Voluntary exits are signed by the keymanager API's `voluntary_exit` route and
by [`ethlambda voluntary-exit`](#voluntary-exit).

### The per-slot sync check

A validator must not sign against a beacon node that is syncing, whose head is
not the network's, or one whose head is optimistic (its execution client has
not validated the payload): the optimistic-sync specification says an
optimistic validator must not propose, attest or take part in sync
committees. So every slot the client asks every configured node on its chain
(see [the chain check](#several-beacon-nodes-the-chain-check))
`GET /eth/v1/node/syncing`, all at once, a sixth of a slot before the slot's
boundary: 2 s on 12 s slots, as Lighthouse does. That is after the previous
slot's last duty and leaves a healthy node time to answer, so the duty loop
reads the answers at the boundary and never waits for one. A node gets until
the next slot's probe to answer.

- **A slot signs nothing when every node that answered is syncing or
  optimistic**, and at least one answered: no block, attestation, aggregate,
  sync committee message, contribution or payload timeliness vote. The epoch's
  duty refresh, the proposer preferences poll and the builder registration
  re-sends are skipped with the slot, and a refresh that was due runs at the
  next slot that passes. The fee recipient re-send still goes out, since it
  signs nothing and a node restarted while syncing must be prepared before its
  first proposal. Each skipped slot is logged at warn and counted on
  `ethlambda_validator_slots_skipped_syncing_total`, also by a client with no
  keys loaded.
- **A node that did not answer does not count as syncing.** Its duty endpoints
  still answer `503` while it syncs, which the client reads as a node to fail
  over from. So nodes that cannot be reached never stop the duties by
  themselves, and only the probe taken for the slot counts: a late answer, or
  one from an earlier slot, opens the check rather than holding it shut. A
  node whose answer is still on its way at the boundary, and that answered
  synced the slot before, holds the check open too, so a slow synced node does
  not lose the slot to a fast syncing one.
- **Requests go to the best-ranked node first**: see
  [Ranking and broadcast](#ranking-and-broadcast). A blinded block still goes
  back to the node that produced it.
- **The head root and the payload attestation data are never asked of a node
  whose last probe said syncing or optimistic, or got no answer**, even after
  the nodes that passed have failed the request. Neither endpoint has a `503`
  for that state: a syncing node answers its stale head, and an optimistic one
  hands out payload data for a block its execution client has not validated.
  So here, unlike for the slot's check, a node that did not answer is not
  given the benefit of the doubt. With no node left to ask, the sync committee
  message and the payload vote are not signed.
- **`el_offline` ranks a node lower and stops nothing**: a node whose
  execution client has just gone offline still has the head it validated
  before, and reports itself optimistic once that stops being true. A node's
  change of state (synced, syncing, optimistic, no answer, `el_offline`,
  behind by its sync distance) is logged once, when it changes.
- **There is no clock-based rule for signing.** The client never skips duties
  because the head looks old: during a network-wide stall every head is old,
  and clients that stop signing then keep the chain stalled. Only the node's
  own `is_syncing` and `is_optimistic` count. `sync_distance` only ranks the
  nodes, and in a stall every node is about as far behind. The
  [clock checks](#clock-checks) read it and `head_slot` as well, and only warn.

### Ranking and broadcast

With several `--beacon-nodes`, every request walks the nodes in rank order
and takes the first answer. The rank comes from each node's last sync probe,
best first, as Lighthouse ranks its nodes:

1. synced and validated: not syncing, not optimistic, execution client
   online, and at most 8 slots behind by its own `sync_distance`
   (Lighthouse's tolerance);
2. synced but optimistic, or with its execution client offline;
3. syncing, or more than 8 slots behind;
4. not probed yet;
5. failing: it did not answer its last probe, or since then did not answer a
   request.

Inside a tier, a node that reports syncing goes last, and an optimistic one
or one with its execution client offline after the rest. That only reorders
tier 3, which a stalled network fills with every node, so a synced node is
still asked ahead of a syncing one there. `--beacon-nodes` order breaks ties,
so a single healthy node, or several equally healthy ones, are asked exactly
as listed. Lighthouse's finer tiers (16 and 64 slots behind) are not kept:
they only reorder nodes that are all behind, which in practice means a stalled
network, where every node is behind by about as much.

A request that times out, or whose connection cannot be made, ranks its node
failing at once, until a probe sent after it answers. So a node that takes requests
and never answers costs one request timeout (8 s) and then nothing until it
answers again, rather than a timeout on every request: an attestation duty
used to wait out the whole timeout on a hung first node every slot, which
left the second node no time. An answer with an error status (a `404` from a
node with nothing to aggregate, a `503` from a syncing one) is an answer and
changes no rank. A probe more than two slots old is not read, which only
matters if the probe task stops, and puts every node back in list order.

Every node here means every node on this client's chain: a node the
[chain check](#several-beacon-nodes-the-chain-check) found on another chain,
or has not checked yet, is never probed, asked or sent a broadcast, whatever
its rank, and an envelope whose producer left the chain goes to the others.

`--broadcast` sends signed messages to every node at once rather than to the
first that accepts them, so they reach the network through every node's gossip
mesh: `attestations` (attestations, aggregates, payload attestations),
`blocks` (blocks and envelopes) and `sync-committee` (messages and
contributions), comma-separated. None by default, as in Lighthouse, so the
client behaves as before unless asked. Subscriptions, fee recipient
preparations, builder registrations and proposer preferences always go to
every node; `subscriptions` and `none` are accepted for compatibility and
change nothing.

- **One accepting node is success.** A message one node took is on the
  network. A node that refused is logged.
- **Failing nodes are sent it last.** A node ranked failing is sent a
  broadcast only when no other node took it, so a hung node does not hold
  every broadcast back by a request timeout.
- **Half a second after the first acceptance, the rest are cut off.** A node
  still sending by then is not waited for, so a node that hangs costs a
  broadcast half a second, not a request timeout a proposal's deadline would
  cut short. It is not ranked failing for it: a node that is only slower (to
  import a block, or to take a large envelope) would otherwise be dropped
  from every broadcast until its next probe, slot after slot. A node that
  really hung is ranked failing once its probe gets no answer.
- **A block reports the best answer**: imported (`200`) over broadcast but
  not imported (`202`) over refused, each node's answer logged. A blinded
  block still goes only to the node that produced it.
- **An envelope goes to its block's producer first**, then to the other
  nodes once the producer has answered, or after half a second without an
  answer. The producer certainly holds the block the envelope reveals; a
  node that has not imported it yet queues or drops the envelope, and
  waiting for the producer's answer gives each a round trip longer to import
  it. The half-second bound is for a producer that holds the request open
  (one that answered the block `202` and never imported it waits for it),
  which would otherwise keep the envelope from every node until the
  proposal's deadline. An envelope sent without its blobs goes to the
  producer first, with or without the flag, since only it cached them; if it
  does not take it, the other nodes are tried in rank order, since a block
  with no blobs can be revealed through any of them.
- **Signed once.** Every message is signed, and recorded by slashing
  protection, before it is sent, however many nodes it is sent to.

### Clock checks

Every duty is timed by this client's own clock. Ahead by more than half a
second, an ethlambda beacon node refuses its block requests; ahead by a few
seconds, its attestations vote for the parent; behind, every duty goes out late
and nothing refuses it. So the client compares its clock with each beacon
node's on every sync probe, and watches its own for steps. These checks only
warn, since a difference does not say which clock is off. A client and a node
on one host share a clock, so between the two only a split setup is caught.

- **`Date`.** The probe answer's `Date` header, taken at the middle of the
  second it names, less the midpoint of the round trip; answers slower than a
  second are not used. A node is warned about once the median of its last three
  samples is 2 s or more off, which is as fine as a one-second header can tell.
  A sample is read for six slots, so a node that stops sending a usable `Date`
  loses its estimate rather than keeping an old one.
- **Slots.** A `head_slot` more than one slot past this client's wall slot
  means this client's clock is behind, as Lighthouse checks. A node that
  reports a nonzero `sync_distance` and is not syncing also gives its own wall
  slot, `head_slot + sync_distance`, compared with this client's at send and at
  receive, so a boundary crossed while the request was out does not count.
  (Teku reports a distance of 0 whenever it is in sync, so no other distance
  is read.) A node that sends no `Date` gets this check alone.
- **Steps.** Each pass of the duty loop compares how far the wall clock moved
  with how far the monotonic clock did. A step of half a second or more is
  logged and counted on `ethlambda_validator_clock_steps_total`: back before
  the slot served, the loop waits for the wall clock to reach the next slot
  again; forward past the next slot, the slots stepped over are lost; within
  those, only the next boundary moves. A loop back more than a slot late with no step (a duty
  overran, or the process was paused) is logged too.

The warnings name the node by its position in `--beacon-nodes`, from 0, and
recur at most once an epoch while the clocks disagree.
`ethlambda_validator_beacon_node_clock_offset_seconds` carries each node's
offset. A warning from the slots alone shows there only the offset the slots
prove, which can read under 2 (about 1.9 s on 12 s slots when this client is
behind), so an alert meant to match the warnings fires lower; see
[Metrics](./metrics.md#validator-client). A slot disagreement proving less
than half a second, a boundary crossed inside a long round trip, is not
warned about.

### Doppelganger protection

Off unless `--enable-doppelganger-protection` is passed. A doppelganger is a
second validator client running the same key, usually a key moved to a new
machine while the old one still runs. Slashing protection cannot see it, since
each client's record holds only what that client signed. With the flag on, a
key signs no attestation or block until its beacon node has watched it stay
silent for a full epoch, through the standard
`POST /eth/v1/validator/liveness/{epoch}`. The rule is Lighthouse's:

- A key loaded at startup, or imported through the keymanager API, in epoch
  `E` is watched from `E + 1`. Activity in `E` is not held against it, since it
  is most likely this client's own previous process, restarted within the
  epoch.
- Three quarters into every slot the client asks about the previous epoch and
  the current one. A key found live in an epoch it is watched for stops the
  client with an error naming the validators.
- An epoch counts as clean at the last slot of the epoch after it, once its
  attestations have had their full inclusion window, and only when both
  questions were answered and the key was explicitly reported not live. A
  failed query, or a beacon node reporting itself syncing or optimistic, makes
  no progress. With several `--beacon-nodes`, a syncing one is skipped for the
  next.
- So a key registered in `E` signs from `E + 3`, missing two to three epochs of
  attestations. A key registered in epoch 0 (before genesis or during the
  chain's first epoch, at startup or by import) signs at once, as Lighthouse's
  do: every validator missing those epochs together could stall a new chain.
- An epoch that could not be counted clean (no beacon node answered at its
  deciding slot) is not asked about again, since a node answers only for the
  previous, current and next epoch: the key waits for the next epoch instead,
  and the miss is logged at error.

Withheld while a key is checked: attestations, blocks (with the RANDAO reveal)
and aggregates, the last because a node marks an aggregator live and would
report this client as a doppelganger of itself. Everything else goes on: duties
are fetched and subnets subscribed, so the key is ready the moment it is
cleared, and sync committee messages and contributions, payload timeliness
votes, builder registrations, proposer preferences and voluntary exits are
signed as usual, as Lighthouse's client signs them during its own check. None
of them is slashable, and an ethlambda beacon node counts none of them as
liveness: it counts attestations, aggregates and block proposers. A beacon node
that did count one of them (a sync committee message, say) would report this
client's own message back as a doppelganger and stop it; against such a node,
leave the flag off.

A key with no validator index yet is not asked about and stays withheld; with
no index it has no duties either. A key deleted through the keymanager API is
no longer checked, so a copy the operator now runs elsewhere on purpose does
not stop this client, and importing it again starts the check again.

Under a supervisor that restarts the client (`Restart=on-failure`), a detection
becomes a restart loop: each start checks again and stops again for as long as
the other client runs. That is safe, since a key under the check signs nothing,
but the loop does not end until the other client is found and stopped. The
check is not foolproof either: two clients with the same key started together
both see silence and both start signing, and a doppelganger that is down for
the epochs checked goes unseen until it comes back, when nothing is checking any
more. `ethlambda_validator_doppelganger_detecting` counts the keys still
withheld.

### Duty offsets come from the network

The slot length and the duty offsets are read from the beacon node's
`/eth/v1/config/spec`, not divided out of a compiled-in constant. The
specification states them as `SLOT_DURATION_MS` plus basis points of it,
`ATTESTATION_DUE_BPS` and `AGGREGATE_DUE_BPS`, which on mainnet's 12-second slot
work out at 3999 ms and 8000 ms. Gloas moves both earlier
(`ATTESTATION_DUE_BPS_GLOAS`, `AGGREGATE_DUE_BPS_GLOAS`) and adds
`PAYLOAD_ATTESTATION_DUE_BPS` (and `PAYLOAD_DUE_BPS`, which the node uses), so
the clock picks the pair by the fork of each slot's own epoch. The sync
committee offsets (`SYNC_MESSAGE_DUE_BPS`, `CONTRIBUTION_DUE_BPS` and their
`_GLOAS` variants) are read and picked the same way.

`SECONDS_PER_SLOT` no longer exists in the specification and is accepted only as
a fallback, since deployed nodes still send it. A node sending both is required
to agree with itself.

### Duties start on the block

The offsets are deadlines, not start times. The specification has an attester
sign once it has the slot's block or once the offset has passed, whichever comes
first, a sync committee member likewise, and a payload timeliness committee
member as soon as it has seen the payload and its blob data. So the client reads
every beacon node's `GET /eth/v1/events`, one connection per topic: `head`, and
on a network that schedules gloas `execution_payload_available` as well, opened
when gloas first shows in the fork schedule, at startup or once the chain check
picks it up later.

- A `head` for the current slot, not `execution_optimistic`, starts the slot's
  attestation and sync committee message.
- An `execution_payload_available` for the current slot starts its committee
  vote. The block alone never does.
- What is signed is still the node's answer, fetched through the usual failover,
  and the early attempt signs it only if it is about the event's block: the
  attestation data's `beacon_block_root`, the head root, or payload attestation
  data that also says `payload_present` and `blob_data_available`. Otherwise
  nothing is recorded or signed, and the duty asks again on the next report
  about the slot it has not tried (another node's, or another block's), or
  runs at its offset if none comes, as it would have with no event. An answer
  still outstanding at the offset is dropped there, so an event never makes a
  duty later. Each duty is signed at most once a slot either way.
- An event from any node starts a duty. The check above is what makes that safe
  when the node answering has not imported the block yet: that attempt
  declines, and the answering node's own report of the block starts the next.
- A stream that drops is opened again after a second, the wait doubling to 12
  seconds while the node stays unreachable. One silent for a minute is taken
  for dead and opened again, logged at debug only, since a stream quiet by
  design (`execution_payload_available` before gloas, on a node that sends no
  keep-alives) does that every minute. While a stream is down the duties keep
  their offsets, so a broken stream costs the early start and nothing else.
- Aggregation and sync contributions keep their own offsets, and nothing waits
  after the block before attesting.

`ethlambda_validator_duty_triggers_total` counts what started each duty (see
[Metrics](./metrics.md#validator-client)). An ethlambda beacon node builds its
`single_attestation` events while any client is subscribed to any topic, so this
client's subscription turns that work on (see
[`rpc.md`](rpc.md#get-ethv1events)). `--disable-event-stream` reads no stream.

### Proposer duties are less durable than attester ones

Worth knowing if a proposal is ever missed after a reorg. An attester schedule
depends on the block two epochs back and survives anything shallower; a
proposer schedule depends on the block one epoch back, so a reorg that leaves
attester duties untouched can still move a proposer between slots. This client
fetches proposer duties once per epoch, at the boundary, so a reorg inside the
epoch is not picked up until the next one.

### Remote signing (Web3Signer)

A validator's key can stay in a [Web3Signer](https://docs.web3signer.consensys.io/)
instead of this process. Each signature is then one `POST
/api/v1/eth2/sign/{pubkey}` carrying the message in full (the attestation
data, the block header, the aggregate, and so on), the fork it is signed under
and the signing root, and the signer answers with the signature. Every duty
this client performs signs this way when the key is remote, the gloas envelope
and payload attestation included; a slot's attestations are requested
concurrently, so a hundred keys behind one signer cost one round trip rather
than a hundred in series.

Because the message travels in full, the signer's own slashing protection
applies to it, on top of this client's: a remote key has a record in
[`slashing_protection.json`](#slashing-protection) like a local one, and a
block or attestation is checked against it and recorded before the signer is
asked. So a remote key written into the definitions file by hand is refused at
startup until it has a record, the same as a local keystore; one imported
through the keymanager API is registered as it is imported. The two records
are separate (see
[Spec Deviations](./spec_deviations.md#the-validator-client-keeps-eip-3076s-minimal-watermarks-not-full-history)):
a key moved to or from a signer carries its history through the signer's own
tools. A signer refusal (`412`) is logged, counted as a
signing failure and never retried; so is a key the signer does not hold, a
signer that cannot be reached, and an answer that does not verify: every
signature a signer returns is checked against the validator's public key and
the signing root before it is used, so a signer holding another key under that
pubkey, or computing another root, costs the signature rather than publishing
one no peer accepts. That check runs off the duty loop, a core per signature,
so a large batch of answers does not hold the loop up. Each duty asks for its
signatures all at once
and gives each one 2 seconds: a signer that has not answered by then loses the
signatures it owes and no others, so the duty publishes whatever arrived,
local keys and other signers' keys included. It publishes them together,
though, so while a signer hangs every duty's batch goes out up to 2 seconds
late, the local keys' share of it too: an attestation is then published 2
seconds after the attestation offset, still ahead of the aggregation one. One
signer is sent at most 64
requests at a time and the rest of a batch waits its turn inside the same 2
seconds, so a signer costs this client 64 connections however many keys it
holds; the sub-command also raises its open-file limit at startup, as `node`
and `beacon` do. Aggregator selection proofs are
remembered once produced, so the one the epoch's subnet subscription asked for
is not asked for again by the aggregation. Those subscriptions are sent from a
task of their own, started once the epoch's first slot has had its block, so
the round trips for their selection proofs never stand between a slot boundary
and a proposal. With no duty waiting on that task, its proofs get 8 seconds
rather than 2: one that misses is a duty subscribed without the aggregator
role, and at startup, or with thousands of remote keys, two epochs of proofs
queue for the signer's 64 request slots. Nothing is asked of the signer at startup or at
import: a signer may start after this client does.

A voluntary exit for a remote key is signed the same way (`VOLUNTARY_EXIT`),
through the keymanager API's `voluntary_exit` route. The signer derives an
exit's root itself and refuses a request naming another, so it is told the one
fork version the exit is signed under, as both `previous_version` and
`current_version`: from deneb on that is the capella version (EIP-7044), not
the fork the schedule has at the exit's epoch. [`ethlambda
voluntary-exit`](#voluntary-exit) decrypts a keystore file, so it signs for
local keys only.

Builder registrations (`VALIDATOR_REGISTRATION`, with `--builder-proposals`)
and gloas proposer preferences (`PROPOSER_PREFERENCES`) are signed by the
signer too. A registration is sent with no `fork_info`: its domain is the
genesis fork version under a zero validators root, which the signer takes from
its own network configuration. A preference is told the fork at its proposal
epoch, the one its domain comes from. Like the subscriptions, the epoch's full
registration send starts after the slot's block, and each chunk of it gets the
same 2-second budget; a registration that fails to sign is left out until the
next epoch's send.

A remote key is declared in `validator_definitions.yml` with `type:
web3signer` and a `url` where a local entry has `type: local_keystore` and its
two keystore paths:

```yaml
- enabled: true
  voting_public_key: "0x9612…0d07"
  type: web3signer
  url: https://signer:9000
```

or imported at runtime through `POST /eth/v1/remotekeys` (below). A `url`
left out of that request means `--web3signer-url`. An entry written without a
`type` (every entry from before remote signing) is read by its fields; one
naming both keystore paths and a `url` is refused at startup rather than read
as either. So is a `web3signer` entry carrying a field this client does not
implement, such as Lighthouse's `root_certificate_path`: skipping it would sign
through a connection the operator did not describe. `description` is the one
exception, since Lighthouse writes it on every entry, and
`suggested_fee_recipient`, `graffiti` and `gas_limit` are not such fields: they
are read on either kind of entry (see the proposer settings below). A local
entry is read past the fields this client does not have, so a file Lighthouse
wrote for local keystores loads as it is; those fields are not kept when the
file is next rewritten. The `url` must not carry credentials, a query string
or a fragment.

The signer is reached over HTTP or HTTPS. HTTPS is verified against the Mozilla
root store bundled into the binary (`webpki-roots`), **not** the operating
system's trust store, and no other CA can be added: a signer behind an internal
or self-signed CA fails every TLS handshake, and every signature for its keys
is then counted as a signing failure. Client certificates are not supported
either. Put such a signer behind a certificate from a public CA, or reach it
over plain HTTP on a private network.

### The keymanager API

Off unless `--enable-keymanager` is passed. It serves `GET`, `POST` and
`DELETE /eth/v1/keystores`, authenticated with a bearer token read from
`api-token.txt` in the validators directory and generated there on first start
if absent. The token file is written `0600` and a file too short to be a real
token, or holding a character an `Authorization` header cannot carry (anything
but visible ASCII, spaces and tabs), is refused rather than accepted.

`--keymanager-token-file` names another file to read the token from instead,
and `api-token.txt` is then neither read nor written. That file is the
operator's: the client only reads it, trimmed and held to the same checks, and
a missing or refused one stops it at startup rather than being replaced with a
generated token.

It serves `GET`, `POST` and `DELETE /eth/v1/remotekeys` for the keys a
Web3Signer holds. The two routes partition the store: `/keystores` lists and
deletes local keys only, `/remotekeys` remote keys only, and a key asked of the
wrong route is `not_found`. An import of a key either route already holds is
`duplicate`. `POST /remotekeys` persists each key to the definitions file and
registers it in the slashing-protection record before it starts signing, the
same order the keystores import uses, and `readonly` is always `false`: this
client has no key it cannot delete. These routes carry no slashing-protection
history, since the specification gives them no field for it: a remote key
imported with no record starts as never having signed, and `DELETE
/remotekeys` leaves the record in place. `DELETE /keystores` exports nothing
for a key a remote signer holds.

A delete through either route reads the definitions file once and saves it
once for the whole request, and takes the keys out of memory in between, so a
request naming hundreds of keys does not hold up the duties' signatures. The
two routes can only disagree with the file about a key's kind after the file
was edited by hand under a running client. A delete that then finds the key in
memory as its own kind, and in the file as the other route's, stops signing
with it and answers `error` naming the other route, not `deleted`: the entry
it leaves would load the key again at the next start. `DELETE /remotekeys` of
a remote entry whose key this process runs from a local keystore removes the
entry and leaves the local key, and its per-validator settings, as they are.
Its answer is `error` too, naming `/eth/v1/keystores`, and never `deleted`:
the key is still signing here until that route removes it.

A deleted key's fee recipient is no longer sent to the beacon node, from the
next slot on. The node keeps the address it was last given for that validator
until it expires the entry or restarts, so a client the key moved to on the
same node prepares it with its own address without this one overwriting it.
An imported key's fee recipient is first sent at the next epoch boundary, when
its index is resolved, which is also when its proposer duties are first
fetched.

It also serves `POST /eth/v1/validator/{pubkey}/voluntary_exit`, which signs a
voluntary exit for a validator this client holds, in a local keystore or in a
remote signer, and answers with the `SignedVoluntaryExit`, for the exit's
`epoch` query parameter or the current epoch when none is given. **It does not publish the exit.** As the
specification has it, the caller hands the message to a beacon node's
`POST /eth/v1/beacon/pool/voluntary_exits`, or holds on to it. The validator
index comes from the beacon node on each call, so a key whose deposit the chain
has not processed yet is a `404` saying so.

And it serves `GET`, `POST` and `DELETE` on
`/eth/v1/validator/{pubkey}/feerecipient`, `/graffiti` and `/gas_limit`, which
give one validator its own value in place of the command line's default:

| Setting | Default | Takes effect |
|---|---|---|
| `feerecipient` | `--suggested-fee-recipient` | Once the duties of the slot it is set in are done, when the fee recipients are sent to the beacon node again, as they are after every slot's duties (the next slot's while a slow beacon node still holds the last send). A validator imported since the last epoch boundary, or with no index on chain yet, is first sent once an epoch boundary resolves its index. A block proposed before then pays the address the node was last given, and the check before signing reports the mismatch. With `--builder-proposals`, the next builder registration carries it too, usually at the next slot (later while the epoch's full registration send is still running) and again every slot until a node accepts it or the epoch's full send carries it, and an ethlambda beacon node takes it from there. A `DELETE` that leaves a validator with no address at all (no `--suggested-fee-recipient` either) sends no fee recipient and no registration, so the beacon node and the builder keep paying the address they were last given. From gloas, the proposer preferences carry it, from the next dependent root on |
| `graffiti` | `--graffiti` | The next proposal, unless `--graffiti-file` names the key or has a `default` line (see [Graffiti](#graffiti)) |
| `gas_limit` | `--gas-limit` | Before gloas, the next builder registration with `--builder-proposals` (usually at the next slot, later while the epoch's full registration send is still running, and again every slot until a node accepts it or the epoch's full send carries it), and stored and served only without it. From gloas, the proposer preferences' target gas limit, from the next dependent root on, flag or not |

**These persist.** Each is written onto the validator's entry in
`validator_definitions.yml` (`suggested_fee_recipient`, `graffiti`, `gas_limit`,
Lighthouse's layout, so a file Lighthouse wrote loads here with the three in
effect) before the request is answered, and loaded again at startup, so a
restart runs with what the operator set. They are the validator's settings
whichever way its key signs, so a key in a remote signer takes them too, on its
`web3signer` entry. The file does not go back to Lighthouse unchanged: a save
here keeps only the fields this client reads, so an entry's `description` and
`builder_*` settings are dropped the first time this client rewrites the file,
which every one of these requests does.

A write that fails is a `500` that changes nothing. One `500` is different and
says so: the file was replaced but its directory could not be flushed, so the
change is in effect, here and at the next start, and only its survival of a
power loss is in doubt; repeating the request flushes it. A request made while
a keystore import is running is answered once the import is done, since both
write the same file. Where the file names one key twice, the change goes to
the enabled entry, the one a restart reads.

The fields may also be put in the file by hand before the client starts; a
malformed one refuses startup, before any keystore is decrypted. Deleting a
keystore drops its entry and its
values with it. Importing a key whose entry is already in the file, a
re-import or one that enables a disabled entry, keeps the entry's values and
runs with them at once; if one of them is malformed the import is refused and
nothing is written.

A few answers worth knowing: `GET feerecipient` is a `500` when the validator
has no address and there is no `--suggested-fee-recipient` default, as
Lighthouse answers it; `POST feerecipient` refuses the zero address, as the
specification requires; `GET graffiti` answers what the next proposal would
carry, `--graffiti-file` included, and an empty string when no graffiti is set
anywhere; `POST graffiti` refuses text over 32 bytes rather than
truncating it; `POST gas_limit` refuses `0`, as `--gas-limit` does; and every
route answers `404` for a key this client does not hold.

The keystore routes carry slashing-protection history. `POST` refuses every
key in the request if its `slashing_protection` does not parse or is for
another chain, and otherwise writes that history before any key is saved, so a
key never loads ahead of it; a validator the history names without a keystore
in the request gets a record too. `DELETE`
returns the deleted keys' records as a minimal EIP-3076 interchange, answering
`not_active` for a key that is gone but still has a record.

The specification requires TLS. This binds to `--http-address`, loopback by
default; exposing it further means putting a TLS terminator in front.

### Graffiti

A block's graffiti comes from the first of these that has one for the
proposing validator, Lighthouse's order:

1. `--graffiti-file`'s line for the validator's public key;
2. `--graffiti-file`'s `default` line;
3. the validator's own graffiti, set through the keymanager API or written by
   hand into `validator_definitions.yml`;
4. `--graffiti`.

`--graffiti-file` and `--graffiti` cannot be given together, as in
Lighthouse, so the file and the last step never both apply. With a file, a
validator it has no line for and no `default` line covers, or a proposal whose
read of it fails, takes the validator's own graffiti, else none.

With none of them, the block request carries no `graffiti` parameter and the
beacon node applies its own default. An ethlambda beacon node reads an absent
graffiti as an empty one and appends both clients' codes and commits to it,
as it does to any graffiti (see [`rpc.md`](rpc.md#validator-endpoints)).

`--graffiti-file` takes Lighthouse's format, so a file written for
Lighthouse's flag works unchanged:

```text
default: ethlambda
0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: mr f was here
```

A line splits at its first `:`. The key before it is exactly `default` or a
`0x`-prefixed public key, and the text after it, trimmed, is the graffiti, so
the text may hold colons of its own (`graffitiwall:720:641:#ffff00`). An empty
graffiti is a graffiti, 32 zero bytes, which a beacon node may treat apart
from an absent one. Lines of whitespace alone are skipped; there is no comment
syntax, so a `#` line is refused. A key named twice takes its last line.

The file is read again before every proposal, and for every `GET graffiti`,
and each read starts from nothing: an edited line applies from the next
proposal, and a deleted one stops applying there. (Lighthouse merges each read
into what it read at startup, so a deleted line stays in effect there until a
restart.) A script can therefore rotate graffiti by rewriting the file; write
it to a temporary path and rename it over the old one, so a proposal never
reads it half-written.

A file that cannot be read or does not parse, a graffiti over 32 bytes among
them, refuses startup, as an over-long `--graffiti` does. So does a path that
is not a regular file (a FIFO, a directory, a device), a file over 16 MiB, and
one not read within 5 seconds, so a stalled mount refuses startup rather than
hang it. A FIFO is refused at once, not after the 5 seconds: the file is
opened without waiting for a writer (`O_NONBLOCK`), and what was opened is
checked to be a regular file before it is read. One read within 5 seconds
but in more than 250 ms starts with a warning, since a proposal gives up on a
read that slow (see below); a cold cache can make one read that slow and the
next ones fast, so it is not refused. Once the client is running,
the same failure costs only the file: the proposal takes its graffiti from the
next source in the list and logs a warning, and the client logs an info line
once the file reads again. `GET graffiti` skips the file the same way, but
warns only at the first of a run of failed reads, so a client polling it does
not repeat the warning. A read that takes longer than 250 ms is given up on
the same way, so a stalled mount cannot cost a proposal its slot; the read
runs alongside the RANDAO signature, so it adds nothing when that takes as
long. A UTF-8 byte-order mark at the start of the file is ignored.

Each read runs on a thread of its own, and only one runs at a time: a
proposal or `GET graffiti` that comes while one runs takes that read's answer
rather than starting another. The 250 ms count from the read's start, so a
caller that joins a running read waits only what is left of them, and one
that finds the read running longer than that skips the file at once. So a
stalled file holds one thread, never one slashing protection runs on, and
costs a proposal at most 250 ms; and a caller that joins a read takes the
file as it was at most 250 ms before it asked. The price of one read at a
time: a read that never returns, as one of a hung network mount does, turns
the file off until it returns or the client restarts. Every proposal
meanwhile skips the file with a warning, even once the file is put right,
since the stuck read is still the running one. A FIFO put in the file's place
cannot cause this, since it is refused at once like a directory, and the next
proposal reads the file again; only a filesystem that never answers an
`open`, `fstat` or `read` can.

One thing differs from Lighthouse besides the reload: the keymanager API's
graffiti routes stay open while the file is set: a `POST graffiti` is written to `validator_definitions.yml` and
applied as usual, and shows in proposals and in `GET graffiti` whenever the
file names neither the key nor a `default`. Until then `GET graffiti` keeps
answering the file's text, since that is what the next proposal carries.

### Stopping

SIGINT or SIGTERM stops the client cleanly once its startup is done. It logs
`Shutdown signal received`, starts no other slot, and lets the work in flight
finish:

- The slot in progress, with its proposal, gloas envelope and attestations,
  and a signed blinded block's publish, get up to 8 s after the signal, which
  is what Prysm's validator client waits. On a 12 s slot that covers the
  proposal and the attestations; the aggregates, sync committee contributions
  and payload timeliness vote due later in the slot may be cut. Cutting any of
  it is safe: a block or attestation is recorded in slashing protection before
  it is signed, and the rest is not slashable.
- The keymanager API takes no new request, and one in flight gets up to 60 s
  more, so an import is not cut between saving its keys and registering them.
- The sends that are repeated anyway (proposer preferences, subnet
  subscriptions, builder registrations, the fee recipient re-send) are not
  waited for.

It then logs `Shutdown complete` and exits 0. Three more signals end it at
once, with exit code 1. Anything still running on the client's threads by
then, such as an import the keymanager wait gave up on, gets up to 2 s more
before the process exits; signals do nothing in those 2 s.

Both signals are listened for from the moment the client starts. One sent
during startup, while the keystores are decrypted and the beacon node is
first asked for the chain, logs `Shutdown signal received during startup`
and ends the process at once with exit code 0: no duty has run and the
keymanager API has taken no request, so nothing is signed and there is
nothing to wait for. That holds in a container too, where the client is
PID 1 and a signal with no handler is ignored.

A signal sent while the client stops on an error (an unusable
slashing-protection record, a doppelganger) does not cut its keymanager wait
short: it is logged, and three more end the process with exit code 1.

systemd's defaults need no change: `KillSignal` is SIGTERM, and `TimeoutStopSec`
(90 s) covers both waits. `docker stop` sends SIGTERM and waits 10 s, enough for
the slot; with `--enable-keymanager`, pass `--stop-timeout 70` so an import in
flight is not cut short.

### Metrics

Served on `--metrics-port`, prefixed `ethlambda_validator_` rather than the
`lean_` used elsewhere in this repository, since this process follows the
beacon chain. Every series is registered at startup so it reads zero rather
than being absent before its first event, which is what lets an alert fire on
"attestations stopped". See [Metrics](./metrics.md#validator-client).

`GET /health` on the same port answers whether the client can do its duties:
`200` when it can, `503` when it cannot or has not started yet, with the checks
behind the answer.

```json
{
  "status": "unhealthy",
  "service": "ethlambda-validator",
  "checks": {
    "beacon_nodes": { "usable": 0, "configured": 2 },
    "validators": { "loaded": 64, "resolved": 64 },
    "slashing_protection": { "last_write_ok": true },
    "started": true,
    "schedule_current": true
  }
}
```

It reads state the client already keeps and sends no request of its own, so it
is cheap to poll.

- **`beacon_nodes`**: `usable` counts the nodes whose latest
  [sync probe](#the-per-slot-sync-check) was answered, neither syncing nor
  optimistic, and is at most two slots old. One usable node is enough: a client
  with some nodes down and one usable is `healthy`, with the counts in the
  body.
- **`validators`**: the keys loaded, and those the last duty refresh resolved to
  an index. Reported, never failing: a key waiting for activation has no index
  yet, and a client started with no keys, to wait for a keymanager import, is
  idle on purpose. A key doppelganger protection still withholds counts as
  loaded.
- **`slashing_protection.last_write_ok`**: the record's last write succeeded,
  and the last access to it did not give up after waiting 3 s for another one
  to finish. A failed write keeps it `false` until a later write succeeds. A
  full disk or a read-only remount under `--validators-dir` shows up here.
- **`started`**: a duty refresh has succeeded since the process started.
- **`schedule_current`**: the attester schedule the last successful duty
  refresh left held reaches the current epoch: the refresh's own epoch, and
  the next when its lookahead fetch went through too. A node can answer its
  probe synced and still fail every refresh, or every lookahead; once the
  schedule runs out the client has no attestations to make. `true` before the
  first refresh and before genesis. A client with no validator resolved (no
  keys, or keys waiting for activation) holds no schedule, and a refresh
  counts through the next epoch, so it is not caught out at each boundary.

`status` is one of three:

- `healthy` (`200`): started, at least one usable node, the last write went
  through, and the schedule is current.
- `starting` (`503`): no refresh has succeeded yet and nothing else has failed.
  A node not probed yet does not count against a client that has not started,
  so a normal startup reads `starting` throughout. Once started, a node with no
  probe counts as unusable.
- `unhealthy` (`503`): anything else.

Remote signers are not checked, since that would take a request to each.
`ethlambda_validator_healthy` carries the same answer as a series, set from the
same report on every scrape.

Point readiness checks, load balancers and uptime monitors at it, not a
Kubernetes liveness probe: it answers `503` while every beacon node is down or
syncing, which restarting the validator client does not fix.

## `voluntary-exit`

`ethlambda voluntary-exit` signs a voluntary exit for one validator and hands
it to a beacon node, which validates it against its head and gossips it. It is
a command of its own rather than part of `ethlambda validator`: it takes one
keystore and none of the client's flags, runs once and ends.

```sh
ethlambda voluntary-exit \
  --keystore ~/validators/0xabc.../voting-keystore.json \
  --password-file ~/secrets/0xabc... \
  --beacon-node http://localhost:5052
```

| Flag | Default | Meaning |
|---|---|---|
| `--keystore` | required | The validator's EIP-2335 voting keystore |
| `--password-file` | required | The file holding that keystore's password. A trailing newline is ignored |
| `--beacon-node` | `http://localhost:5052` | Base URL of the beacon node's HTTP API. One node, not a list: this is a one-shot command, and an operator whose node is down picks another |
| `--epoch` | the current epoch | The exit's epoch, before which the chain refuses it. An earlier one is as good as the current one. A later one needs `--presign`: a node refuses an exit whose epoch has not come, so the command refuses to publish one |
| `--presign` | off | Sign the exit and print it as JSON on stdout without publishing it, for an operator who wants to hold a signed exit for later. Logs go to stderr, so the JSON pipes cleanly into a file |
| `--no-confirmation` | off | Publish without asking for the confirmation phrase. For scripts; use with care |
| `--no-wait` | off | Return as soon as the beacon node has accepted the exit, without waiting for the chain to process it |

**A voluntary exit is irreversible.** Once the chain processes it the
validator is queued to leave, stops earning after its exit epoch, and the key
can never validate again. So before publishing anything the command refuses a
beacon node that is still syncing, refuses a validator the chain would refuse
(one that is not `active_ongoing`, or not yet `SHARD_COMMITTEE_PERIOD` epochs
past its activation, naming the epoch it becomes eligible at), and then prints
a warning and asks for the phrase `Exit my validator` on stdin. Anything else,
an empty stdin included, aborts without publishing and with a failing exit
status, so a script cannot take an exit that never went out for one that did.

The shard committee period is measured the way the chain measures it: against
the epoch the exit is processed in, which is now for an exit being published
and the exit's own epoch for a `--presign` one naming a later epoch. Its
length is the beacon node's own `SHARD_COMMITTEE_PERIOD`, read from
`/eth/v1/config/spec`, so a devnet that shortens it is followed. One rule
of the chain's cannot be checked up front: from electra on it refuses a
validator with a partial withdrawal still pending. That refusal comes back as
the beacon node's `400`, with its reason.

After publishing, unless `--no-wait` is given, it polls the validator's status
once a slot, for up to two epochs. When the chain reports `active_exiting` it
prints the current, exit and withdrawable epochs and how long until the exit
epoch, and returns; **keep the validator running until that epoch**, since it
still has duties until then. Any later status (`exited_*`, `withdrawal_*`) and
`active_slashed` end the wait too, reported as such. If the chain has not
processed the exit when the wait runs out, the command says so and returns
successfully, since the exit was published; a beacon node that cannot answer a
poll is asked again at the next slot rather than failing the run.

Exits are signed for the fork that processes them, not the one their epoch
falls in. From deneb on that is `CAPELLA_FORK_VERSION` whatever epoch the exit
names (EIP-7044), an epoch from before deneb included, so a pre-signed exit
stays valid across every fork to come. The command signs that way, and the
[keymanager API](#the-keymanager-api)'s `voluntary_exit` route does too.

## `slashing-protection`

Moves the validator client's EIP-3076 history in and out of its
`--validators-dir`, offline. It takes the lock the client holds while running,
so it refuses while a client runs on that directory, and it needs no beacon
node: the record names its own chain.

```sh
# Bring a key's history from another client before its first start here.
ethlambda slashing-protection import --validators-dir ./validators interchange.json

# Hand the history over before running the keys elsewhere.
ethlambda slashing-protection export --validators-dir ./validators out.json
ethlambda slashing-protection export --validators-dir ./validators --pubkeys 0xab..,0xcd.. out.json
```

| Sub-command | Does |
|---|---|
| `import <file>` | Merges a version 5 interchange, complete or minimal, into the record. Each validator is reduced to its highest slot, source and target and merged by maximum, so nothing already recorded is lowered and slashable data in the file is absorbed rather than refused, except an attestation whose source is at or past its target outside genesis, which is refused. All or nothing. With no record yet, the import creates one for the interchange's chain, and a failed import creates nothing; the client refuses the record at its next start if that is not its beacon node's chain |
| `export [--pubkeys ...] <file>` | Writes the record, or the named validators' part of it, as a minimal version 5 interchange, readable by its owner only. A named validator with no record fails the export, so a typo or the wrong directory cannot produce a file that reads as complete. Writes nothing to the directory, and the lock is on the directory itself, so a read-only one will do. Refuses to overwrite an existing file |

## `benchmark import` flags

Neither sub-command follows a chain; see [`benchmarking.md`](./benchmarking.md#import-workload)
for what the workload measures and why it exists.

### `benchmark import fetch`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--url` | required | Base URL of the source beacon node, e.g. `http://127.0.0.1:5052` |
| `--from` | required | First slot of the range, and its first sample, so it must hold a block. The anchor is the block at the first slot of the epoch before it; the blocks in between are fetched too, and replayed as unsampled warm-up |
| `--to` | required | Last slot of the range, inclusive. May not pass the source's head. Otherwise not capped: `fetch` streams, so a long range costs disk and time but not memory |
| `--corpus` | required | Corpus directory to create |
| `--force` | `false` | Replace an existing corpus in that directory |
| `--network` | `mainnet` | Which network the source follows |

### `benchmark import replay`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--corpus` | required | Corpus directory written by `fetch` |
| `--network` | `mainnet` | Which network the corpus belongs to. Checked against the manifest's recorded genesis validators root before anything is built |
| `--data-dir` | required | Where to build the replay's RocksDB store. A real backend rather than the in-memory one, since state persistence is part of what is measured |
| `--force` | `false` | Replace an existing store in that directory |
| `--safe-slots-to-import-optimistically` | the specification's own value | How far behind the wall clock a block must be before it may be imported optimistically on age alone. Exposed for parity with `beacon`'s own flag of the same name; a corpus replay never sees the merge transition block it gates |
| `--format` | `human` | `human` or `json` |
| `--output` | none | Also write the JSON report to this file |
