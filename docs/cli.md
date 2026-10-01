# Command line

`ethlambda` follows one of two chains, selected by a subcommand:

| Invocation | Chain |
|---|---|
| `ethlambda node <flags>` | The lean consensus protocol this repository implements |
| `ethlambda beacon <flags>` | The Ethereum Beacon Chain, as a gossip follower |
| `ethlambda <flags>` | `node`: the subcommand is injected |

Two subcommands follow no chain. `ethlambda benchmark` is the offline
benchmarking harness, covering block building (`benchmark synthetic`, run
through `make bench`) and block import (`benchmark import fetch` /
`benchmark import replay`). See [`benchmarking.md`](./benchmarking.md) for
what each workload measures; `benchmark import`'s flags are in
[their own section](#benchmark-import-flags) below. `ethlambda validator` is
the validator client: a separate process that holds keys and performs duties
against a beacon node over the standard REST API, documented in
[its own section](#validator-flags) below.

## `node` is the default

clap has no native default subcommand, so the binary rewrites its own argv
before parsing. If the first argument is not `node`, `beacon`, `benchmark`,
`validator`, `help`, `-h`, `--help`, `-V`, or `--version`, then `node` is
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
| `--node-key` | generates an ephemeral key | Hex file holding the secp256k1 key that is this node's libp2p and discv5 identity. When omitted, a fresh key is generated in memory each start (logged as a warning), so the PeerId and ENR differ on every restart |
| `--bootnodes` | see below | Bootnode ENR list: one `enr:...` per line, as a YAML block sequence, a YAML flow sequence, or a plain list (`#` comments and leading `- ` are both tolerated) |
| `--checkpoint-sync-url` | see below | API base URLs, tried in order until one answers. Supplies `node`'s starting state on the lean API, and `beacon`'s anchor on a standard Beacon API; required on a fresh `beacon` data directory only for a built-in network, since a loaded network anchors at its own `genesis.ssz` instead. See [`checkpoint_sync.md`](checkpoint_sync.md) |
| `--discovery.port` | `9000` | discv5 UDP port; must differ from `--gossipsub-port`. See [Peer discovery](./discovery.md) |
| `--discovery.advertise-ip` | bind address | IP published in the ENR |
| `--discovery.target-peers` | `200` | Connected-peer count above which discovery stops dialing |

Three of those have no clap default, because the two chains answer them
differently. A single `default_value` can only say one thing, so the flag
carries none and each chain resolves an absent value itself:

| Flag | Absent on `node` | Absent on `beacon` |
|---|---|---|
| `--node-key` | ephemeral in-memory key, warned about | same |
| `--bootnodes` | no bootnodes: peers only via discv5, warned about | falls back to the resolved network's own bootnode list: a built-in network's embedded list, or a loaded directory's `bootstrap_nodes.yaml`/`.txt` |
| `--checkpoint-sync-url` | start from a resumable DB, else from genesis | start from a resumable DB, else anchor at the resolved network's own genesis (loaded network only), else abort |

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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--custody-group-count` | `CUSTODY_REQUIREMENT` (4) | How many custody groups this node custodies, advertised as the ENR's `cgc` |
| `--execution-endpoint` | none | Base URL of the execution client's Engine API endpoint, e.g. `http://127.0.0.1:8551`. Must be given together with `--execution-jwt-secret` |
| `--execution-jwt-secret` | none | File holding the 32-byte hex JWT secret shared with the execution client |
| `--safe-slots-to-import-optimistically` | the specification's own value | How far behind the wall clock a block must be before it may be imported optimistically on age alone |

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

With neither execution flag, the follower contacts no execution client and
imports blocks without validating their payloads, which is what it did before
those flags existed. Supplying one without the other is refused at startup: an
Engine API endpoint always requires authentication. See
[the execution layer pairing](./beacon_engine.md) for what each verdict does and
for the limitations that go with the retry ladder.

`beacon` takes one more flag of its own, and two common flags also mean
something specific here.

| Flag | Default | Meaning |
|---|---|---|
| `--network` | `mainnet` | A built-in network name (`mainnet`, `sepolia` or `hoodi`), or a path to a directory of published network files. A value containing a slash is always a path, so `mainnet` is the built-in and `./mainnet` is a directory. The directory must hold `config.yaml` and `genesis.ssz`, and may hold `bootstrap_nodes.yaml` or `bootstrap_nodes.txt` |

`genesis_validators_root` and `genesis_time`, which the fork digest that keys
every gossip topic, the ENR `eth2` entry and discv5 admission is computed from,
come from the resolved network:

| `--network` | genesis values | config | bootnodes |
|---|---|---|---|
| `mainnet` (default), `sepolia`, `hoodi` | two constants in `network::built_in`; no genesis state is carried (a built-in network never anchors at genesis, and the states run from 5 MB to 150 MB) | `bin/ethlambda/assets/<name>/config.yaml`, `eth-clients/<name>`'s file byte for byte | `bin/ethlambda/assets/<name>/bootstrap_nodes.yaml`, from the same repo |
| a directory | read off the directory's own `genesis.ssz` | the directory's `config.yaml` | the directory's `bootstrap_nodes.yaml`/`.txt` |

The genesis constants are checked twice at runtime: checkpoint sync verifies the
downloaded anchor state against both, and a resumed data directory is checked
the same way, so a wrong constant fails at startup rather than following the
wrong chain.

`beacon` therefore takes no genesis config, validator registry, or bootnode file
of its own the way `node` does: those are read off the resolved network instead
of being separate operator input. A `config.yaml` (a directory's, or a built-in
network's embedded one) is read permissively: absent keys fall back to mainnet's values,
numbers are accepted quoted or bare, and unrecognised keys (on a current
config, the gloas and heze schedule this build cannot process) are dropped
with one warning line naming each. Its `PRESET_BASE` is checked against the
compiled preset; a mismatch is a hard startup error naming the cargo feature
that would fix it. The keys this build runs on compile-time constants for (the
custody and subnet counts, the `MAX_REQUEST_*` limits, `MAX_PAYLOAD_SIZE`, the
snappy message domains and `MAXIMUM_GOSSIP_CLOCK_DISPARITY`) must equal those
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
network: this follower imports nothing past its anchor, so anchoring a built-in
network at genesis would leave it parked at slot 0 while claiming to follow a
chain that has been live for years. A loaded network's own genesis
state is a legitimate anchor instead, since a freshly started devnet has no
checkpoint provider at slot 0 and this is the only way to join one. A
directory already anchored from a previous run resumes without the flag
either way, the same way `node`'s does.

`--api-port` is bound here too, off `beacon`'s own anchored store now rather
than an empty one: one HTTP call site (`start_rpc_server`) serves both chains.
The lean-shaped `/lean/v0/...` routes read metadata keys and state variants a
beacon directory never carries, though, so calling one of them, e.g. `GET
/lean/v0/states/finalized`, panics that request rather than answering for a
chain that isn't running. This is deliberate for now: giving the beacon
follower its own HTTP surface is a change of its own. Treat `/metrics` on
`--metrics-port` as the only meaningful HTTP surface of a `beacon` run today.

## What `ethlambda beacon` does today

It follows the resolved network's gossip and nothing above it. It now anchors a real,
RocksDB-backed store at a checkpoint-synced (or resumed) finalized state, but
does nothing more with it: no state transition, no fork choice, and no block
import past that anchor. The node joins the network, decodes what arrives, and
logs it. See [`beacon_wire.md`](./beacon_wire.md) for what goes on the wire and
how to check a run against the live network.

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
| resolve `--node-key` | shared | shared |
| resolve `--network` into a `NetworkSource` | n/a: lean has no `--network` | classify the value (built-in name vs. directory); parse the `config.yaml` (embedded, or the directory's) and check `PRESET_BASE` against the compiled preset and the constant-backed keys against their constants; for a directory, then decode `genesis.ssz` |
| read `--bootnodes` (falls back to the chain's default list; see the table above) | shared | shared |
| build the aggregator, sync-status and event handles | shared | shared |
| open `--data-dir`'s RocksDB backend | shared | shared |
| **the one `match`**: produce a `ChainSetup` | genesis config, validator keys, checkpoint sync or resume onto the shared backend, subnets | `beacon::wire_params` (genesis metadata, epoch, fork digest), then checkpoint sync or resume onto the same backend |
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

`beacon::wire_params` reads `genesis_time` and `genesis_validators_root` off
the resolved network (a built-in network's two constants, or a loaded
network's own `genesis.ssz`, decoded at whatever fork its own schedule names
for epoch 0), derives the wall-clock epoch
and fork digest from them, and logs the next boundary that would move the
digest. It builds nothing: one `build_swarm` serves both chains, dispatching on
the `WireConfig` variant for the topics, the req/resp protocol set, the
gossipsub `seen_ttl`, the identify version and the connection limits.

The chain actor is the one thing mainnet has none of, so `RunningNode`
carries it as an `Option` and the shared shutdown skips it.

Not implemented here: block import and fork choice past the anchor. A decoded
block is logged and dropped.

## `validator` flags

`ethlambda validator` is not a node. It binds no libp2p port, opens no
database, runs no discovery and follows no chain: it holds validator keys and
performs duties against a beacon node's standard REST API. It works against any
conformant beacon node, this repository's `beacon` subcommand or another
implementation's, so none of the [common flags](#common-flags) apply to it.

> **It keeps no slashing-protection record.** Read
> [Spec Deviations](./spec_deviations.md#the-validator-client-keeps-no-slashing-protection-record)
> before running it with keys that hold real stake. In short: do not run these
> keys in any other client while this one runs, and treat a restart with the
> same care as a manual key move. The client repeats this warning at startup.

| Flag | Default | Meaning |
|---|---|---|
| `--beacon-nodes` | required | Base URLs of the beacon nodes to use, comma-separated or repeated. Tried in list order; the first that answers serves the request, so the order is a preference, not load balancing |
| `--validators-dir` | required | Directory holding the EIP-2335 keystores and `validator_definitions.yml` |
| `--secrets-dir` | required | Directory holding one password file per keystore, named after the validator's public key |
| `--http-address` | `127.0.0.1` | Bind address for the metrics and keymanager servers |
| `--metrics-port` | `5064` | Prometheus metrics port |
| `--keymanager-port` | `5062` | Keymanager API port. Only bound with `--enable-keymanager` |
| `--suggested-fee-recipient` | none | Execution address to receive block rewards, `0x`-prefixed, for every validator the keymanager API gives no address of its own. Optional, and startup warns when it is absent: without it the beacon node picks an address, and it will not be yours |
| `--graffiti` | empty | Text for the graffiti field of proposed blocks, for every validator the keymanager API gives no graffiti of its own. At most 32 bytes as UTF-8, right-padded with zeros. Refused rather than truncated if longer. An ethlambda beacon node appends both clients' versions to it (see [`rpc.md`](rpc.md#validator-endpoints)) |
| `--enable-keymanager` | off | Serve the keymanager API: keystores, plus each validator's own fee recipient, graffiti and gas limit. Off by default because it mutates key material |

### What it does today

Attestations, block proposals and attestation aggregation.

Each epoch it resolves its validators' indices, fetches their attester duties
for this epoch and the next, fetches this epoch's proposer duties, subscribes
to the committee subnets the attester duties need, and registers each
validator's fee recipient with the beacon node. The subscription also tells the
node which committees this client will aggregate for, which it has to know in
advance so it can collect the votes.

Each slot it wakes at the boundary. If one of its validators proposes that
slot, it signs the RANDAO reveal, asks the beacon node for a block, checks that
the block is for the slot and proposer it asked about, signs it and publishes
it. One third into the slot it fetches the attestation data, signs for every
validator due that slot, and submits the batch. Two thirds in, for any duty it
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
it is abandoned and the slot's attesters still vote.

Electra is the earliest fork it will propose under. A deneb block body has one
field fewer than an electra one, so it would need a container pair of its own,
and it would buy nothing: the attestations this client submits are electra's
`SingleAttestation`, which has no earlier form, so a pre-electra chain is one it
cannot serve whatever it does with blocks. A block from any earlier fork is
refused by name rather than failing to decode.

Blocks are fetched and published as SSZ rather than JSON. Signing a block means
computing its `hash_tree_root`, which only the typed container can give; a
hand-written JSON mapping of an execution payload would be a large surface on
which a single wrong field silently produces a signature over the wrong block.

Not implemented: the builder flow and blinded blocks (the client asks for an
unblinded block and refuses a blinded one), sync-committee duties, voluntary
exits, doppelganger protection and remote signing.

### Duty offsets come from the network

The slot length and the two duty offsets are read from the beacon node's
`/eth/v1/config/spec`, not divided out of a compiled-in constant. The
specification states them as `SLOT_DURATION_MS` plus basis points of it,
`ATTESTATION_DUE_BPS` and `AGGREGATE_DUE_BPS`, which on mainnet's 12-second slot
work out at 3999 ms and 8000 ms.

`SECONDS_PER_SLOT` no longer exists in the specification and is accepted only as
a fallback, since deployed nodes still send it. A node sending both is required
to agree with itself.

### Proposer duties are less durable than attester ones

Worth knowing if a proposal is ever missed after a reorg. An attester schedule
depends on the block two epochs back and survives anything shallower; a
proposer schedule depends on the block one epoch back, so a reorg that leaves
attester duties untouched can still move a proposer between slots. This client
fetches proposer duties once per epoch, at the boundary, so a reorg inside the
epoch is not picked up until the next one.

### The keymanager API

Off unless `--enable-keymanager` is passed. It serves `GET`, `POST` and
`DELETE /eth/v1/keystores`, authenticated with a bearer token read from
`api-token.txt` in the validators directory and generated there on first start
if absent. The token file is written `0600` and a file too short to be a real
token is refused rather than accepted.

It also serves `GET`, `POST` and `DELETE` on
`/eth/v1/validator/{pubkey}/feerecipient`, `/graffiti` and `/gas_limit`, which
give one validator its own value in place of the command line's default:

| Setting | Default | Takes effect |
|---|---|---|
| `feerecipient` | `--suggested-fee-recipient` | At the next epoch boundary, when the fee recipients are registered with the beacon node again. A block proposed before then pays the address the node was last given, and the check before signing reports the mismatch |
| `graffiti` | `--graffiti` | The next proposal |
| `gas_limit` | `DEFAULT_GAS_LIMIT` | Stored and served only: it matters to builder registrations, and there is no builder flow |

**These are held in memory only.** A restart puts every validator back on the
defaults, so an operator driving these endpoints must set them again after one.
Deleting a keystore drops its values too.

A few answers worth knowing: `GET feerecipient` is a `500` when the validator
has no address and there is no `--suggested-fee-recipient` default, as
Lighthouse answers it; `POST feerecipient` refuses the zero address, as the
specification requires; `POST graffiti` refuses text over 32 bytes rather than
truncating it; and every route answers `404` for a key this client does not
hold.

The specification requires TLS. This binds to `--http-address`, loopback by
default; exposing it further means putting a TLS terminator in front.

### Metrics

Served on `--metrics-port`, prefixed `ethlambda_validator_` rather than the
`lean_` used elsewhere in this repository, since this process follows the
beacon chain. Every series is registered at startup so it reads zero rather
than being absent before its first event, which is what lets an alert fire on
"attestations stopped". See [Metrics](./metrics.md#validator-client).

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
