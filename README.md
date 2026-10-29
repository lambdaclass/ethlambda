<p align="center">
  <img src="assets/ethlambda_banner.png" alt="ethlambda banner" width="300">
</p>

# ethlambda

Minimalist, fast and modular implementation of a Beacon Chain and Lean Chain client written in Rust.

🌐 Visit our website at [**ethlambda.xyz**](https://ethlambda.xyz) to learn more about the project.

## Quickstart

### Beacon Chain follower

Follows Ethereum mainnet from a checkpoint-synced anchor and serves the
standard Beacon API on port 5052, paired with an
[ethrex](https://github.com/lambdaclass/ethrex) execution client that validates
each block's execution payload. The two talk over the Engine API, authenticated
with a shared JWT secret. Both ship release binaries for Linux (x86_64,
aarch64) and macOS (Apple silicon): ethlambda's are listed under
[Releases](#releases) below and ethrex's on
[its releases page](https://github.com/lambdaclass/ethrex/releases/latest).
To run both from pre-built Docker images instead, see
[Running with Docker](#running-with-docker) below.

> **Warning:** this uses a lot of disk. ethrex needs at least 500 GB for
> mainnet (1 TB recommended; see its
> [hardware requirements](https://docs.ethrex.xyz/getting-started/hardware_requirements.html)).

```sh
# Pick the assets for your platform: linux-x86_64, linux-aarch64 or macos-aarch64
curl -LO https://github.com/lambdaclass/ethlambda/releases/latest/download/ethlambda-linux-x86_64
curl -LO https://github.com/lambdaclass/ethrex/releases/latest/download/ethrex-linux-x86_64
chmod +x ethlambda-linux-x86_64 ethrex-linux-x86_64
mv ethlambda-linux-x86_64 ethlambda && mv ethrex-linux-x86_64 ethrex
./ethlambda --version && ./ethrex --version

mkdir -p beacon-data ethrex-data
# A persisted key keeps the node's identity, and so its custody set, stable across restarts
openssl rand -hex 32 > beacon-data/node-key
# The secret both clients authenticate the Engine API with
openssl rand -hex 32 > jwt.hex

# In one terminal: ethrex, serving the Engine API on 127.0.0.1:8551
./ethrex \
  --network           mainnet \
  --datadir           ethrex-data \
  --authrpc.jwtsecret jwt.hex

# In another: the beacon node, pointed at ethrex
./ethlambda beacon \
  --network                mainnet \
  --checkpoint-sync-url    https://beaconstate.ethstaker.cc \
  --node-key               beacon-data/node-key \
  --data-dir               beacon-data/db \
  --discovery.advertise-ip "$(curl -s https://ifconfig.me)" \
  --execution-endpoint     http://127.0.0.1:8551 \
  --execution-jwt-secret   jwt.hex
```

`--discovery.advertise-ip` is the address published in the node's ENR. Without
it the node advertises `0.0.0.0` and logs a warning. It still dials out and
follows the chain, but peers cannot reach it until discovery learns the address
from their replies. The Beacon API binds `127.0.0.1:5052` by default, so
`--http-address` is only needed to reach it from another host. Stop the node
with `Ctrl+C`; it shuts down gracefully on SIGINT only, so a systemd unit needs
`KillSignal=SIGINT`.

- `ethlambda-linux-x86_64` targets x86-64-v3, so it needs a CPU with AVX2
  (Haswell or later), and glibc 2.35 or newer.
- The macOS binaries are not notarized. A browser download is quarantined, which
  `xattr -d com.apple.quarantine <file>` lifts; a `curl` download is not.
- [`RELEASE.md`](./RELEASE.md#verifying-a-release) shows how to verify an
  ethlambda binary's provenance attestation.

To skip payload validation, run the node without ethrex: drop it, the JWT
secret and the two `--execution-*` flags. The node then follows the chain and
serves the Beacon API without validating execution payloads, but it cannot
serve a validator client, since it answers attestation data, aggregation and
block production requests with `503`.

The first start downloads the finalized state (several hundred MB) and logs
`Beacon checkpoint sync complete`, then a few minutes of
`Block parent missing, storing as pending` before `Block imported successfully`
lines start. Later starts resume from `beacon-data/db`.

ethrex logs `No messages from the consensus layer` until the beacon node's
first fork choice update, then starts snap sync. Until that finishes, which
takes hours on mainnet, ethrex answers each payload `SYNCING` and the beacon
node imports blocks optimistically.

Check progress from another terminal:

```sh
curl -s localhost:5052/eth/v1/node/syncing
```

The node has caught up once `sync_distance` (the chain's current slot minus
`head_slot`) is near 0. Don't rely on `is_syncing` yet: it currently reads
`false` during catch-up as well.

For Sepolia or Hoodi, change `--network mainnet` to `--network sepolia` or
`--network hoodi` in both the ethrex and the beacon node arguments, and point
`--checkpoint-sync-url` at that network's provider. See
[`ethlambda beacon`](#ethlambda-beacon--the-ethereum-beacon-chain) below for
the remaining flags.

`--network plataberget` (the Glamsterdam testnet) is built in as well. It has
run Gloas since its `GLOAS_FORK_EPOCH`, which the node follows: a Gloas
checkpoint anchor is accepted, payload envelopes are fetched and imported, and
the validator-client endpoints serve Gloas duties, the payload envelope and the
payload timeliness vote included.

The same binary runs [`ethlambda node`](#ethlambda-node--the-lean-consensus-chain)
and [`ethlambda validator`](#ethlambda-validator--the-validator-client); their
flags are below.

### Running with Docker

The same two nodes from pre-built images (`ghcr.io/lambdaclass/ethlambda:latest`
and `ghcr.io/lambdaclass/ethrex`), so only
[Docker](https://www.docker.com/get-started) is needed. Follow the logs with
`docker logs -f ethlambda-beacon` and `docker logs -f ethrex`. For another
network, change `--network mainnet` in both containers' arguments, not Docker's
own `--network ethereum`.

```sh
docker pull ghcr.io/lambdaclass/ethlambda:latest
docker pull ghcr.io/lambdaclass/ethrex

mkdir -p beacon-data ethrex-data
# A persisted key keeps the node's identity, and so its custody set, stable across restarts
openssl rand -hex 32 > beacon-data/node-key
# The secret both clients authenticate the Engine API with
openssl rand -hex 32 > jwt.hex
# This host's public address, published in the node's ENR (see above)
PUBLIC_IP=$(curl -s https://ifconfig.me)

# A private network, so the beacon node reaches ethrex's Engine API by name
# without publishing it on the host
docker network create ethereum

docker run -d --name ethrex --network ethereum \
  -p 30303:30303 -p 30303:30303/udp \
  -v "$PWD/ethrex-data:/data" \
  -v "$PWD/jwt.hex:/jwt.hex:ro" \
  ghcr.io/lambdaclass/ethrex \
  --network           mainnet \
  --datadir           /data \
  --authrpc.addr      0.0.0.0 \
  --authrpc.jwtsecret /jwt.hex

# The node shuts down gracefully on SIGINT only, so this makes `docker stop` flush its state
docker run -d --name ethlambda-beacon --network ethereum --stop-signal SIGINT \
  -p 9000:9000/udp -p 9001:9001/udp -p 9001:9001/tcp \
  -p 127.0.0.1:5052:5052 \
  -v "$PWD/beacon-data:/data" \
  -v "$PWD/jwt.hex:/jwt.hex:ro" \
  ghcr.io/lambdaclass/ethlambda:latest beacon \
  --network                mainnet \
  --checkpoint-sync-url    https://beaconstate.ethstaker.cc \
  --node-key               /data/node-key \
  --data-dir               /data/db \
  --http-address           0.0.0.0 \
  --discovery.advertise-ip "$PUBLIC_IP" \
  --execution-endpoint     http://ethrex:8551 \
  --execution-jwt-secret   /jwt.hex
```

<details>
<summary>Running without an execution client</summary>

The node without ethrex, as described above: no shared network, no JWT secret
and no `--execution-*` flags.

```sh
docker pull ghcr.io/lambdaclass/ethlambda:latest

mkdir -p beacon-data
# A persisted key keeps the node's identity, and so its custody set, stable across restarts
openssl rand -hex 32 > beacon-data/node-key
# This host's public address, published in the node's ENR (see above)
PUBLIC_IP=$(curl -s https://ifconfig.me)

# The node shuts down gracefully on SIGINT only, so this makes `docker stop` flush its state
docker run -d --name ethlambda-beacon --stop-signal SIGINT \
  -p 9000:9000/udp -p 9001:9001/udp -p 9001:9001/tcp \
  -p 127.0.0.1:5052:5052 \
  -v "$PWD/beacon-data:/data" \
  ghcr.io/lambdaclass/ethlambda:latest beacon \
  --network                mainnet \
  --checkpoint-sync-url    https://beaconstate.ethstaker.cc \
  --node-key               /data/node-key \
  --data-dir               /data/db \
  --http-address           0.0.0.0 \
  --discovery.advertise-ip "$PUBLIC_IP"
```

</details>

### Lean consensus devnet

To run a local lean devnet with ethlambda, follow the instructions on the
[`devnet5-ethlambda-keygen` branch of lambdaclass/lean-quickstart](https://github.com/lambdaclass/lean-quickstart/tree/devnet5-ethlambda-keygen).

## Building from source

### Prerequisites

- [Rust](https://rust-lang.org/tools/install)
- [Git](https://git-scm.com/install)
- For `make run-devnet` and `make docker-build` only:
  [Docker](https://www.docker.com/get-started) and
  [yq](https://github.com/mikefarah/yq#install)

### Building and testing

We use `cargo` as our build system, but prefer `make` as a convenient wrapper for common tasks. These are some common targets:

```sh
# Formats all code
make fmt
# Checks and lints the code
make lint
# Runs all tests
make test
# Builds a docker image tagged as "ghcr.io/lambdaclass/ethlambda:local"
make docker-build DOCKER_TAG=local
```

Run `make help` or take a look at our [`Makefile`](./Makefile) for other useful commands.

### Running the node

The binary carries both chains and the validator client as sub-commands:

```sh
cargo build --release
./target/release/ethlambda <node|beacon|validator> [flags]
```

[`docs/cli.md`](./docs/cli.md) is the full flag reference for every sub-command,
`benchmark` and `replay-era` included. The
[quickstart](#beacon-chain-follower) runs a release binary with the same arguments.

#### `ethlambda node` — the Lean consensus chain

The [devnet section](#running-in-a-devnet) below runs this sub-command, and it
is the default: a bare flag list with no sub-command still runs the node, so existing scripts and
Docker entrypoints keep working unchanged.

It needs a genesis config, a validator registry, a bootnode list and this
node's own keys, all of which a devnet generates for you:

```sh
./target/release/ethlambda node \
  --genesis            config/config.yaml \
  --validators         config/annotated_validators.yaml \
  --bootnodes          config/nodes.yaml \
  --validator-config   config/validator-config.yaml \
  --hash-sig-keys-dir  config/hash-sig-keys \
  --node-key           config/ethlambda_0.key \
  --node-id            ethlambda_0 \
  --data-dir           ./data \
  --is-aggregator
```

`--node-id` picks this node's entry out of `annotated_validators.yaml`, so it
is what decides which validators this process runs.

The easiest way to get those files is `make run-devnet`, which generates them
under `lean-quickstart/local-devnet/genesis/`. See
[Running in a devnet](#running-in-a-devnet) below.

> **Important:** at least one node on the network must run with
> `--is-aggregator`, or attestations are never aggregated into blocks and the
> chain produces blocks but never finalizes.

#### `ethlambda beacon` — the Ethereum Beacon Chain

A beacon node. It anchors at a finalized checkpoint fetched from a Beacon API,
then follows the chain to its tip: blocks arriving over gossip and range sync
are imported through fork choice, and it custodies its slice of the fulu data
column matrix. What it stores it serves back, to peers over
`beacon_blocks_by_{range,root}` and to anyone over the standard Beacon API on
`--api-port`. It performs no validator duties of its own: those belong to
[`ethlambda validator`](#ethlambda-validator--the-validator-client), which it
serves over that API once paired with an execution client, joining the
attestation and sync committee subnets its validators ask for and publishing
what they sign.

```sh
./target/release/ethlambda beacon \
  --network             mainnet \
  --checkpoint-sync-url <beacon-api-url> \
  --node-key            ./node-key \
  --data-dir            ./data
```

| Flag | Meaning |
|---|---|
| `--network` | `mainnet` (default), `sepolia`, `hoodi`, `plataberget`, or a path to a directory of network files (`config.yaml`, `genesis.ssz`, optionally `bootstrap_nodes.yaml`), the layout `eth-clients` publishes and kurtosis mounts |
| `--checkpoint-sync-url` | Where the anchor comes from. Required on a fresh data directory for a built-in network, since those never start from genesis. A resumable data directory is used before it; a network loaded from a directory anchors at its own `genesis.ssz` when no URL is given |
| `--node-key` | Optional, but worth persisting: the columns this node custodies are a function of its node id, so without a key file it changes identity, and custody set, on every restart |
| `--execution-endpoint`, `--execution-jwt-secret` | Optional Engine API pairing, given together. Without them, blocks import without payload validation |

A built-in network needs nothing else on disk. Its `eth-clients` `config.yaml`
and bootnode list, and the two genesis values the fork digest is computed from,
are compiled into the binary, so deriving the wire parameters touches no
network.

A healthy run logs its anchor, then imports each new block within a couple of
seconds of its slot starting (from a Sepolia run):

```
Beacon checkpoint sync complete slot=11197376 fork=fulu validators=1997 finalized_epoch=349916 anchor_block_slot=11197376
Beacon block decoded slot=11197516 proposer=834 fork="fulu" block_root=c44ad3d8 bytes=92333
Block imported successfully slot=11197516 proposer=834 block_root=c44ad3d8 parent_root=4397e224
Beacon aggregate attestation decoded slot=11197516 aggregator=574 attesters=53 target_epoch=349922 …
```

See [`docs/beacon_wire.md`](./docs/beacon_wire.md) for what goes on the wire,
[`docs/checkpoint_sync.md`](./docs/checkpoint_sync.md) for how the anchor is
chosen and verified, and [`docs/rpc.md`](./docs/rpc.md) for the Beacon API
endpoints.

#### `ethlambda validator` — the validator client

A separate process that holds the keys and performs the duties: attestations,
block proposals, aggregation, sync committee messages and, from Gloas on, the
payload envelope and the payload timeliness vote. It talks to a beacon node over
the standard Beacon API, so it works against `ethlambda beacon` (run with the
`--execution-*` flags) or any other conformant beacon node.

> **Slashing protection:** every block and attestation is checked against a
> durable per-validator record in `--validators-dir` before it is signed, and a
> second validator client pointed at the same directory refuses to start. A key
> with no record is refused at startup: pass `--init-slashing-protection` once,
> and only for keys that have signed nothing anywhere for at least two epochs.
> A key moving from another client brings its history with
> `ethlambda slashing-protection import` (or the keymanager API), and never runs
> in two clients at once. See
> [Spec deviations](./docs/spec_deviations.md#the-validator-client-keeps-eip-3076s-minimal-watermarks-not-full-history).

```sh
./target/release/ethlambda validator \
  --beacon-nodes            http://127.0.0.1:5052 \
  --validators-dir          ./validators \
  --secrets-dir             ./secrets \
  --suggested-fee-recipient 0x<your-address>
```

| Flag | Meaning |
|---|---|
| `--beacon-nodes` | Base URLs of the beacon nodes to use, comma-separated or repeated. Tried in order, so the order is a preference |
| `--validators-dir` | Directory of EIP-2335 keystores and `validator_definitions.yml`. Without that file, keystores in the Lighthouse layout (`<0xpubkey>/voting-keystore.json`) are discovered and the file is written |
| `--secrets-dir` | One password file per keystore, named after the validator's public key |
| `--suggested-fee-recipient` | Execution address for block rewards, `0x`-prefixed. Optional, but without it the beacon node picks an address that is not yours |
| `--graffiti` | Text for proposed blocks, at most 32 bytes |
| `--enable-keymanager` | Serve the keymanager API on `--keymanager-port` (default `5062`). Off by default, since it mutates key material |

Metrics are served on `--metrics-port` (default `5064`). See
[`docs/cli.md`](./docs/cli.md#validator-flags) for the remaining flags and what
the client does each slot.

### Running in a devnet

To run a local devnet with multiple clients using [lean-quickstart](https://github.com/blockblaz/lean-quickstart):

```sh
# This will clone lean-quickstart, build the docker image, and start a local devnet
make run-devnet
```

This generates fresh genesis files and starts all configured clients with metrics enabled.
Press `Ctrl+C` to stop all nodes.

> **Note:** On Linux, QUIC performance benefits from larger UDP receive buffers. If you see warnings about buffer sizes, increase the kernel limit:
> ```sh
> sudo sysctl -w net.core.rmem_max=7340032
> sudo sysctl -w net.core.wmem_max=7340032
> ```
> To persist across reboots, add to `/etc/sysctl.conf`. For Docker, pass `--sysctl net.core.rmem_max=7340032 --sysctl net.core.wmem_max=7340032`.

For custom devnet configurations, go to `lean-quickstart/local-devnet/genesis/validator-config.yaml` and edit the file before running the command above. See `lean-quickstart`'s documentation for more details on how to configure the devnet.

## Philosophy

Many long-established clients accumulate bloat over time. This often occurs due to the need to support legacy features for existing users or through attempts to implement overly ambitious software. The result is often complex, difficult-to-maintain, and error-prone systems.

In contrast, our philosophy is rooted in simplicity. We strive to write minimal code, prioritize clarity, and embrace simplicity in design. We believe this approach is the best way to build a client that is both fast and resilient. By adhering to these principles, we will be able to iterate fast and explore next-generation features early.

Read more about our engineering philosophy [in this post of our blog](https://blog.lambdaclass.com/lambdas-engineering-philosophy/).

## Design principles

- Ensure effortless setup and execution across all target environments.
- Be vertically integrated. Have the minimal amount of dependencies.
- Be structured in a way that makes it easy to build on top of it.
- Have a simple type system. Avoid having generics leaking all over the codebase.
- Have few abstractions. Do not generalize until you absolutely need it. Repeating code two or three times can be fine.
- Prioritize code readability and maintainability over premature optimizations.
- Avoid concurrency split all over the codebase. Concurrency adds complexity. Only use where strictly necessary.

## 📚 References and acknowledgements

The following links, repos, companies and projects have been important in the development of this repo, we have learned a lot from them and want to thank and acknowledge them.

- [Ethereum](https://ethereum.org/en/)
- [LeanEthereum](https://github.com/leanEthereum)
- [Zeam](https://github.com/blockblaz/zeam)
- [Lantern](https://github.com/Pier-Two/lantern)

If we forgot to include anyone, please file an issue so we can add you. We always strive to reference the inspirations and code we use, but as an organization with multiple people, mistakes can happen, and someone might forget to include a reference.

## 📖 Documentation

Full documentation is available in the [`docs/`](./docs) directory. Please refer to it for setup, usage, and development details. For better viewing, we have it hosted in [docs.ethlambda.xyz](https://docs.ethlambda.xyz).

## Current status

ethlambda is a Beacon Chain and Lean Chain client. On the Beacon Chain
(`ethlambda beacon`), it follows a network from a checkpoint-synced anchor and serves
the standard Beacon API; paired with an execution client it validates payloads and
serves the [validator client](#ethlambda-validator--the-validator-client). See the
[Beacon Chain follower](#beacon-chain-follower) quickstart. On the Lean Chain
(`ethlambda node`), it implements the core features of a Lean consensus client:

- **Networking** — libp2p peer connections, STATUS message handling, gossipsub for blocks and attestations
- **State management** — genesis state generation, state transition function, block processing
- **Fork choice** — 3SF-mini fork choice rule implementation with attestation-based head selection
- **Validator duties** — attestation production and broadcasting, block building

Additional features:

- [leanMetrics](docs/metrics.md) support for monitoring and observability
- [lean-quickstart](https://github.com/blockblaz/lean-quickstart) integration for easier devnet running

### Releases

Binaries for Linux (x86_64, aarch64) and macOS (Apple silicon) are attached to
[GitHub Releases](https://github.com/lambdaclass/ethlambda/releases). Docker
images are published to `ghcr.io/lambdaclass/ethlambda` with the following tags:

| Tag | Description |
|-----|-------------|
| `latest` | The latest release |
| `X.Y.Z` | A specific release |
| `X.Y.Z-rc.N` | A release candidate, promoted to `X.Y.Z`/`latest` once tested |
| `devnetX` | Stable image for a specific devnet (e.g. `devnet4`) |
| `unstable` | Built from the latest main commit |
| `sha-XXXXXXX` | Specific commit |

Release binaries and images carry GitHub build provenance attestations;
[`RELEASE.md`](./RELEASE.md#verifying-a-release) shows how to verify them.

[`RELEASE.md`](./RELEASE.md) has more details on our release process and how to tag new images.

### pq-devnet-5

We are running the `pq-devnet-5` spec. A Docker tag `devnet5` is available for this version.

### pq-devnet-6

`pq-devnet-6` is in a planning phase; no features have been specified yet. Likely candidates are replacing [LMD-GHOST](docs/lmd_ghost.md) and [3SF-mini](docs/3sf_mini.md), or [execution layer integration](https://github.com/lambdaclass/ethlambda/pull/367).

### Older devnets

Docker tags for each devnet are released, with format `devnetX` (i.e. `devnet1`, `devnet2`, `devnet3`, `devnet4`).

Support for older devnet releases is discontinued when the next devnet version is released.

## Incoming features / Roadmap

We wrote a [blogpost](https://blog.lambdaclass.com/ethlambda-devnet-5-and-beyond/) about what we think should be included in the near future.

Some features we are looking to implement in the near future, in order of priority:

- [Optimize block building](https://github.com/lambdaclass/ethlambda/issues/465)
- [Prototype Goldfish + RLMD GHOST + BFT — devnet-6](https://github.com/lambdaclass/ethlambda/pull/434)
- Integrate the Lean Chain with execution clients, in particular [ethrex](https://github.com/lambdaclass/ethrex) — devnet-7 ([first prototype](https://github.com/lambdaclass/ethlambda/pull/367)). The beacon node already pairs with one over the Engine API; see [`docs/beacon_engine.md`](./docs/beacon_engine.md)
- Replace libp2p with the experimental [ethp2p](https://github.com/ethp2p/ethp2p), which we are porting to Rust
- [Add a guest program and ZK proving of the STF](https://github.com/lambdaclass/ethlambda/issues/156)
- Rewrite the STF in the concrete programming language to enable formal verification

### Experimental features

We have a proof-of-concept formalization of a part of the state transition function in Lean4 in PR [#269](https://github.com/lambdaclass/ethlambda/pull/269).

## Community

- **Telegram**: [ethlambda group](https://t.me/ethlambda_client), where we post daily updates; drop by to ask questions or chat about anything Lean-related.
- **X (Twitter)**: [@ethlambda_lean](https://twitter.com/ethlambda_lean) for occasional updates.
- **Weekly community call**: every Friday, streamed live on [@class_lambda](https://x.com/class_lambda); the call link is posted on Telegram beforehand.
- **Ecosystem coordination**: the [PQ Interop calls](https://github.com/ethereum/pm/issues?q=is%3Aissue+%22PQ+Interop%22+in%3Atitle) on `ethereum/pm` cover cross-client Lean Ethereum work and related updates; the meeting links are posted on each issue.

## Security

We take security seriously. If you discover a vulnerability in this project, please report it responsibly.

- You can report vulnerabilities directly via the **[GitHub "Report a Vulnerability" feature](../../security/advisories/new)**.
- Alternatively, send an email to **[security@lambdaclass.com](mailto:security@lambdaclass.com)**.

For more details, please refer to our [Security Policy](./.github/SECURITY.md).

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on how to get involved.
