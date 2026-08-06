# Multi-Client Conversion Reference

How to run zeam / ream / qlean / gean / lantern / grandine validators in place of
ethlambda on a devnet, and current interop status. `scripts/convert.sh` implements
all of this; this file explains the why and the gotchas.

## Core principle: keep the node identity, rename only the container

All genesis artifacts are keyed by **node identity** `node_N`
(`annotated_validators.yaml`, `validator-config.yaml`, `node_N.key`,
`hash-sig-keys/validator_N_*`, data dir `data/node_N`). So any client can take over
a validator slot **without touching identity or data layout**: keep `--node-id
node_N` and the key `/config/node_N.key`.

What *does* change is the **container/display name**, which becomes `<client>_N`
(e.g. `zeam_8`) so cAdvisor's `name` label and promtail's `node` label — and hence
Grafana — show which client is running. Scripts locate a node's existing container
by the `_N$` suffix, so the prefix can differ from run to run.

Conversion = swap image + CLI shape + wipe data + checkpoint sync. Never keep-DB
across a client switch (wrong-format data) — wipe and checkpoint-sync from a
healthy **same-devnet** node.

## Vote math constraint

Finality threshold is `ceil(2/3 · NODES)` aligned votes on that devnet. Keep
aggregators on ethlambda and keep the ethlambda node count above the threshold, so
finality survives any single non-eth cohort failing. Do NOT convert so many nodes
that ethlambda drops below the threshold unless every other client is proven to
reliably contribute justification votes. Convert a **canary** of each client type
first and confirm `vote_count` rises before mass conversion.

## Images (devnet5 — current)

| Client | Image | Notes |
|--------|-------|-------|
| ethlambda | `ghcr.io/lambdaclass/ethlambda:devnet5` | |
| zeam | `blockblaz/zeam:devnet5` | needs `--security-opt seccomp=unconfined` |
| ream | `ghcr.io/reamlabs/ream:latest-devnet5` | |
| qlean | `qdrvm/qlean-mini:devnet-5-amd64` | arch-specific tag (`-amd64`/`-arm64`) |
| gean | `ghcr.io/geanlabs/gean:devnet5` | |
| lantern | `bitminemavan/lantern:devnet5` | `v0.0.X` == devnetX; see mirror note |
| grandine | `sifrai/lean:devnet-5` | |

**`bitminemavan/lantern` is lantern's current repo** — it is what upstream
lean-quickstart's ansible pulls and where new builds land (including
`devnet5-leanvm-main` for chains on leanVM `main`). `piertwo/lantern` is the older
repo: same tag names, but it stopped tracking (its `devnet5` predates
bitminemavan's). Use `bitminemavan`; the scripts default to it.

devnet4 images (older): `blockblaz/zeam:devnet4`,
`ghcr.io/reamlabs/ream:latest-devnet4`, `qdrvm/qlean-mini:devnet-4-amd64`,
`sifrai/lean:devnet-4`, `bitminemavan/lantern:v0.0.4`.

Image tag must match the chain's leanVM/proof format. After a leanVM bump, other
clients must ship a matching build or signature aggregation deserialization fails.
**Re-canary every client after any bump.**

## CLI shapes (per node)

Placeholders below: `N` = node index, `G`/`A`/`M` = gossip/api/metrics ports
(`9000+N`/`5052+N`/`9200+N`), `ACC` = the devnet's `SUBNETS`
(`ATTESTATION_COMMITTEE_COUNT`), `URL` = `http://127.0.0.1:<CS_PORT>/lean/v0/states/finalized`.
Aggregator flags in `[...]` are added only for an aggregator node, and it covers a
**single** subnet: `--aggregate-subnet-ids $((N % ACC))`.

zeam — `--validator-config genesis_bootnode` (NOT a file path; the file form fails
with `NotDir`). Reads the genesis dir via `--custom-genesis`. The log flags come
before the `node` subcommand; `--console_log_level info` is what puts zeam's own
duty publishes on stdout where the duty-timing profiler can read them (the file
sink stays at warn):
```
--log_file_active_level warn --console_log_level info node \
  --custom-genesis /config --validator-config genesis_bootnode --data-dir /data \
  --node-id node_N --node-key /config/node_N.key --metrics-enable \
  --api-port A --metrics-port M --attestation-committee-count ACC \
  [--is-aggregator --aggregate-subnet-ids <subnet>] --checkpoint-sync-url URL --db-backend lmdb
```

ream — uses `annotated_validators.yaml`, `--socket-port` for QUIC:
```
--data-dir /data lean_node --network /config/config.yaml \
  --validator-registry-path /config/annotated_validators.yaml --bootnodes /config/nodes.yaml \
  --node-id node_N --node-key /config/node_N.key --socket-port G \
  --metrics --metrics-address 0.0.0.0 --metrics-port M --http-address 0.0.0.0 --http-port A \
  --attestation-committee-count ACC [--is-aggregator --aggregate-subnet-ids <subnet>] --checkpoint-sync-url URL
```

qlean — `--genesis-dir`, multiaddr listen, NO `--aggregate-subnet-ids` (crashes
`unrecognised option`); it aggregates only auto-derived subnets:
```
--genesis-dir /config --data-dir /data --node-id node_N --node-key /config/node_N.key \
  --listen-addr /ip4/0.0.0.0/udp/G/quic-v1 --metrics-host 0.0.0.0 --metrics-port M \
  --api-host 0.0.0.0 --api-port A --attestation-committee-count ACC [--is-aggregator] --checkpoint-sync-url URL -linfo
```

lantern — C client. Docker entrypoint runs the binary directly when argv[0] starts
with `--`. `--validator_config` is a DIR (holds both annotated_validators.yaml +
validator-config.yaml); needs `--genesis-state /config/genesis.ssz`; node key via
`--node-key-path`; multiaddr `--listen-address`. Reads the gossip fork digest from
genesis ENRs in nodes.yaml, falling back to `--devnet NAME` as the topic segment —
pass `--devnet 12345678` to match the cross-client dummy digest. Supports
`--checkpoint-sync-url` (URL must include the `/lean/v0/states/finalized` path) and
`--is-aggregator --aggregate-subnet-ids`:
```
--data-dir /data --genesis-config /config/config.yaml --nodes-path /config/nodes.yaml \
  --genesis-state /config/genesis.ssz --validator_config /config \
  --node-id node_N --node-key-path /config/node_N.key \
  --listen-address /ip4/0.0.0.0/udp/G/quic-v1 --http-port A --metrics-port M \
  --hash-sig-key-dir /config/hash-sig-keys --attestation-committee-count ACC \
  --devnet 12345678 [--is-aggregator --aggregate-subnet-ids <subnet>] --checkpoint-sync-url URL
```

grandine — `--port` for QUIC, `--hash-sig-key-dir` (singular):
```
--genesis /config/config.yaml --validator-registry-path /config/annotated_validators.yaml \
  --bootnodes /config/nodes.yaml --node-id node_N --node-key /config/node_N.key \
  --port G --address 0.0.0.0 --http-address 0.0.0.0 --http-port A \
  --metrics --metrics-address 0.0.0.0 --metrics-port M --hash-sig-key-dir /config/hash-sig-keys \
  --attestation-committee-count ACC [--is-aggregator --aggregate-subnet-ids <subnet>] --checkpoint-sync-url URL
```

gean — Go client. `--custom-network-config-dir` is the genesis dir; gossip port flag
like ethlambda. **`--data-dir` is not optional in practice**: it defaults to a
container-relative `./data` (= `/app/data`), so without it the Pebble DB lives
inside the container instead of the `/data` mount — a host-side `rm -rf
data/node_*` then silently wipes nothing, and the DB dies with the container:
```
--custom-network-config-dir /config --data-dir /data --gossipsub-port G --node-id node_N \
  --node-key /config/node_N.key --http-address 0.0.0.0 --api-port A --metrics-port M \
  --attestation-committee-count ACC [--is-aggregator --aggregate-subnet-ids <subnet>] [--checkpoint-sync-url URL]
```

## convert.sh usage

```
convert.sh <CS_PORT> <spec>...   spec = N:client[:agg]   client in zeam|ream|qlean|gean|lantern|grandine
# e.g.  convert.sh 5052 25:zeam 26:zeam 27:zeam
# ACC=<SUBNETS> only to override what the genesis says
```
No BASE arg (each devnet numbers nodes from 0). `ACC` (the devnet's `SUBNETS` /
`ATTESTATION_COMMITTEE_COUNT`) is read from `genesis/config.yaml` on the host, so it
can't silently disagree with the chain — a wrong value puts the node's votes on a
subnet nobody aggregates. CS_PORT = a healthy same-devnet node's api port.

Guards, both learned the hard way:

- **Specs are validated before anything is removed.** A typo'd client name used to
  be caught only after the container was gone, the data wiped and the 60s backoff
  slept — leaving the node down.
- **Converting an aggregator away warns.** If the node currently runs with
  `--is-aggregator` and the new spec has no `:agg`, that subnet is left with no
  aggregator: votes verify, nothing is stored, `attestation_count` goes to 0 and
  finality dies quietly. Either keep the role (`N:client:agg`) or move it to
  another node first (`AGG=<subnet> cs-restart.sh <CS_PORT> <node>`).

Keeps the 60s backoff, memory limits, and json-log caps. After converting, relabel
prometheus (see operations.md) and confirm with `host-check.sh`.
