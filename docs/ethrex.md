# Embedded ethrex

A build with the `include-ethrex` feature can run
[ethrex](https://github.com/lambdaclass/ethrex) inside the beacon node's own
process and use it as its execution client. The Engine API then stops being a
network protocol: every `newPayload`, `forkchoiceUpdated` and `getPayload` is a
direct call into ethrex's own handler, with no socket, no JWT and no JSON request
body.

```bash
cargo build --release --features include-ethrex
docker build --build-arg FEATURES=include-ethrex -t ethlambda:ethrex .
```

## Choosing the execution client

| Build | `--execution-endpoint` given | Execution client |
|---|---|---|
| default | no | none: blocks import without payload validation |
| default | yes | the external client at that endpoint |
| `include-ethrex` | no | **embedded ethrex** |
| `include-ethrex` | yes | the external client at that endpoint; ethrex does not start |

A feature build cannot run without an execution client. Build without the
feature for that mode.

The lean chain (`ethlambda node`) is unaffected.

## Flags

The `--ethrex.*` flags are a deliberate subset of ethrex's own. Everything they
leave out keeps the value the `ethrex` binary would start with, read the way that
binary reads it: its clap defaults, overridden by any `ETHREX_*` environment
variable (`ETHREX_P2P_NAT_EXTIP`, `ETHREX_MEMPOOL_MAXSIZE`, ...). A flag given
here wins over both.

| Flag | Default | Notes |
|---|---|---|
| `--ethrex.datadir` | `<--data-dir>/ethrex` | ethrex appends the network name, as it does standalone. The beacon RocksDB ignores the foreign subdirectory |
| `--ethrex.network` | derived from `--network` | `mainnet`, `hoodi`, `sepolia` and `plataberget` map by name; a network directory supplies its `genesis.json`. Anything else must name it explicitly |
| `--ethrex.syncmode` | `snap` | `snap` or `full` |
| `--ethrex.p2p-port` | `30303` | devp2p (RLPx), TCP |
| `--ethrex.discovery-port` | `30303` | discv4 + discv5, UDP |
| `--ethrex.bootnodes` | the network's | comma-separated enode URLs, added to the network's own |
| `--ethrex.target-peers` | ethrex's | |
| `--ethrex.http-addr` | `127.0.0.1` | |
| `--ethrex.http-port` | off | turns on the execution JSON-RPC server (`eth_*`, `net_*`, `web3_*`) |
| `--ethrex.metrics-port` | off | turns on ethrex's own Prometheus server; its metrics live in their own registries, apart from `--metrics-port` |

Every ethrex port is checked against the beacon node's own (`--gossipsub-port`,
`--api-port`, `--metrics-port`, `--discovery.port`) and against each other
before anything binds.

## How a call works

```
EngineClient::new_payload(&deneb::ExecutionPayload, ..)
  └─ Transport::InProcess
       ├─ our payload → ethrex Block → ExecutionPayload::from_block, claimed block_hash kept
       ├─ NewPayloadV4Request { payload, .. }.handle(ctx)      ← ethrex's own handler
       └─ serde_json::Value → PayloadStatusV1                   ← the HTTP transport's decoder
```

- **Typed requests.** Each method builds the ethrex handler struct it names and
  calls `RpcHandler::handle`. ethrex keeps most `ExecutionPayload` fields
  private, so the payload goes through `from_block`, with the consensus layer's
  claimed hash put back so ethrex checks that claim rather than a recomputation.
- **Malformed payloads.** A payload no ethrex block can carry (a transaction
  that does not decode, a base fee past `u64`) is handed to the handler's own
  JSON `parse` instead, so ethrex gives exactly the verdict it gives over the
  wire.
- **Answers and errors.** A handler answers with the JSON value it would send,
  decoded by the same types the HTTP transport uses. An `RpcErr` becomes
  `EngineError::Rpc` with the wire's code (`-38005`, `-38006`, ...).
- **No retry ladder, same timeouts.** An in-process error is always ethrex's
  answer, so retrying would only repeat it. The per-method timeouts stay (8 s,
  6 s for `newPayloadV5`), because the chain actor awaits `newPayload` inline.

## Lifecycle

Startup (`ethlambda_ethrex::start`) is ethrex's `init_l1` with its RPC servers
left out: `init_l1` builds the RPC context inside `bind_api` and never returns
it, so the steps are repeated and the context is assembled from the same parts.
**When the ethrex pin moves, diff `init_l1`, `init_rpc_api` and the binary's
`server_shutdown` against `crates/execution/ethrex/src/lib.rs`.**

Shutdown runs after the chain actor has joined, so no Engine API call is in
flight: cancel ethrex's tasks, wait up to 5 s for them, flush the store, then
write `node_config.json` (identity and known peers). If an ethrex subsystem
cancels the node on its own, the beacon node shuts down the same way and exits
with an error.

## Not included

- ethrex's WebSocket server. The JSON-RPC server answers ethrex's default
  namespaces (`eth`, `net`, `web3`); `ETHREX_HTTP_API=eth,net,web3,debug` widens
  them, as it does for the standalone binary.
- ethrex's RocksDB metrics collector, which is crate-private.
- The authenticated Engine API port: nothing outside the process can drive the
  embedded node's fork choice.
