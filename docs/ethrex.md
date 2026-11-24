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
here wins over both. An `--ethrex.*` flag together with `--execution-endpoint`
is a usage error: the endpoint replaces the embedded client the flag would
configure.

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
| `--ethrex.metrics-port` | off | turns on ethrex's own Prometheus server. Both servers also export the process-wide default registry, so each repeats some of the other's series (`lean_*` here, a few `ethrex_*` on `--metrics-port`); the prefixes keep them from colliding |

Every ethrex port is checked against the beacon node's own (`--gossipsub-port`,
`--api-port`, `--metrics-port`, `--discovery.port`) and against each other
before anything binds. Two sockets on one port clash only when their addresses
can overlap: the same address, a wildcard covering the other (`::` covers IPv4
too), or devp2p's address when `ETHREX_P2P_ADDR` leaves ethrex to pick it. So
`--ethrex.http-port` may equal `--api-port` when `--ethrex.http-addr` and
`--http-address` are different addresses, neither of them a wildcard.

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
- **Same timeouts, and a timeout is asked again.** A handler's error is
  ethrex's answer, so it is never retried, as an RPC error is not over HTTP. A
  timeout is not an answer, and is asked again on the HTTP transport's ladder
  (three attempts at the method's timeout, 8 s or 6 s for `newPayloadV5`,
  backing off from 500 ms), with the same one-attempt exceptions, `getPayload`
  and `getBlobsV2`. The chain actor awaits `newPayload` inline, so a payload
  that keeps timing out holds it for about 25 s, as an external client can.
  Giving up on an attempt does not stop ethrex's execution of the block: it
  records the verdict on its own, and asking again joins the execution already
  running.
- **Off the caller's thread.** Each attempt runs on a thread of tokio's blocking
  pool. ethrex replays a deep reorg's side chain inside `forkchoiceUpdated` and
  waits for it synchronously; on the chain actor's own thread that would hold
  the actor for the whole replay, with no timeout able to fire.
- **Refused once shutdown begins**, with a transport error (as a stopped
  external client refuses the connection), and a call still running is
  cancelled. See [Lifecycle](#lifecycle).

## Lifecycle

Startup (`ethlambda_ethrex::start`) is ethrex's `init_l1` with its RPC servers
left out: `init_l1` builds the RPC context inside `bind_api` and never returns
it, so the steps are repeated and the context is assembled from the same parts.
**When the ethrex pin moves, diff `init_l1`, `init_rpc_api`, `init_network`
and the binary's `server_shutdown` against `crates/execution/ethrex/src/lib.rs`.**
`init_network` is inlined so that a devp2p socket that cannot bind is a startup
error rather than its `expect` panic. A startup step that fails once ethrex is
running, in `start` or later in `run_node`, still stops it and flushes its
store.

Shutdown begins once the chain actor has joined and the Beacon API server has
drained: cancel ethrex, flush the store, then write `node_config.json` (identity
and known peers), as ethrex's own `server_shutdown` does, alongside the final
telemetry flush rather than after it. Once it begins, the in-process Engine API
and the execution JSON-RPC server refuse every request and cancel any still
running, so none reaches the store while it flushes; that refusal is the one
addition to `server_shutdown`. Like it, shutdown waits for none of ethrex's
tasks: several never watch the cancel token, so a wait would always run out.
ethrex's block executor thread is not waited for either: a block it is still on
is executed again on the next start, as every recent block is, since ethrex's
flush keeps only the state it has committed to disk and a restart re-executes
the newest blocks. A flush that fails makes the node exit with an error. If the
execution JSON-RPC server fails, it stops ethrex, as ethrex's own does, and the
beacon node shuts down the same way and exits with an error.

## Not included

- ethrex's WebSocket server. The JSON-RPC server answers ethrex's default
  namespaces (`eth`, `net`, `web3`); `ETHREX_HTTP_API=eth,net,web3,debug` widens
  them, as it does for the standalone binary.
- ethrex's RocksDB metrics collector, which is crate-private.
- The authenticated Engine API port: nothing outside the process can drive the
  embedded node's fork choice.
