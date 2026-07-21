# event-monitor

Live arrival-time monitor for lean-consensus (ethlambda) nodes.

It dials the `GET /lean/v0/events` SSE stream of several nodes, timestamps each
event on arrival, and serves a browser dashboard that visualizes when
`block` / `attestation` / `aggregate` events arrive **relative to the slot**
(rolling beeswarm, per node) and how a given block/aggregate/head **propagates**
between nodes (a second beeswarm of per-node delay behind the first node to see
each id). The rolling window is adjustable live from the header, and a fresh
page load backfills recent history from the collector so it's never blank.

Standalone: its own Cargo workspace, **no dependency on any ethlambda crate** —
it only speaks the documented SSE/HTTP wire shape. See [`CONTRACT.md`](./CONTRACT.md)
for the authoritative interface between the Rust backend and the JS frontend.

## Run

```bash
cp config.example.toml config.toml
$EDITOR config.toml                 # list your nodes' RPC URLs
cargo run --release -- --config config.toml
# open the `listen` address (default http://127.0.0.1:8080) in a browser
```

## Layout

```
src/            Rust collector + axum server (owns Cargo.toml)
web/            vanilla HTML/JS/CSS dashboard (no build step)
CONTRACT.md     frozen interface: SSE input, NormalizedEvent, HTTP API, viz spec
config.example.toml
```
