# event-monitor

Live arrival-time monitor for lean-consensus (ethlambda) nodes.

It dials the `GET /lean/v0/events` SSE stream of several nodes, timestamps each
event on arrival, and serves a browser dashboard that visualizes when
`block` / `attestation` / `aggregate` events arrive **relative to the slot**
(rolling beeswarm, per node) and how a given block/aggregate **propagates**
between nodes (a second beeswarm of per-node delay behind the first node to see
each id). The rolling window is adjustable live from the header, and a fresh
page load backfills recent history from the collector so it's never blank.

Standalone: its own Cargo workspace, **no dependency on any ethlambda crate** —
it only speaks the documented SSE/HTTP wire shape. See [`CONTRACT.md`](./CONTRACT.md)
for the authoritative interface between the Rust backend and the JS frontend.

## Reading the numbers

Two caveats worth knowing before drawing conclusions from a panel:

- Arrival is timestamped **on the collector**, so every offset includes the
  collector↔node round trip. That single clock is what makes propagation deltas
  skew-free, but it also means nodes reached over different links (loopback vs a
  WAN tunnel) carry a systematic offset that looks like lag. Compare nodes whose
  paths are comparable.
- The collector re-resolves slot geometry every 60s and drops its retained
  history if `genesis_time` changes, so a regenerated genesis no longer corrupts
  offsets silently. An already-open dashboard still needs a **page reload** to
  pick up the new geometry and reset its own slot watermark, and it now says so:
  the change is pushed on the live stream and the tab raises a reload banner
  rather than quietly emptying every panel.
- A dot outlined in magenta arrived *before* its slot boundary (negative offset,
  i.e. the collector's clock is ahead of the node's). There is no room to plot it
  left of the lane labels, so it sits at 0 with the outline as the tell.

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
