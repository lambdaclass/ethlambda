# P2P Message Reception Logging with Peer Count

## Goal

Emit a dedicated `info!`-level log line every time a message is received via p2p,
including the count of currently connected peers. This gives operators visibility
into network activity correlated with peer connectivity, complementing the
existing per-message-type logs.

## Context

- **Log level**: `info!` — same level used for chain/fork events such as
  `"Fork choice reorg detected"` (`crates/blockchain/src/store.rs:65`),
  `"Block imported"`, and `"Peer connected"`.
- **Peer count source**: `P2PServer::connected_peers: HashSet<PeerId>` at
  `crates/net/p2p/src/lib.rs:316`. Already used for the existing `peer_count`
  field in connection lifecycle logs (`lib.rs:455`, `lib.rs:506`).
- **Decision**: Option B (dedicated log line) — chosen by the user as a first
  iteration. We will revisit and may collapse into existing logs if the new line
  proves redundant in operation.

## Inbound message taxonomy

Two categories of p2p reception, both ultimately arriving via
`handle_swarm_event` in `crates/net/p2p/src/lib.rs:423`:

| Category   | Variants                                                                  | Current handler                                |
| ---------- | ------------------------------------------------------------------------- | ---------------------------------------------- |
| Gossipsub  | `block`, `aggregation`, `attestation_subnet_<id>`                         | `gossipsub::handle_gossipsub_message` (handler.rs:20) |
| Req/Resp   | `Status` request, `Status` response, `BlocksByRoot` request, `BlocksByRoot` response | `req_resp::handle_req_resp_message` (handlers.rs:22) |

We deliberately exclude:

- Connection lifecycle events (already logged with `peer_count`).
- `OutboundFailure` / `InboundFailure` / `ResponseSent` from the req/resp
  protocol — these are not "received messages" in the user-visible sense.

## Design

A new `info!` log emitted once per received message, at the earliest point where
we know the kind:

```text
info!(peer_count, kind, "P2P message received");
```

- `peer_count`: `server.connected_peers.len()` at log time.
- `kind`: short string identifier — one of:
  `block` | `aggregation` | `attestation` | `status_request` | `status_response` |
  `blocks_by_root_request` | `blocks_by_root_response` | `unknown_topic`.

### Placement

Two log sites total — one per protocol entry point:

1. `crates/net/p2p/src/gossipsub/handler.rs::handle_gossipsub_message`
   - Resolve `kind` from `topic_kind` (the existing `match` already classifies
     this) by extracting topic classification into a small helper that returns a
     `&'static str` or by inlining the `kind` value into each match arm before
     the existing per-variant `info!` calls.
   - Emit the new log at the top of each match arm (after kind is known).

2. `crates/net/p2p/src/req_resp/handlers.rs::handle_req_resp_message`
   - Emit the new log inside the `Message::Request` / `Message::Response`
     branches, with `kind` set from the inner request/response variant.

Both handlers already receive `server: &mut P2PServer`, so peer count access
is free and requires no signature changes.

### Field ordering (per CLAUDE.md logging guidance)

Following the project's standardized ordering (temporal → identity →
identifiers → context → metadata), the new log treats `kind` as identity-ish
and `peer_count` as metadata:

```rust
info!(kind, peer_count, "P2P message received");
```

## Implementation steps

1. **Gossipsub handler** (`crates/net/p2p/src/gossipsub/handler.rs`)
   - In each branch of the `match topic_kind` (block / aggregation /
     attestation subnet / unknown), add a one-line `info!(kind, peer_count, "P2P message received")`
     immediately after the topic kind is known and before existing decoding work.
   - The peer count is captured once at the top of `handle_gossipsub_message`
     into a local `let peer_count = server.connected_peers.len();` to avoid
     re-reads (immutable read; does not conflict with later mutable use of
     `server`).

2. **Req/Resp handler** (`crates/net/p2p/src/req_resp/handlers.rs`)
   - In `handle_req_resp_message`, capture `peer_count` once per
     `Message::Request` / `Message::Response` branch.
   - Emit `info!(kind, peer_count, "P2P message received")` with `kind`
     determined by the inner variant (`status_request`, `status_response`,
     `blocks_by_root_request`, `blocks_by_root_response`).

3. **No new helpers, no new types.** The `kind` strings are short literals
   inlined at the call site — the duplication is minimal (≤ 7 occurrences
   across 2 files) and avoids over-abstraction.

4. **No metric is added.** This is a logging-only change. If the log proves
   useful and we want a counterpart metric (e.g. `lean_p2p_messages_received_total`),
   that is a separate follow-up.

## Out of scope

- Modifying or augmenting existing per-message reception logs (e.g.
  `"Received block from gossip"`). Those remain unchanged. If we later decide
  the dedicated log is redundant, we will collapse `peer_count` into them
  (Option A) and remove the new log.
- Any change to outbound publishing logs.
- Any new metric.
- Any change to req/resp `OutboundFailure` / `InboundFailure` / `ResponseSent`
  handling.

## Verification

1. `make fmt` — formatting must be clean.
2. `make lint` — clippy with `-D warnings`.
3. `make test` — full workspace test suite.
4. Manual smoke test against the local devnet (`make run-devnet` or
   `.claude/skills/test-pr-devnet/scripts/test-branch.sh`):
   - `grep "P2P message received"` in node logs while peers are connected.
   - Confirm `peer_count` matches the value reported by `"Peer connected"` /
     `"Peer disconnected"` events.
   - Confirm we see all expected `kind` values during a normal slot
     (`block`, `attestation`, and — once aggregations occur — `aggregation`).

## Risks / open questions

- **Log volume**: this duplicates one log line per inbound message. At steady
  state with N validators that is roughly N attestations per slot per node,
  which on the current devnets remains acceptable. If volume becomes a concern
  we have a clear path to Option A (collapse into existing logs).
- **`unknown_topic` kind**: today this case only emits a `trace!`. Adding an
  `info!` here would increase noise from misbehaving / cross-version peers.
  We will keep `unknown_topic` at `trace!` only — i.e. the new `info!` is
  emitted only for known kinds. This is the one deliberate exception to "every
  received message".

## Files touched

- `crates/net/p2p/src/gossipsub/handler.rs`
- `crates/net/p2p/src/req_resp/handlers.rs`

No new files. No public API changes. No dependency changes.
