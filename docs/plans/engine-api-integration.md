# Engine API integration: ethlambda ↔ ethrex

> Plan owner: pablo
> Created: 2026-05-13
> Status: draft, awaiting scope confirmation

## Goal

Integrate ethlambda (Lean consensus client) with ethrex (Ethereum execution
client) over the standard Engine API: JWT-authenticated JSON-RPC on a separate
"auth" port, with `engine_*` methods driving execution-layer fork choice,
payload validation, and payload building.

## Starting state

**ethlambda** (this repo):
- Pure consensus, no execution layer awareness.
- `BlockBody` carries `attestations` only — no `execution_payload` field
  (`crates/common/types/src/block.rs`).
- `State` carries justification/finalization data but no
  `latest_execution_payload_header`.
- No JWT / JSON-RPC client crate.
- Slot duration: 4s, tick intervals 0-4 per slot.

**ethrex** (`/Users/pablodeymonnaz/Lambda/ethrex`):
- Full mainline Engine API on an auth RPC port: V1-V5 of `engine_newPayload`,
  V1-V4 of `engine_forkchoiceUpdated`, V1-V5 of `engine_getPayload`, plus
  `engine_exchangeCapabilities` and `engine_getClientVersionV1`.
- JWT HS256 bearer auth (`crates/networking/rpc/authentication.rs`).
- Reference Engine *client* (used when ethrex acts as a rollup sequencer)
  in `crates/networking/rpc/clients/auth/mod.rs` — direct template for our
  new client crate.
- `PayloadAttributesV4` already includes `slot_number: u64`, friendly to
  Lean's slot-driven model.

**leanSpec**: no execution payload definition. Lean Ethereum consensus does
not currently mandate an EL. This means integration is *additive* — we choose
when to carry/validate payloads.

## Scope options (the question that needs answering)

Three plausible interpretations of "integrate":

| Option | What it means | Effort | Spec dependency |
|---|---|---|---|
| **A. Spike** | ethlambda speaks JWT+JSON-RPC to ethrex. On each tick, fires `engine_forkchoiceUpdated` with the current head/finality hashes (initially dummy `H256::zero()`). Validates JWT plumbing end-to-end. No block-schema changes. | ~1 day | none |
| **B. Scaffold** | Spike + typed Rust wrappers for all four engine methods, CLI flags, capability handshake on startup, observability. Block schema unchanged. Still no real payload flow because blocks have no payload. | ~3-5 days | none |
| **C. Full merge** | Add `execution_payload(_header)` to Lean `BlockBody` + `State`, propagate through STF (call `engine_newPayload` on import, `engine_getPayload` on proposal), require ethrex for consensus validity. | weeks | requires leanSpec proposal — not yet drafted |

**Recommendation**: do **A → B → wait for spec**. Option C should not be
attempted ahead of a leanSpec change; doing so forks ethlambda from the other
six Lean clients.

## Architecture (B target)

### New crate: `crates/net/ethrex-client`

```
crates/net/ethrex-client/
├── Cargo.toml          # reqwest (rustls-tls), serde, jsonwebtoken, bytes, eyre/thiserror
└── src/
    ├── lib.rs          # public EngineClient API
    ├── auth.rs         # JWT HS256 generation (iat-based, 60s expiry per spec)
    ├── transport.rs    # reqwest + bearer + JSON-RPC envelope
    ├── methods.rs      # engine_exchangeCapabilities / fcu / newPayload / getPayload wrappers
    └── types/          # PayloadStatus, ForkChoiceState, ExecutionPayload, PayloadAttributes(V3,V4)
        └── ...         # ported from ethrex's rpc/types/ — minimal subset, ours own
```

Why a separate crate (not in `crates/net/rpc`): rpc crate today serves the
*beacon* HTTP API and the metrics server. Engine API is conceptually a
*client* to a different process, so it belongs in its own crate to keep
dependencies clean (rpc doesn't need `jsonwebtoken`; ethrex-client doesn't
need axum).

### Types

We re-derive the mainline Engine API types locally (not depend on
`ethrex_rpc`) — ethrex is a sibling project, not an upstream library. We mirror
field names exactly so JSON wire format is identical.

Minimal V1 subset to start:
- `ForkChoiceState { head_block_hash, safe_block_hash, finalized_block_hash }`
- `PayloadAttributesV3` (Cancun) and `PayloadAttributesV4` (Prague, with
  `slot_number`) — both supported, picked per ethrex's capabilities.
- `ExecutionPayload` (with optional V3/V4 fields)
- `PayloadStatus { status, latest_valid_hash, validation_error }`

### CLI flags (`bin/ethlambda`)

| Flag | Default | Purpose |
|---|---|---|
| `--execution-endpoint` | (unset; integration disabled if missing) | URL of ethrex auth RPC, e.g. `http://127.0.0.1:8551` |
| `--execution-jwt-secret` | (unset) | Path to JWT hex secret file (same format ethrex/lighthouse/etc. use) |
| `--execution-fee-recipient` | (unset) | 20-byte hex; required only when proposing |

Behavior:
- Both unset → integration **disabled**, ethlambda runs as before.
- Both set → instantiate `EngineClient`, run capability handshake on startup
  (log mismatches as warnings, not errors), pass client to `BlockChain` actor.
- Capability handshake also fetches `engine_getClientVersionV1` and logs
  ethrex name/version for support diagnostics.

### Blockchain actor hookup (Option B level)

In `crates/blockchain/src/lib.rs`:
- On each `Tick`, if integration is enabled and tick interval is 0 (block
  proposal time): call `engine_forkchoiceUpdated` with our current
  `(head, safe, finalized)` hashes mapped onto dummy execution-block hashes
  (e.g., `H256::zero()` or `keccak256(beacon_root)` — TBD).
- On block import: log only, no payload flow.

This is deliberately a no-op for ethrex (the FCU it receives points at hashes
it doesn't know about → it returns `SYNCING`). The point is to exercise the
*wire* end-to-end so the real schema work (Option C) can land without surprises.

### Observability

Three new metrics (`ethrex_engine_*` to disambiguate from internal ethlambda
metrics; falls under "Custom Metrics" in `docs/metrics.md`):

- `lean_ethrex_engine_request_duration_seconds{method}` — histogram
- `lean_ethrex_engine_request_total{method, status}` — counter (`status` ∈ `ok`, `rpc_error`, `transport_error`)
- `lean_ethrex_engine_last_payload_status{}` — int gauge (0=unknown, 1=valid, 2=invalid, 3=syncing, 4=accepted)

## Milestones

### M1 — Plan locked + scope decided (TODAY)
Resolve A/B/C with user. Plan stays in `docs/plans/`.

### M2 — `ethrex-client` crate skeleton (1-2 days, parallelizable)
- New crate compiles in workspace, exports `EngineClient` with all four
  methods returning `eyre::Result<_>`, JWT auth implemented and unit-tested
  (fixed `iat`, deterministic token).
- Stub integration test against `mockito` (no real ethrex).

### M3 — Wire into `bin/ethlambda` (1 day)
- CLI flags added, client constructed at startup, capability handshake logged.
- Disabled by default; `make test` unchanged.

### M4 — FCU on tick (½ day)
- Blockchain actor fires `engine_forkchoiceUpdated` on interval 0 of every
  slot when client is configured. Use dummy hashes initially.
- Add metrics. Document expected `SYNCING` response.

### M5 — End-to-end test against real ethrex (1 day)
- Devnet config wiring ethlambda → local ethrex; verify ethrex logs receive
  the FCU and respond. No consensus block changes yet.

### M6 — *(blocked on leanSpec)* — Real payload flow (Option C)
Out of scope for this plan unless C is selected up front.

## Open questions

1. **Genesis EL hash mapping**: when Lean genesis is created, what
   execution-block hash do we pin? `H256::zero()` is the simplest convention
   but means ethrex must accept ethlambda's FCU pointing at zero.
2. **Multi-EL support** (Lighthouse/Lodestar style): not in M2-M5. Single EL
   endpoint only.
3. **JWT secret format**: file vs. inline hex. ethrex/lighthouse/teku all
   accept a file containing `0x`-prefixed hex; we follow the same convention.
4. **Slot → timestamp mapping**: ethlambda has `GENESIS_TIME` + slot duration
   = 4s. Lean slot 0 timestamp = `GENESIS_TIME`. ethrex `PayloadAttributesV4`
   wants Unix `timestamp` + `slot_number`. Both available.

## References

- ethrex Engine API: `/Users/pablodeymonnaz/Lambda/ethrex/crates/networking/rpc/engine/`
- ethrex auth client (template): `/Users/pablodeymonnaz/Lambda/ethrex/crates/networking/rpc/clients/auth/mod.rs`
- ethrex JWT auth: `/Users/pablodeymonnaz/Lambda/ethrex/crates/networking/rpc/authentication.rs`
- Engine API spec: <https://github.com/ethereum/execution-apis/tree/main/src/engine>
- Capability list (mainline): `engine_*V1..V5` — see `engine/mod.rs:CAPABILITIES`
