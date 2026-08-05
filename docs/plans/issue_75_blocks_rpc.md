# Issue #75 — JSON-RPC endpoints for blocks

**Issue:** https://github.com/lambdaclass/ethlambda/issues/75
**Goal:** Add debug-friendly HTTP endpoints returning JSON representations of blocks and block headers, looked up by root hash or slot.

## Decisions (confirmed with user)

1. **Response body:** `Block` (no signatures). Header endpoint returns `BlockHeader`.
2. **`Serialize` is added to `common/types`** (not a DTO in the RPC crate).
3. **No named tags** (`head`/`finalized`/`genesis`). Only root hex or slot number.
4. **JSON only** — no SSZ content negotiation.
5. **Include `/header` variant** (beacon API convention).

## Endpoints

```
GET /lean/v0/blocks/:block_id         → 200 application/json  Block
GET /lean/v0/blocks/:block_id/header  → 200 application/json  BlockHeader
```

`block_id` is either:
- A `0x`-prefixed 32-byte hex root (`^0x[0-9a-fA-F]{64}$`) → direct lookup
- A decimal slot number (`^[0-9]+$`) → resolve via head state's `historical_block_hashes`

### Error responses
| Status | Condition | Body |
|---|---|---|
| 400 | `block_id` doesn't match either shape | `{"error": "invalid block_id"}` |
| 404 | slot beyond `historical_block_hashes` length | `{"error": "block not found"}` |
| 404 | slot is empty (`H256::ZERO` in history) | `{"error": "block not found"}` |
| 404 | root not in storage | `{"error": "block not found"}` |

## Implementation steps

### Step 1 — `Serialize` in `common/types`

`Block` → `BlockBody` → `AggregatedAttestations (SszList)` → `AggregatedAttestation` → `AggregationBits (SszBitlist)`.

`SszList` and `SszBitlist` **do not** derive `Serialize` upstream. Approach:

- Derive `Serialize` on `Block`, `BlockBody`, `AggregatedAttestation`, `AttestationData`.
- `Checkpoint` already derives `Serialize`.
- Add `#[serde(serialize_with = "...")]` for the two SSZ-collection fields:
  - `BlockBody.attestations: SszList<AggregatedAttestation, 4096>` → serialize as JSON array (iterate, serialize each element).
  - `AggregatedAttestation.aggregation_bits: SszBitlist<4096>` → serialize as `"0x..."` hex string (same convention as validator pubkeys in `state.rs:81`).
- Place the helper serializers next to the derive site (`block.rs` and `attestation.rs`).

### Step 2 — Handler module

New file `crates/net/rpc/src/blocks.rs`:

- `pub async fn get_block(Path(block_id), State(store)) -> Response`
- `pub async fn get_block_header(Path(block_id), State(store)) -> Response`
- `fn resolve_block_id(store: &Store, block_id: &str) -> Result<H256, BlockIdError>`
  - Hex path → parse `H256`, return it (no existence check yet).
  - Slot path → load head state, index `historical_block_hashes`, reject `H256::ZERO`.
- `enum BlockIdError { Invalid, NotFound }` → mapped to 400/404.

Head-state access: use the same pattern as `get_latest_finalized_state` (`store.head()` → `get_state(&root)`). If no method for head currently exposed from `Store`, reuse whatever the fork-choice handler uses; worst case, add a minimal getter.

### Step 3 — Register routes

Wire routes in `build_api_router` (`crates/net/rpc/src/lib.rs:37`):

```rust
.route("/lean/v0/blocks/:block_id", get(blocks::get_block))
.route("/lean/v0/blocks/:block_id/header", get(blocks::get_block_header))
```

### Step 4 — Tests (`crates/net/rpc/src/lib.rs#tests`)

Add tests mirroring the existing pattern:

| Test | Covers |
|---|---|
| `get_block_by_root_returns_json` | Happy path: insert a block, GET by hex root |
| `get_block_by_slot_returns_json` | Happy path: GET by slot, resolves via head state |
| `get_block_header_by_root_returns_json` | Header variant happy path |
| `get_block_invalid_id_returns_400` | `:block_id` = `"not-a-slot-or-hash"` |
| `get_block_missing_root_returns_404` | Valid hex but not stored |
| `get_block_missing_slot_returns_404` | Slot beyond history length |
| `get_block_empty_slot_returns_404` | Slot is `H256::ZERO` in history |

Extend `test_utils::create_test_state` if needed to populate a block and `historical_block_hashes`.

### Step 5 — CLAUDE.md update

Append the two new endpoints to the **API Server (`:5052`)** section.

## Files touched

| File | Change |
|---|---|
| `crates/common/types/src/block.rs` | Derive `Serialize` on `Block`, `BlockBody`; add `serialize_with` for attestations list |
| `crates/common/types/src/attestation.rs` | Derive `Serialize` on `AggregatedAttestation`, `AttestationData`; add `serialize_with` for bits |
| `crates/net/rpc/src/blocks.rs` | **New.** Handlers + `block_id` parser |
| `crates/net/rpc/src/lib.rs` | Module declaration + route wiring + tests |
| `CLAUDE.md` | Document new endpoints |

## Out of scope

- Named tags (`head`, `finalized`, `genesis`)
- SSZ content negotiation
- Signatures in the response
- Deserialization of blocks from JSON
- Pagination or range queries
- OpenAPI spec

## Verification

```bash
make fmt
make lint
make test
```

Manual smoke test with a running devnet:
```bash
curl -s http://127.0.0.1:5052/lean/v0/blocks/0x<root> | jq .
curl -s http://127.0.0.1:5052/lean/v0/blocks/42 | jq .
curl -s http://127.0.0.1:5052/lean/v0/blocks/42/header | jq .
```
