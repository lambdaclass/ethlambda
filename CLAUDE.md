# ethlambda Development Guide

Development reference for ethlambda - minimalist Lean Ethereum consensus client.
Not to be confused with Ethereum consensus clients AKA Beacon Chain clients AKA Eth2 clients.

## Quick Reference

**Main branch:** `main`
**Rust version:** 1.92.0 (edition 2024)
**Test fixtures commit:** Check `LEAN_SPEC_COMMIT_HASH` in Makefile

## Codebase Structure (10 crates)

```
bin/ethlambda/              # Entry point, CLI, orchestration
crates/
  blockchain/               # State machine actor (GenServer pattern)
    ├─ src/lib.rs           # BlockChain actor, tick events, validator duties
    ├─ src/store.rs         # Fork choice store, block/attestation processing
    ├─ fork_choice/         # LMD GHOST implementation (3SF-mini)
    └─ state_transition/    # STF: process_slots, process_block, attestations
  common/
    ├─ types/               # Core types (State, Block, Attestation, Checkpoint)
    ├─ crypto/              # XMSS aggregation (leansig wrapper)
    └─ metrics/             # Prometheus metrics
  net/
    ├─ p2p/                 # libp2p: gossipsub + req-resp (Status, BlocksByRoot)
    └─ rpc/                 # Axum HTTP endpoints (/lean/v0/* and /metrics)
  storage/                  # RocksDB backend, in-memory for tests
```

## Key Architecture Patterns

### Actor Concurrency (spawned-concurrency)
- **BlockChain**: Main state machine (GenServer pattern)
- **P2P**: Network event loop with libp2p swarm
- Communication via `mpsc::unbounded_channel`
- Shared storage via `Arc<dyn StorageBackend>` (clone Store, share backend)

### Tick-Based Validator Duties (4-second slots, 4 intervals per slot)
```
Interval 0: Proposer check → accept attestations → build/publish block
Interval 1: Non-proposers produce attestations
Interval 2: Safe target update (fork choice with 2/3 threshold)
Interval 3: Accept accumulated attestations
```

### Attestation Pipeline
```
Gossip → Signature verification → new_attestations (pending)
  ↓ (intervals 0/3)
promote → known_attestations (fork choice active)
  ↓
Fork choice head update
```

### State Transition Phases
1. **process_slots()**: Advance through empty slots, update historical roots
2. **process_block()**: Validate header → process attestations → update justifications/finality
3. **Justification**: 3SF-mini rules (delta ≤ 5 OR n² OR n(n+1))
4. **Finalization**: Source with no unjustifiable gaps to target

## Development Workflow

### Before Committing
```bash
cargo fmt                                    # Format code
make lint                                    # Clippy with -D warnings
make test                                    # All tests + forkchoice (with skip-signature-verification)
```

### Common Operations
```bash
.claude/skills/test-pr-devnet/scripts/test-branch.sh    # Test branch in multi-client devnet
rm -rf leanSpec && make leanSpec/fixtures                # Regenerate test fixtures (requires uv)
```

### Testing with Local Devnet

See `.claude/skills/test-pr-devnet/SKILL.md` for multi-client devnet testing workflows.

## Important Patterns & Idioms

### Trait Implementations
```rust
// Prefer From/Into traits over custom from_x/to_x methods
impl From<u8> for ResponseCode { fn from(code: u8) -> Self { Self(code) } }
impl From<ResponseCode> for u8 { fn from(code: ResponseCode) -> Self { code.0 } }

// Enables idiomatic .into() usage
let code: ResponseCode = byte.into();
let byte: u8 = code.into();
```

### Ownership for Large Structures
```rust
// Prefer taking ownership to avoid cloning large data (signatures ~3KB)
pub fn consume_signed_block(signed_block: SignedBlockWithAttestation) { ... }

// Add .clone() at call site if needed - makes cost explicit
store.insert_signed_block(root, signed_block.clone());
```

### Formatting Patterns
```rust
// Extract long arguments into variables so formatter can join lines
// Instead of:
batch.put_batch(Table::X, vec![(key, value)]).expect("msg");

// Prefer:
let entries = vec![(key, value)];
batch.put_batch(Table::X, entries).expect("msg");
```

### Error Handling Patterns

**Use `inspect` and `inspect_err` for side-effect-only error handling:**
```rust
// ✅ GOOD: Use inspect_err when only logging or performing side effects on error
result
    .inspect_err(|err| warn!(%err, "Operation failed"));

// Extract complex expressions to variables for cleaner formatting
let response = Response::success(ResponsePayload::BlocksByRoot(blocks));
server.swarm.behaviour_mut().req_resp.send_response(channel, response)
    .inspect_err(|err| warn!(%peer, ?err, "Failed to send response"));

// ✅ GOOD: Use inspect + inspect_err when both branches need side effects
operation()
    .inspect(|_| metrics::inc_success())
    .inspect_err(|_| metrics::inc_failed());

// ❌ AVOID: Using if let Err when only performing side effects
if let Err(err) = result {
    warn!(%err, "Operation failed");
}

// ❌ AVOID: Using if/else for both success and error side effects
if let Err(err) = operation() {
    metrics::inc_failed();
} else {
    metrics::inc_success();
}
```

**When NOT to use `inspect_err`:**
```rust
// Use if let Err or match when:
// 1. Early return needed
if let Err(err) = operation() {
    error!(%err, "Fatal error");
    return false;
}

// 2. Error needs transformation (use map_err + ?)
let result = operation()
    .map_err(|err| CustomError::from(err))?;
```

### Metrics (RAII Pattern)
```rust
// Timing guard automatically observes duration on drop
let _timing = metrics::time_state_transition();
```

### Logging Patterns

**Use tracing shorthand syntax for cleaner logs:**
```rust
// ✅ GOOD: Shorthand for simple variables
let slot = block.slot;
let proposer = block.proposer_index;
info!(
    %slot,              // Shorthand for slot = %slot (Display)
    proposer,           // Shorthand for proposer = proposer
    block_root = %ShortRoot(&block_root.0),  // Named expression
    "Block imported"
);

// ❌ BAD: Verbose
info!(
    slot = %slot,
    proposer = proposer,
    ...
);
```

**Standardized field ordering (temporal → identity → identifiers → context → metadata):**
```rust
// Block logs
info!(%slot, proposer, block_root = ..., parent_root = ..., attestation_count, "...");

// Attestation logs
info!(%slot, validator, target_slot, target_root = ..., source_slot, source_root = ..., "...");

// Consensus events
info!(finalized_slot, finalized_root = ..., previous_finalized, justified_slot, "...");

// Peer events
info!(%peer_id, %direction, peer_count, our_finalized_slot, our_head_slot, "...");
```

**Root hash truncation:**
```rust
use ethlambda_types::ShortRoot;

// Always use ShortRoot for consistent 8-char display (4 bytes)
info!(block_root = %ShortRoot(&root.0), "...");
```

### Relative Indexing (justified_slots)
```rust
// Bounded storage: index relative to finalized_slot
actual_slot = finalized_slot + 1 + relative_index
// Helper ops in justified_slots_ops.rs
```

## Cryptography & Signatures

**XMSS (eXtended Merkle Signature Scheme):**
- Post-quantum signature scheme
- 52-byte public keys, 3112-byte signatures
- Epoch-based to prevent reuse
- Aggregation via leanVM for efficiency

**Signature Aggregation (Two-Phase):**
1. **Gossip signatures**: Fresh XMSS from network → aggregate via leanVM
2. **Fallback to proofs**: Reuse previous block proofs for missing validators

## Networking (libp2p)

### Protocols
- **Transport**: QUIC over UDP (TLS 1.3)
- **Gossipsub**: Blocks + Attestations (snappy raw compression)
  - Topic: `/leanconsensus/{network}/{block|attestation}/ssz_snappy`
  - Mesh size: 8 (6-12 bounds), heartbeat: 700ms
- **Req/Resp**: Status, BlocksByRoot (snappy frame compression + varint length)

### Retry Strategy on Block Requests
- Exponential backoff: 10ms, 40ms, 160ms, 640ms, 2560ms
- Max 5 attempts, random peer selection on retry

### Message IDs
- 20-byte truncated SHA256 of: domain (valid/invalid snappy) + topic + data

## Configuration Files

**Genesis:** `genesis.json` (JSON format, cross-client compatible)
- `GENESIS_TIME`: Unix timestamp for slot 0
- `GENESIS_VALIDATORS`: Array of 52-byte XMSS pubkeys (hex)

**Validators:** JSON array of `{"pubkey": "...", "index": 0}`
**Bootnodes:** ENR records (Base64-encoded, RLP decoded for QUIC port + secp256k1 pubkey)

## Testing

### Test Categories
1. **Unit tests**: Embedded in source files
2. **Spec tests**: From `leanSpec/fixtures/consensus/`
   - `forkchoice_spectests.rs` (requires `skip-signature-verification`)
   - `signature_spectests.rs`
   - `stf_spectests.rs` (state transition)

### Running Tests
```bash
cargo test --workspace --release                                    # All workspace tests
cargo test -p ethlambda-blockchain --features skip-signature-verification --test forkchoice_spectests
cargo test -p ethlambda-blockchain --features skip-signature-verification --test forkchoice_spectests -- --test-threads=1  # Sequential
```

## Common Gotchas

### Signature Verification
- Tests require `skip-signature-verification` feature for performance
- Crypto tests marked `#[ignore]` (slow leanVM operations)

### Storage Architecture
- Genesis block has no signatures - stored in Blocks table only, not BlockSignatures
- All other blocks must have entries in both tables

### State Root Computation
- Always computed via `tree_hash_root()` after full state transition
- Must match proposer's pre-computed `block.state_root`

### Finalization Checks
- Use `original_finalized_slot` for justifiability checks during attestation processing
- Finalization updates can occur mid-processing

### `justified_slots` Window Shifting
- Call `shift_window()` when finalization advances
- Prunes justifications for now-finalized slots

## External Dependencies

**Critical:**
- `leansig`: XMSS signatures (leanEthereum project)
- `ethereum_ssz`: SSZ serialization
- `tree_hash`: Merkle tree hashing
- `spawned-concurrency`: Actor model
- `libp2p`: P2P networking (custom LambdaClass fork)

**Storage:**
- `rocksdb`: Persistent backend
- In-memory backend for tests

## Resources

**Specs:** `leanSpec/src/lean_spec/` (Python reference implementation)
**Devnet:** `lean-quickstart` (github.com/blockblaz/lean-quickstart)

## Other implementations

- zeam (Zig): <https://github.com/blockblaz/zeam>
- ream (Rust): <https://github.com/ReamLabs/ream>
- qlean (C++): <https://github.com/qdrvm/qlean-mini>
