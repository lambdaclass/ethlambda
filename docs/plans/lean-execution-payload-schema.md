# Proposal: embed `ExecutionPayload` in Lean `BlockBody`

> Status: draft (2026-05-18). Intended as the body of a leanSpec issue once
> the maintainers are ready to discuss.
>
> Implementation reference:
> [`lambdaclass/ethlambda` PR #367](https://github.com/lambdaclass/ethlambda/pull/367).

## Summary

Add an execution payload to the Lean `BlockBody` and a cached
`ExecutionPayloadHeader` to the Lean `State`, mirroring Ethereum's
Cancun (`V3`) shape verbatim. Define a minimal `process_execution_payload`
in the state transition. This is the schema dependency that gates every
Lean client's ability to pair with a standard Ethereum execution client
over the Engine API.

## Motivation

Today Lean blocks carry only consensus payload (`attestations` plus the
type-2 SNARK proof). The Engine API (`engine_forkchoiceUpdatedV3`,
`engine_newPayloadV3`, `engine_getPayloadV3`) needs an EL block hash per
slot to forward to the EL, and that hash is what the EL itself produced
when it built/validated a payload — there is no way to source it without
a payload in the block body. Without it:

- An EL paired with a Lean CL stays in `SYNCING` indefinitely. It only
  ever sees zero-valued `ForkChoiceState` triplets and never receives a
  `newPayload` call to chain forward from.
- Each Lean client either omits EL pairing entirely or invents an ad-hoc
  payload field that is wire-incompatible with peers.

ethlambda has implemented the full Engine API client (JWT, JSON-RPC,
typed V3 wrappers) and a scaffold that fires `engine_forkchoiceUpdatedV3`
each slot — but those calls are no-ops until block bodies carry payloads.
This proposal is the schema half of that work.

## Proposal

### `BlockBody`

Add one field, of the canonical Ethereum `ExecutionPayloadV3` shape:

```python
class BlockBody(Container):
    attestations: List[AggregatedAttestation, MAX_ATTESTATIONS_PER_BLOCK]
    execution_payload: ExecutionPayloadV3
```

Where `ExecutionPayloadV3` is the unmodified Cancun container:
`parent_hash`, `fee_recipient`, `state_root`, `receipts_root`,
`logs_bloom (ByteVector[256])`, `prev_randao`, `block_number`,
`gas_limit`, `gas_used`, `timestamp`, `extra_data (ByteList[32])`,
`base_fee_per_gas`, `block_hash`,
`transactions (List[ByteList[MAX_BYTES_PER_TRANSACTION], MAX_TRANSACTIONS_PER_PAYLOAD])`,
`withdrawals (List[Withdrawal, 16])`,
`blob_gas_used`, `excess_blob_gas`.

### `State`

Cache the latest applied payload's header, same projection as Capella:

```python
class State(Container):
    ...
    latest_execution_payload_header: ExecutionPayloadHeader
```

`ExecutionPayloadHeader` is the same shape minus `transactions` and
`withdrawals`, which are replaced by their SSZ hash-tree roots (`Bytes32`
each). Genesis seeds the header to all zeros.

### State transition

A two-assertion `process_execution_payload` runs inside `process_block`,
between header processing and attestation processing:

```python
def process_execution_payload(state, block):
    payload = block.body.execution_payload
    assert payload.parent_hash == state.latest_execution_payload_header.block_hash
    assert payload.timestamp == GENESIS_TIME + state.slot * SECONDS_PER_SLOT
    state.latest_execution_payload_header = ExecutionPayloadHeader(payload)
```

Three deliberate omissions compared to Capella:

1. `prev_randao` check — Lean state has no RANDAO mix yet. Add when one
   lands.
2. `execution_engine.verify_and_notify_new_payload` — that's the
   `engine_newPayloadV3` roundtrip. It belongs in the import pipeline,
   not the STF (which runs in fork-choice testing, replay, and other
   network-free contexts).
3. EIP-4844 blob-versioned-hash check — Lean doesn't define blob
   transactions yet; the EL API call still requires the parameter and
   we pass `[]`.

### Genesis convention

`latest_execution_payload_header = ExecutionPayloadHeader()` (every
field zeroed). The first non-genesis block's `execution_payload.parent_hash`
must therefore equal `H256::ZERO` to be accepted. The synthetic
`block_hash = ZERO` is a degenerate value the EL would normally reject;
that's fine — at genesis we have no real EL block yet, and the first
real `engine_newPayloadV3` call will be against a payload the EL itself
just built.

## Alternatives considered

### A minimal Lean-specific payload

A handful of fields (parent_hash, block_hash, state_root, timestamp).
Smaller surface, but every Engine API call still needs the full V3
shape on the wire, so we'd be translating at the edge. Mirroring V3
verbatim removes that translation cost and aligns Lean clients on a
schema every implementer already understands.

### Defer payload until a future hard fork

Each Lean client would continue to either skip EL pairing or invent
its own field. Wire incompatibility compounds. The translation cost
above also compounds: the longer this is deferred, the more ad-hoc
divergence accumulates.

### Cargo / build-time feature gate (per-client)

ethlambda evaluated this and rejected it during PR #367's
[Phase 2c](engine-api-integration.md). A feature flag inflates every
`BlockBody` and `State` construction with `cfg` pollution and
maintains two SSZ encodings indefinitely. Cleaner to commit to the
schema once it's agreed upstream.

## Open questions

1. **Slot duration vs. EL timestamp granularity.** Lean = 4s, Ethereum
   mainnet = 12s. `compute_time_at_slot` is local to the chain so
   timestamps are internally consistent; it only matters if/when we
   bridge to a mainnet-derived EL state.

2. **Suggested fee recipient.** Per-validator? Per-node CLI? For
   the proposal-mode `engine_forkchoiceUpdatedV3` call, every client
   needs to supply *something*. Convention TBD.

3. **`parent_beacon_block_root` in `PayloadAttributesV3`.** Lean has
   no beacon root analogue. Pass `ZERO` and document, or define a
   meaningful value (e.g., `state.latest_block_header.hash_tree_root()`).

4. **Blob transactions (EIP-4844).** Out of scope here. Phase-N item.

## Reference implementation

ethlambda PR #367 ships this proposal in seven commit-sized phases:

| Phase | What | File |
|---|---|---|
| 1a | Promote `ExecutionPayloadV3` to canonical types crate | `crates/common/types/src/execution_payload.rs` |
| 2a | SSZ-derivable `ExecutionPayloadV3` + `Withdrawal` | same |
| 2b | `ExecutionPayloadHeader` + `payload.to_header()` | same |
| 2c | Embed in `BlockBody` and `State` | `crates/common/types/src/{block,state,genesis}.rs` |
| 2d | `process_execution_payload` in STF | `crates/blockchain/state_transition/src/lib.rs` |
| 3 | `engine_newPayloadV3` on receive | `crates/blockchain/src/lib.rs` (`Handler<NewBlock>`) |
| 4 | `engine_getPayloadV3` on propose | `crates/blockchain/src/lib.rs` (`request_payload_id_for_next_slot` / `take_prepared_payload`) |
| 5 | Real `block_hash` in `engine_forkchoiceUpdatedV3` | `crates/blockchain/src/lib.rs` (`el_hash_at`) |

Spec fixtures stay gated behind a `FIXTURES_AWAIT_M6_REGEN` flag at the
top of each affected `tests/*.rs` entry until upstream regenerates them
against the new schema.
