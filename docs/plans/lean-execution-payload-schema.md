# Proposal: embed `ExecutionPayload` in Lean `BlockBody`

> Status: ready to file (updated 2026-06-09). Intended as the body of a
> leanSpec issue/PR.
>
> Implementation reference:
> [`lambdaclass/ethlambda` PR #367](https://github.com/lambdaclass/ethlambda/pull/367)
> — the full pairing has landed and is verified live against
> [ethrex](https://github.com/lambdaclass/ethrex): real execution payloads flow
> ethlambda → ethrex every slot, and the chain advances on both sides.

## Summary

Add an execution payload to the Lean `BlockBody` and a cached
`ExecutionPayloadHeader` to the Lean `State`, mirroring Ethereum's
Cancun (`ExecutionPayloadV3`) shape verbatim. Define a minimal
`process_execution_payload` in the state transition. This is the schema
dependency that gates every Lean client's ability to pair with a standard
Ethereum execution client over the Engine API.

The change targets the `lstar` fork containers, which is where `BlockBody`
and `State` currently live upstream
(`src/lean_spec/spec/forks/lstar/containers/`).

## Motivation

Today Lean blocks carry only consensus payload (`attestations`, with
signatures folded into the block-level proof). The Engine API
(`engine_forkchoiceUpdated*`, `engine_newPayload*`, `engine_getPayload*`)
needs an EL block hash per slot to forward to the EL, and that hash is what
the EL itself produced when it built/validated a payload — there is no way
to source it without a payload in the block body. Without it:

- An EL paired with a Lean CL stays in `SYNCING` indefinitely. It only ever
  sees zero-valued `ForkChoiceState` triplets and never receives a
  `newPayload` call to chain forward from.
- Each Lean client either omits EL pairing entirely or invents an ad-hoc
  payload field that is wire-incompatible with peers.

ethlambda has implemented the full Engine API client (JWT, JSON-RPC, typed
V3/V4/V5 wrappers) and the complete payload pipeline on the slot loop:
build-mode FCU at interval 4, `getPayload` + embed + `newPayload` at
interval 0, and `newPayload` revalidation on block import. With a payload in
the body this pipeline drives a real EL end-to-end; the only thing that is
not standardized across Lean clients is **the body schema itself**. This
proposal is that schema.

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
`logs_bloom (ByteVector[BYTES_PER_LOGS_BLOOM])`, `prev_randao`,
`block_number`, `gas_limit`, `gas_used`, `timestamp`,
`extra_data (ByteList[MAX_EXTRA_DATA_BYTES])`, `base_fee_per_gas`,
`block_hash`,
`transactions (List[ByteList[MAX_BYTES_PER_TRANSACTION], MAX_TRANSACTIONS_PER_PAYLOAD])`,
`withdrawals (List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD])`,
`blob_gas_used`, `excess_blob_gas`.

Constants (per [execution-apis](https://github.com/ethereum/execution-apis)):

| Constant | Value |
|---|---|
| `BYTES_PER_LOGS_BLOOM` | `256` |
| `MAX_EXTRA_DATA_BYTES` | `32` |
| `MAX_BYTES_PER_TRANSACTION` | `1073741824` |
| `MAX_TRANSACTIONS_PER_PAYLOAD` | `1048576` |
| `MAX_WITHDRAWALS_PER_PAYLOAD` | `16` |

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
   `engine_newPayload` roundtrip. It belongs in the import pipeline, not the
   STF (which runs in fork-choice testing, replay, and other network-free
   contexts).
3. EIP-4844 blob-versioned-hash check — Lean doesn't define blob
   transactions yet; the EL API call still requires the parameter and we
   pass `[]`.

### Genesis convention

`latest_execution_payload_header = ExecutionPayloadHeader()` (every field
zeroed). The first non-genesis block's `execution_payload.parent_hash` must
therefore equal the genesis EL block hash to be accepted.

A real EL rejects an all-zero `block_hash` because it re-derives the hash
from the payload fields on `newPayload`. In practice the CL is seeded with
the EL's genesis block hash (ethlambda takes it via
`--execution-genesis-block-hash`), so the genesis header's `block_hash`
holds the EL's real genesis hash rather than zero, and the first
`newPayload` is against a payload the EL itself just built. leanSpec should
either (a) standardize a "seed genesis header with the EL genesis hash"
convention, or (b) leave the genesis EL hash out of band as a client config
input. ethlambda implements (b).

## Engine API version note

The embedded container is the **Cancun `ExecutionPayloadV3` shape**; the
**Engine method version** a client uses is an independent, EL-driven choice
keyed off the payload `timestamp` against the EL's fork schedule. ethlambda
advertises `V3`/`V4`/`V5` of `newPayload`/`getPayload` in
`engine_exchangeCapabilities` and currently pins `forkchoiceUpdatedV3` plus
the `V5` flavours of new/get payload (matching ethrex main). The body schema
proposed here is version-independent: it is the same `ExecutionPayloadV3`
container regardless of which Engine method version carries it on the wire.

## Alternatives considered

### A minimal Lean-specific payload

A handful of fields (parent_hash, block_hash, state_root, timestamp).
Smaller surface, but every Engine API call still needs the full V3 shape on
the wire, so we'd be translating at the edge. Mirroring V3 verbatim removes
that translation cost and aligns Lean clients on a schema every implementer
already understands.

### Defer payload until a future hard fork

Each Lean client would continue to either skip EL pairing or invent its own
field. Wire incompatibility compounds. The translation cost above also
compounds: the longer this is deferred, the more ad-hoc divergence
accumulates.

### Build-time feature gate (per-client)

ethlambda evaluated this and rejected it during PR #367. A feature flag
inflates every `BlockBody` and `State` construction with conditional-compile
pollution and maintains two SSZ encodings indefinitely. Cleaner to commit to
the schema once it's agreed upstream.

## Decision requested from leanSpec maintainers

1. **Accept the schema** — `execution_payload: ExecutionPayloadV3` in
   `BlockBody` and `latest_execution_payload_header: ExecutionPayloadHeader`
   in `State`, in the `lstar` fork containers — or propose an alternative
   shape. Field ordering and naming should be pinned exactly, since they
   determine the SSZ encoding all clients must agree on.
2. **Genesis EL-hash convention** — standardize seeding the genesis header
   with the EL genesis hash, or treat it as out-of-band client config.
3. **Regenerate consensus test fixtures** against the new schema. This is
   the concrete unblock: ethlambda's spec-fixture tests are gated behind a
   `FIXTURES_AWAIT_M6_REGEN` flag and stay skipped until upstream fixtures
   carry the payload field. See "Reference implementation" below.

## Open questions

1. **Slot duration vs. EL timestamp granularity.** Lean = 4s, Ethereum
   mainnet = 12s. `compute_time_at_slot` is local to the chain so timestamps
   are internally consistent; it only matters if/when we bridge to a
   mainnet-derived EL state.

2. **Suggested fee recipient.** ethlambda implements node-level config: an
   optional `suggested_fee_recipient` key in `validator-config.yaml`'s
   network `config` block (additive — clients that don't read it ignore it).
   Defaults to the zero address, which burns the rewards; ethlambda warns at
   startup when EL-paired with the zero default. Per-validator granularity is
   a possible future refinement.

3. **`parent_beacon_block_root` in `PayloadAttributes`.** ethlambda
   implements the **lean-parent-root convention**: the value is the Lean
   parent block's root — at build time the proposer's current head root
   (the block being built will carry it as `parent_root`), at validate time
   `block.parent_root`. Deterministic on both paths and mirrors EIP-4788
   semantics, so the EL block hash commits to the Lean chain. Note this is
   consensus-relevant for any client validating payloads against an EL
   (the value is part of the EL block hash), so other Lean clients must
   adopt the same rule when they pair.

4. **Blob transactions (EIP-4844).** Out of scope here. Future item.

## Reference implementation

ethlambda PR #367 ships this proposal. The schema and STF have landed and
the full Engine API pipeline is verified live against ethrex.

| Area | What | File |
|---|---|---|
| Types | `ExecutionPayloadV3` + `Withdrawal` (SSZ + JSON dual encoding) | `crates/common/types/src/execution_payload.rs` |
| Types | `ExecutionPayloadHeader` + `payload.to_header()` | same |
| Schema | Embed in `BlockBody` and `State` | `crates/common/types/src/{block,state,genesis}.rs` |
| STF | `process_execution_payload` (parent-hash + timestamp asserts, header projection) | `crates/blockchain/state_transition/src/lib.rs` |
| Import | `engine_newPayloadV5` revalidation on receive | `crates/blockchain/src/lib.rs` (`Handler<NewBlock>`) |
| Propose | `engine_getPayloadV5` on propose (build request at interval 4, consume at interval 0) | `crates/blockchain/src/lib.rs` (`request_payload_id_for_next_slot` / `take_prepared_payload`) |
| FCU | Real `block_hash` triplet in `engine_forkchoiceUpdatedV3` | `crates/blockchain/src/lib.rs` (`current_el_forkchoice_state`) |

Spec fixtures stay gated behind a `FIXTURES_AWAIT_M6_REGEN` flag at the top
of each affected `tests/*.rs` entry
(`forkchoice_spectests.rs`, `signature_spectests.rs`, `stf_spectests.rs`,
and the BlockBody/Block/State/SignedBlock arms of `ssz_spectests.rs`) until
upstream regenerates them against the new schema.
