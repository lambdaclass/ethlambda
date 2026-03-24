# Proto-array fork choice

## The problem

Every time `update_head` ran (up to 2x per slot), it recomputed the LMD-GHOST head from scratch: for every validator attestation, walk backward through the entire chain accumulating weights, then pick the heaviest path. That's **O(validators × chain_depth)** per call.

## How proto-array works

Proto-array is a flat array of nodes (one per block) that maintains:
- **Subtree weights**: how many votes each node's subtree has
- **`best_child` pointers**: which child has the heaviest subtree

Instead of recomputing everything, it works incrementally:

1. **`compute_deltas`**: Compare each validator's current vote against their previous vote. If validator 5 moved from block A to block B, produce `A: -1, B: +1`. Unchanged votes produce zero deltas. This is **O(changed_votes)**.

2. **`apply_score_changes`**: Single backward pass over the array — update each node's weight by its delta, propagate to parent, update `best_child`. This is **O(nodes)**.

3. **`find_head`**: Follow `best_child` pointers from the justified root to a leaf. This is **O(depth)**.

### Complexity comparison

| Operation | Spec implementation | Proto-array |
|-----------|-------------------|-------------|
| `update_head` | O(validators × chain_depth) | O(changed_votes + nodes + depth) |
| `update_safe_target` | O(validators × chain_depth) | O(changed_votes + nodes + depth) |

## Architecture

### Two independent fork choice pools

`update_head` and `update_safe_target` use **different attestation pools**:
- **Head**: only "known" attestations (already promoted through the pipeline)
- **Safe target**: "known" + "new" merged (the most complete picture available)

A `VoteTracker` is stateful — it remembers each validator's last vote to compute deltas. If we fed both pools into the same tracker, the head computation would see attestations it shouldn't, corrupting weights.

Solution: two independent `ForkChoiceState` instances, each with its own proto-array and vote tracker:

```
ForkChoice
├── head: ForkChoiceState          ← known attestations only
│   ├── proto_array                   (same block tree)
│   └── vote_tracker                  (tracks known-pool votes)
└── safe_target: ForkChoiceState   ← known + new attestations merged
    ├── proto_array                   (same block tree)
    └── vote_tracker                  (tracks merged-pool votes)
```

The `ForkChoice` wrapper ensures both proto-arrays stay in sync:
- `fc.on_block(root, parent, slot)` → registers the block in **both** trees
- `fc.prune_and_reset(finalized_root)` → prunes **both** trees and resets **both** vote trackers

### Safe target threshold

`update_safe_target` picks the deepest block with ≥ 2/3 validator support. This uses `find_head_with_threshold(root, min_score)` — same as `find_head` but stops walking down when the best child's weight drops below the threshold:

```rust
while let Some(best_child_idx) = self.nodes[current_idx].best_child {
    if self.nodes[best_child_idx].weight < min_score {
        break;  // no child meets the 2/3 threshold, stop here
    }
    current_idx = best_child_idx;
}
```

This works because `best_child` always points to the heaviest child. If even the heaviest doesn't meet the threshold, no child can.

## Lifecycle

### Startup

`ForkChoice::from_store` builds both proto-arrays from the `LiveChain` table (sorted by slot for topological order), then applies the current known attestations to initialize weights.

### Per-block (`on_block_core`)

1. Run state transition
2. If finalization advanced: `fc.prune_and_reset(finalized_root)` — prune both trees, reset both vote trackers
3. `fc.on_block(root, parent, slot)` — register in both trees
4. `update_head` — apply known attestations to `fc.head`, find head

### Per-slot tick

| Interval | Action | Fork choice involvement |
|----------|--------|------------------------|
| 0 | Accept attestations if proposal exists | `fc.head` updated via `update_head` |
| 1 | Vote propagation | — |
| 2 | Aggregate committee signatures | — |
| 3 | Update safe target | `fc.safe_target` updated via `update_safe_target` |
| 4 | Accept accumulated attestations | `fc.head` updated via `update_head` |

## Debug oracles

Both `update_head` and `update_safe_target` have a `#[cfg(debug_assertions)]` block that runs the old spec implementation in parallel and asserts the result matches proto-array:

- **Debug/test builds**: both implementations run and any divergence panics immediately
- **Release builds**: only proto-array runs (zero overhead from the oracle)

This means the 27 fork choice spec tests validate proto-array correctness on every `update_head` call, and any `update_safe_target` call in debug builds is also verified.

## Key files

| File | What |
|------|------|
| `crates/blockchain/fork_choice/src/proto_array.rs` | `ProtoArray` (tree + weights), `VoteTracker` (delta computation) |
| `crates/blockchain/src/store.rs` | `ForkChoice` wrapper, `update_head`, `update_safe_target`, `on_block_core` |
| `crates/blockchain/src/lib.rs` | `BlockChainServer` owns the `ForkChoice` instance |
