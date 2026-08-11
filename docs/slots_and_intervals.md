# Slots and Intervals

A Lean Chain slot has a duration of 4 seconds and is divided in 5 intervals:

1. Block proposal
2. Vote propagation
3. Vote aggregation
4. Safe target computation
5. Head update

```text
                             ONE SLOT (4000 ms)
    ┌────────────┬────────────┬────────────┬────────────┬────────────┐
    │ Interval 0 │ Interval 1 │ Interval 2 │ Interval 3 │ Interval 4 │
    │  t+0 ms    │  t+800 ms  │ t+1600 ms  │ t+2400 ms  │ t+3200 ms  │
    ├────────────┼────────────┼────────────┼────────────┼────────────┤
    │   block    │    vote    │    vote    │ safe target│    head    │
    │  proposal  │propagation │aggregation │computation │   update   │
    └────────────┴────────────┴────────────┴────────────┴────────────┘
```

Block proposal is the first interval of a slot. During this interval, a block proposer, selected in a round-robin fashion, proposes a new block and gossips it to the network. Right before building the block, the proposer merges their "new attestations buffer" into their fork-choice view. They then include attestations that the proposer has recently seen into their block. Other validators verify the block and its contents, and merge the votes it includes into their fork-choice view. After importing a block, all validators recompute their [head](./lmd_ghost.md), and update the latest [finalized and justified checkpoints](./3sf_mini.md) according to the block's post-state.

Vote propagation is the second interval of a slot. During this interval, validators gossip their votes for the block they consider to be the head of the chain, and append to it a `(source, target)` [finality vote](./3sf_mini.md). These votes are in aggregation subnets and are imported by aggregators. Aggregators verify the votes in their subnet and store them for later aggregation.

Vote aggregation is the third interval of a slot. During this interval, aggregators aggregate the votes they have received and gossip the resulting aggregated attestations to the network. These aggregated attestations are imported by all validators, who verify and store them in a "new attestations buffer".

Safe target computation is the fourth interval of a slot. During this interval, validators compute the [safe target](./lmd_ghost.md#safe-target-selection) they'll use when deciding which finality vote to cast on the next slot. The safe target is computed based on the votes received in the current slot.

Head update is the fifth and final interval of a slot. During this interval, validators merge the aggregated attestations they have in their "new attestations buffer" into their fork-choice view, and recompute their head.

> **In ethlambda:** the intervals are the `SlotInterval` variants in
> `crates/blockchain/src/lib.rs`, and their length comes from
> `MILLISECONDS_PER_INTERVAL` and `INTERVALS_PER_SLOT` in
> `crates/common/types/src/constants.rs`. Block proposal is merged into the
> previous slot's head-update interval: the proposer advances its store to the
> next slot, builds the block there, and holds publication until the slot
> boundary. That buys the build one extra interval of headroom and leaves no
> actor work at the block-proposal tick itself.
