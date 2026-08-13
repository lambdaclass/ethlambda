# Slots and Intervals

A Lean Chain slot has a duration of 4 seconds and is divided in 5 intervals of 800 ms.
Every duty a validator owes the chain is due in one of them:

| Interval | Offset | Duty | Who acts | What it publishes |
| --- | --- | --- | --- | --- |
| 0 | t+0 ms | [Block proposal](#interval-0-block-proposal) | the slot's proposer | the block, on the `block` topic |
| 1 | t+800 ms | [Vote propagation](#interval-1-vote-propagation) | every validator | a signed attestation, on its subnet topic |
| 2 | t+1600 ms | [Vote aggregation](#interval-2-vote-aggregation) | aggregators | an aggregated attestation, on the `aggregation` topic |
| 3 | t+2400 ms | [Safe target computation](#interval-3-safe-target-computation) | every validator | nothing: local bookkeeping |
| 4 | t+3200 ms | [Head update](#interval-4-head-update) | every validator | nothing: local bookkeeping |

```text
                             ONE SLOT (4000 ms)
    ┌────────────┬────────────┬────────────┬────────────┬────────────┐
    │ Interval 0 │ Interval 1 │ Interval 2 │ Interval 3 │ Interval 4 │
    │  t+0 ms    │  t+800 ms  │ t+1600 ms  │ t+2400 ms  │ t+3200 ms  │
    ├────────────┼────────────┼────────────┼────────────┼────────────┤
    │   block    │    vote    │    vote    │safe target │    head    │
    │  proposal  │propagation │aggregation │computation │   update   │
    └────────────┴────────────┴────────────┴────────────┴────────────┘
     ◄───────────── gossiped ─────────────▶ ◄───── local only ───────▶
```

The grid comes from a genesis timestamp every node shares, so the schedule needs no
coordination messages: a node reads its clock, works out which interval it is in, and
knows which duty is due. The order is a dependency chain, since each interval consumes
what the previous one produced. A duty that overruns its interval is not rescheduled: it
lands late, and the slot moves on without it.

> **In ethlambda:** the intervals are the `SlotInterval` variants in
> `crates/blockchain/src/lib.rs`, and their length comes from
> `MILLISECONDS_PER_INTERVAL` and `INTERVALS_PER_SLOT` in
> `crates/common/types/src/constants.rs`.

## Interval 0: Block proposal

A block proposer, selected in a round-robin fashion (`slot % num_validators`), proposes a
new block and gossips it to the network. Right before building the block, the proposer
merges their "new attestations buffer" into their fork-choice view. They then include
attestations that the proposer has recently seen into their block. Other validators verify
the block and its contents, and merge the votes it includes into their fork-choice view.
After importing a block, all validators [recompute their head](./lmd_ghost.md), and update
the latest [finalized and justified checkpoints](./3sf_mini.md) according to the block's
post-state.

A block body carries at most `MAX_ATTESTATIONS_DATA` aggregated attestations: distinct
`(slot, head, target, source)` tuples, each paired with a bitfield naming the validators
bound to it.
Genesis occupies slot 0, so proposals start at slot 1, and nothing forces a slot to be
filled: a proposer that is offline or too slow leaves an empty slot, and the next block
simply points its parent root at an older block.

> **In ethlambda:** block proposal is merged into the previous slot's head-update
> interval: the proposer advances its store to the next slot, builds the block there,
> and holds publication until the slot boundary. That buys the build one extra interval
> of headroom and leaves no actor work at the block-proposal tick itself.

## Interval 1: Vote propagation

Validators gossip their votes for the block they consider to be the head of the chain, and
append to it a `(source, target)` [finality vote](./3sf_mini.md#recap-attestation-anatomy).
These votes are in aggregation subnets and are imported by aggregators. Aggregators verify
the votes in their subnet and store them for later aggregation.

> **In ethlambda:** a validator's subnet is `validator_index % attestation_committee_count`,
> and a node only aggregates for subnets it subscribed to at startup. Aggregation is also
> gated on the aggregator role, seeded by `--is-aggregator` and flippable at runtime
> through the admin API. A chain whose validators all decline the role still gossips votes
> and logs them as processed, but no aggregate is ever produced, so every block is empty
> and the chain never justifies.

## Interval 2: Vote aggregation

Aggregators aggregate the votes they have received and gossip the resulting aggregated
attestations to the network. These aggregated attestations are imported by all validators,
who verify and store them in a "new attestations buffer".

Aggregation earns its own interval because collapsing a subnet's worth of XMSS signatures
into one proof is the heaviest recurring computation in the client. It is also what makes a
block affordable, since a block carrying raw votes would need one full XMSS signature per
voter, quickly going over the network bandwidth limit.

> **In ethlambda:** the proofs run on an off-thread worker so the blockchain actor's
> message loop stays responsive, and a session may start up to `EARLY_AGGREGATION_WINDOW`
> before the interval boundary once two thirds of the signatures are in. At the session's
> soft deadline the actor stops handing out new jobs, but a proof already in flight
> finishes and publishes late rather than being discarded.

## Interval 3: Safe target computation

Validators compute the [safe target](./lmd_ghost.md#safe-target-selection) they'll use when
deciding which finality vote to cast on the next slot. The safe target is computed based on
the votes received in the current slot.

It is LMD-GHOST again, but run over just the votes that arrived this slot and with a
two-thirds weight threshold, where head selection applies none. The safe target therefore
sits at or behind the head and advances only once a branch is backed by a supermajority.
Deriving targets from it is what stops [3SF-mini](./3sf_mini.md) from justifying a branch
the network has not visibly converged on.

## Interval 4: Head update

Validators merge the aggregated attestations they have in their "new attestations buffer"
into their fork-choice view, and recompute their head.

This is the slot's second and last promotion point; the first is the proposer's, just
before it builds. Until a vote is promoted it carries no weight in head selection, which is
what keeps a validator's fork-choice view from shifting under it mid-slot. The safe target
is the exception: it reads the unpromoted buffer directly, which is how it stays a view of
this slot alone. See [why staged promotion](./lmd_ghost.md#why-staged-promotion) for the
reasoning.
