# LMD-GHOST fork choice algorithm

A deep dive into how the **LMD-GHOST** (Latest Message Driven, Greedy Heaviest Observed SubTree)
fork choice algorithm works. LMD-GHOST is the fork choice rule used by Ethereum's consensus layer
and its derivatives. Each validator's **latest attestation** is their single active vote, and the
algorithm follows the heaviest branch at every fork.

This document is implementation-agnostic, with ethlambda-specific details called out in
blockquotes marked **"In ethlambda"**.

> Much of the conceptual framing in this document is inspired by Ben Edgington's
> [Eth2 Book](https://eth2book.info/), particularly the
> [LMD GHOST chapter](https://eth2book.info/latest/part2/consensus/lmd_ghost/).
> Highly recommended reading for anyone interested in Ethereum consensus.

---

## Background & History

The GHOST protocol was introduced by **Sompolinsky and Zohar** in a
[2013 paper][ghost-paper]. Its core idea: instead of choosing the heaviest chain,
we choose the **heaviest subtree**, counting orphaned blocks as evidence of support for
their ancestors.

The "LMD" in LMD-GHOST stands for **Latest Message Driven**: only each validator's
**most recent** attestation counts, preventing vote amplification. LMD-GHOST is the
fork choice rule used by the Ethereum Beacon Chain and Lean Ethereum.

[ghost-paper]: https://eprint.iacr.org/2013/881.pdf

---

## Why Fork Choice?

In a distributed system where validators propose blocks concurrently, the blockchain can
fork: two valid blocks may appear at the same slot, creating competing chains. The
**fork choice rule** answers a critical question:

> *Which chain tip should I follow?*

```text
                   ┌──────────┐
             ┌────▶│ Block C  │  ← Chain tip 1
             │     │ slot 5   │
┌──────────┐ │     └──────────┘
│ Block A  │─┤
│ slot 3   │ │     ┌──────────┐
└──────────┘ └────▶│ Block D  │  ← Chain tip 2
                   │ slot 5   │
                   └──────────┘

                    Which tip should validators follow?
```

Every node in the network must be able to independently arrive at the same answer using
only its local view of blocks and attestations. The fork choice rule is what makes this
possible. It is a deterministic function from a node's observed state to a single chain tip.

---

## From Heaviest Chain to Heaviest Subtree

The simplest fork choice rule is **heaviest chain**: follow the chain tip with the most
accumulated weight. This works when fork rates are low, but breaks down when honest
validators fork within a common branch:

```text
              HEAVIEST CHAIN vs HEAVIEST SUBTREE
              ──────────────────────────────────

    An attacker with 40% of stake forks at A.
    The honest majority (60%) builds on B but forks into C and D:

                    ┌───B──┬──C     V0, V1, V2 vote for C (30%)
              A ────┤      └──D     V3, V4, V5 vote for D (30%)
                    │
                    └───X──Y──Z     V6, V7, V8, V9 vote for Z (40%)

    Heaviest chain:
      Z has 40% of votes, C and D each have 30%.
      Attacker wins! ✗

    Heaviest subtree (LMD-GHOST):
      At A: B subtree has 60% (C + D), X subtree has 40%.
      Pick B. Then at B: C has 30%, D has 30% (tiebreaker).
      Honest majority wins. ✓
```

LMD-GHOST is strictly better when honest validators fork within a common subtree.
Instead of requiring all honest validators to agree on a single chain tip (which is
impossible under network delay), it aggregates their support at each level of the tree.

### How Subtree Weight Works (the "GHOST" Part)

The key insight behind the "Heaviest Observed SubTree" part of LMD-GHOST:
**a vote for a block is implicitly a vote for all its ancestors.**

When a validator attests to block F as their head, they are also expressing support
for every block on the path from the root to F:

```text
    Validator attests: head = F

    A ── B ── C ── D ── E ── F
    ▲    ▲    ▲    ▲    ▲    ▲
    │    │    │    │    │    │
    └────┴────┴────┴────┴────┘
    All ancestors implicitly supported
```

This is why LMD-GHOST counts the **subtree** weight: a block's weight includes every
attestation for any of its descendants, because those attestations implicitly endorse
the ancestor too. The algorithm exploits this by walking backward from each attested
head and incrementing every block along the path.

---

## LMD: Why Only the Latest Message?

The "LMD" in LMD-GHOST stands for **Latest Message Driven**. Each validator's **most
recent** attestation is their only vote. All previous attestations are discarded.

```text
    Validator 7's attestation history:

    Slot 10: attests to head = B     ← discarded
    Slot 11: attests to head = C     ← discarded
    Slot 12: attests to head = E     ← THIS is the active vote

    Only the slot 12 attestation counts for fork choice.
```

Why only the latest? Two reasons:

1. **Prevents double-voting.** If all messages counted, a validator could cast many
   attestations and amplify their influence. With LMD, each validator gets exactly one
   active vote regardless of how many attestations they've broadcast.

2. **Reflects current knowledge.** A validator's latest attestation reflects their most
   recent view of the chain. Older attestations may reference blocks that are no longer
   on the best chain. Keeping only the latest ensures fork choice uses the most up-to-date
   information.

The fork choice store maintains a mapping of `validator_index → latest attestation`.
When a new attestation arrives from a validator, it **replaces** their previous entry:

```text
    Fork choice store (latest messages):

    ┌──────────────┬──────────────────────────────┐
    │ Validator    │ Latest Attestation           │
    ├──────────────┼──────────────────────────────┤
    │ 0            │ head=E, target=C, source=A   │
    │ 1            │ head=D, target=C, source=A   │
    │ 2            │ head=E, target=C, source=A   │
    │ 3            │ head=F, target=D, source=A   │
    │ ...          │ ...                          │
    └──────────────┴──────────────────────────────┘

    One row per validator. New attestation → overwrite row.
```

---

## LMD-GHOST Step by Step

The algorithm takes a set of inputs and produces a single block root: the head of
the chain.

### Inputs

| Input | Purpose |
|-------|---------|
| Start root | The justified checkpoint (root of the subtree to search) |
| Block tree | The set of known blocks: root → (slot, parent) |
| Attestations | Latest message per validator: validator_index → attestation |
| Min score | Minimum weight for a branch to be considered (0 = follow any branch; higher = conservative) |

> **In ethlambda:** The function is `compute_lmd_ghost_head()` in
> `crates/blockchain/fork_choice/src/lib.rs`. The block tree comes from
> the `LiveChain` storage index, and `min_score` is 0 for head selection
> or ⌈2V/3⌉ for safe target computation.

### The Algorithm

First, **accumulate weights.** Each attestation "paints" the path from its head back
to the start root. In the simplest form (equal-weight validators), this adds +1 to
every block on the path. In systems with balance-weighted voting, the validator's
effective balance is added instead.

```text
    Validator 0 attests to head = F

      J ─ A ─ B ─ C ─ D ─ E ─ F       (J = justified root)
          +1  +1  +1  +1  +1  +1       J is at start_slot, not counted

    Validator 1 attests to head = D

      J ─ A ─ B ─ C ─ D
          +1  +1  +1  +1

    Accumulated weights:

      Block:    J    A    B    C    D    E    F
      Weight:   ─    2    2    2    2    1    1
                │
                └ start_root (not weighted, used as the descent origin)
```

> **In ethlambda:** All validators have equal weight (+1 per vote). The Ethereum
> Beacon Chain instead weights votes by effective balance (up to 2048 ETH).

Then, **greedily descend.** Starting from the start root, at each node pick the child
with the most weight. Repeat until reaching a leaf:

```text
    J ──┬── B (5)   ← pick B (higher weight)
        └── G (2)

    B ──┬── C (3)   ← pick C (higher weight)
        └── H (2)

    C ──── D (3)    ← only child, continue

    D ── (no children) → HEAD = D!
```

Children below `min_score` are ignored during the descent. With `min_score = 0`
(normal head selection) all children are visible. With a higher threshold, only
branches with strong support are followed. This is used for
[safe target selection](#safe-target-selection).

### The Tiebreaker

When two children have exactly equal weight, a deterministic tiebreaker is needed.
Without one, different nodes could pick different heads from the same data, breaking
consensus. The tiebreaker is **lexicographically higher block root hash**, i.e.,
higher hash value wins.

```text
    Equal weight scenario:

        Parent
        │
    ┌───┴───┐
    B (3)   C (3)         ← Equal weight!
    root:   root:
    0x3a..  0x7f..        ← 0x7f > 0x3a, so pick C
```

The choice of "higher hash wins" is a convention. Any deterministic rule would work;
what matters is that all nodes apply the same one.

---

## Worked Example: Head Selection

Consider a network with **5 validators** (indices 0–4) and the following block tree
rooted at the justified checkpoint `J` at slot 10:

```text
                          BLOCK TREE
                          ──────────

Slot 10     ┌──────┐
(justified) │  J   │ ← Justified checkpoint (start_root)
            └──┬───┘
               │
Slot 11     ┌──┴───┐
            │  A   │
            └──┬───┘
            ┌──┴────────┐
            │           │
Slot 12  ┌──┴───┐    ┌──┴───┐
         │  B   │    │  C   │
         └──┬───┘    └──┬───┘
            │           │
Slot 13  ┌──┴───┐    ┌──┴───┐
         │  D   │    │  E   │
         └──────┘    └──────┘
```

**Latest attestations (one per validator):**

| Validator | Attested Head | Path back from head to J |
|-----------|---------------|--------------------------|
| 0         | D             | D → B → A → (J)         |
| 1         | D             | D → B → A → (J)         |
| 2         | E             | E → C → A → (J)         |
| 3         | E             | E → C → A → (J)         |
| 4         | E             | E → C → A → (J)         |

**Accumulate weights** by walking backward from each attested head, adding +1 per
block (stopping at J's slot):

```text
    V0 (head=D):  D+1  B+1  A+1
    V1 (head=D):  D+1  B+1  A+1
    V2 (head=E):  E+1  C+1  A+1
    V3 (head=E):  E+1  C+1  A+1
    V4 (head=E):  E+1  C+1  A+1
```

| Block | Weight | Explanation |
|-------|--------|-------------|
| A     | 5      | On path of all 5 validators |
| B     | 2      | On path of V0, V1 |
| C     | 3      | On path of V2, V3, V4 |
| D     | 2      | Head of V0, V1 |
| E     | 3      | Head of V2, V3, V4 |

**Greedily descend** from J, always picking the heaviest child:

```text
    Start at J
      └─▶ A (only child, weight 5)
           ├── B (weight 2)
           └── C (weight 3)  ← Pick C (3 > 2)
                └─▶ E (only child, weight 3)
                     └─▶ No children → HEAD = E ✓
```

**Result:** The canonical head is **Block E**. Even though both branches have the same
depth, the C→E branch has 3 votes vs B→D's 2 votes.

```text
                          RESOLVED HEAD
                          ─────────────

Slot 10     ┌──────┐
            │  J   │
            └──┬───┘
               │
Slot 11     ┌──┴───┐
            │  A   │ ✓ canonical
            └──┬───┘
            ┌──┴────────┐
            │           │
Slot 12  ┌──┴───┐    ┌──┴───┐
         │  B   │    │  C   │ ✓ canonical (weight 3 > 2)
         └──┬───┘    └──┬───┘
            │           │
Slot 13  ┌──┴───┐    ┌──┴───┐
         │  D   │    │  E   │ ★ HEAD
         └──────┘    └──────┘
```

### What If a Vote Changes?

Suppose validator 1 now sees block E and switches their attestation from D to E:

```text
    Before:  V0=D, V1=D, V2=E, V3=E, V4=E   → Head = E (3 vs 2)
    After:   V0=D, V1=E, V2=E, V3=E, V4=E   → Head = E (4 vs 1)

    The head didn't change, but the margin increased from 1 to 3.
    If instead V2 and V3 had switched to D:

    After:   V0=D, V1=D, V2=D, V3=D, V4=E   → Head = D (4 vs 1)

    The head reorgs from E to D.
```

---

## Fork Choice vs Finality

An important conceptual distinction: **LMD-GHOST provides fork choice, not finality.**

LMD-GHOST gives the network a way to agree on the current head of the chain at any
moment, but the head can change. A block selected by fork choice today could be
reorged away tomorrow if attestations shift. LMD-GHOST alone provides no guarantee
that any block is permanent.

**Finality**, the guarantee that a block can never be reverted, comes from a separate
mechanism called a **finality gadget**. LMD-GHOST is designed to compose with any
finality gadget (e.g., Casper FFG in the Ethereum Beacon Chain, or [3SF-mini](3sf_mini.md) in Lean Ethereum).

```text
    ┌────────────────────────────────────────────────────┐
    │                 CONSENSUS = TWO LAYERS             │
    │                                                    │
    │  ┌─────────────┐        ┌──────────────────────┐   │
    │  │  LMD-GHOST  │        │  Finality Gadget     │   │
    │  │             │        │                      │   │
    │  │ "Which tip  │        │ "Which blocks are    │   │
    │  │  is best    │        │  permanent and can   │   │
    │  │  right now?"│        │  never be reverted?" │   │
    │  │             │        │                      │   │
    │  │ Dynamic,    │        │ Monotonic, only      │   │
    │  │ can reorg   │        │ moves forward        │   │
    │  └──────┬──────┘        └──────────┬───────────┘   │
    │         │                          │               │
    │         └──────────┬───────────────┘               │
    │                    ▼                               │
    │         ┌──────────────────┐                       │
    │         │  Full Consensus  │                       │
    │         └──────────────────┘                       │
    └────────────────────────────────────────────────────┘
```

> **In ethlambda:** The finality gadget is [3SF-mini](3sf_mini.md), which operates at
> the slot level rather than epoch boundaries.

The two layers interact: LMD-GHOST runs its greedy descent **starting from the latest
justified checkpoint** (not genesis). This means finality constrains fork choice: once
a checkpoint is finalized, no fork choice run will ever consider blocks before it.

```text
    ┌─────────┐         ┌─────────┐         ┌──── ...
    │FINALIZED│────────▶│JUSTIFIED│────────▶│  fork choice
    │ slot 50 │         │ slot 55 │         │  runs here
    └─────────┘         └─────────┘         └──── ...
         │                   │
         │                   └── start_root for LMD-GHOST
         │
         └── everything before this is permanent
```

This has a major practical benefit: **finality allows aggressive pruning of the block
tree.** Without finality, fork choice would need to consider every block since genesis,
and the tree would grow without bound. With finality, all blocks at or before the finalized
checkpoint can be discarded from the fork choice's working set.

> **In ethlambda:** The `LiveChain` index (the in-memory block tree used by fork choice)
> is pruned every time finalization advances, keeping it bounded to only the non-finalized
> portion of the chain.

---

## Attestation Pipeline

In a naive implementation, every attestation would influence fork choice the instant it
arrives. This creates problems: validators with faster network connections see different
heads than slower ones, and the proposer's view of the chain could shift mid-block-construction.

Lean Ethereum solves this with a **staged promotion pipeline**: attestations are
collected into a pending set and only promoted to the active fork choice set at
designated moments. This ensures all validators operate on a consistent view.

```text
                       ATTESTATION LIFECYCLE
                       ─────────────────────

  ┌──────────────┐       ┌──────────────────┐       ┌──────────────────┐
  │   Network    │       │    Pending       │       │    Active        │
  │  (gossip)    │──────▶│  Attestations    │──────▶│  Attestations    │
  │              │       │                  │       │                  │
  └──────────────┘       └──────────────────┘       └──────────────────┘
                                 │                          │
                          NOT used for               Used for fork choice
                          fork choice                weight calculations
                                 │                          │
                          Promoted at ─────────────▶ designated intervals
                          fixed points
```

> **In ethlambda:** The two stages are called "new" and "known" attestations, stored
> in `LatestNewAttestations` and `LatestKnownAttestations` tables respectively.
> Promotion happens at tick intervals 0 (if proposing) and 3 (end of slot).

### Why Staged Promotion?

The staged design serves two purposes:

1. **Consistency:** All validators promote attestations at the same moments,
   reducing divergence in head selection. Without batching, validators with faster
   network connections would see different heads than slower ones.

2. **Proposer fairness:** The proposer computes the block against a known, fixed set
   of attestations. If new attestations could influence fork choice mid-computation,
   different validators might disagree on the head.

### On-Chain vs Off-Chain Attestations

Attestations arrive from two sources, and how they enter the pipeline matters:

| Source | Enters As | Reason |
|--------|-----------|--------|
| Network gossip | **Pending** | Must wait for promotion window |
| Block body (on-chain) | **Active** | Already consensus-validated |
| Proposer's own attestation | **Pending** | Prevents proposer weight advantage |

The proposer's own attestation enters as pending (not active) deliberately. If it
were immediately active, the proposer would gain an unfair weight advantage for
their own block, a circular dependency where proposing a block gives you an extra
vote toward making that block canonical.

---

## Safe Target Selection

The **safe target** is a conservative head computed with a high weight threshold.
Validators use this as their attestation target (not the regular head), ensuring
they only vote for chains backed by a supermajority. This is achieved by running
the same LMD-GHOST algorithm but with a non-zero `min_score` in the filtering phase.

```text
                    SAFE TARGET vs HEAD
                    ────────────────────

    Regular head (min_score = 0):
    Follow heaviest branch, even with a slim margin

             ┌── B (3 votes) ← HEAD (3 > 2)
    J ── A ──┤
             └── C (2 votes)


    Safe target (min_score = ⌈2V/3⌉):
    Only follow branches with supermajority support

    V = 5 validators, threshold = ⌈10/3⌉ = 4

             ┌── B (3 votes) ← Below threshold (3 < 4), pruned
    J ── A ──┤
             └── C (2 votes) ← Below threshold (2 < 4), pruned

    Safe target = A (no children pass threshold)
```

This means the safe target **lags behind** the head. It only advances when a branch
accumulates overwhelming support, making it resistant to temporary fluctuations:

```text
    Timeline of safe target vs head:

    Slot:    10    11    12    13    14    15    16
    Head:    J     A     B     D     D     E     F
    Safe:    J     J     J     A     A     A     D
                                                  │
                        Safe target is always ────┘
                        at or behind the head
```

The safe target prevents a dangerous feedback loop: without it, a slim-majority fork
could attract attestations → making it the head → attracting more attestations, even
if it shouldn't be the canonical chain. By requiring supermajority support for the
target, validators only reinforce branches that already have strong consensus.

---

## Reorgs

A **reorg** (reorganization) occurs when the fork choice head switches from one branch
to another. This happens when a competing branch accumulates more attestation weight
than the current head's branch.

```text
                    REORG SCENARIO
                    ──────────────

    Before (head = D):

              ┌── B ── D   ★ HEAD (weight 4)
    J ── A ──┤
              └── C ── E      (weight 3)


    New attestations arrive, 3 validators switch to E:

              ┌── B ── D      (weight 2)
    J ── A ──┤
              └── C ── E   ★ HEAD (weight 5)    ← REORG!


    The canonical chain changed from  J─A─B─D  to  J─A─C─E
    Blocks B and D are no longer canonical (but remain in the block tree).
```

Reorgs are normal during transient network conditions but should be rare in stable
operation. They cannot cross a finalization boundary: once a block is finalized, it is
permanently part of the canonical chain.

> **In ethlambda:** Reorgs are detected by checking whether the old and new heads
> share a common prefix, and tracked via Prometheus metrics
> (`lean_fork_choice_reorgs_total`).

---

## LMD-GHOST Variants

LMD-GHOST is one of several variants that have been proposed and studied. Understanding
the design space helps explain why LMD was chosen.

| Variant | Full Name | What Counts | Trade-off |
|---------|-----------|-------------|-----------|
| **IMD** | Immediate Message Driven | All attestations ever | Maximizes data but creates unbounded storage and is vulnerable to long-range rewriting |
| **LMD** | Latest Message Driven | Only each validator's most recent attestation | Good balance: one vote per validator, reflects current view, bounded storage |
| **FMD** | Fresh Message Driven | Only attestations from current/previous epoch | Prevents very old attestations from influencing fork choice, but validators who go offline lose influence immediately |
| **RLMD** | Recent Latest Message Driven | Latest attestation, but only if within N epochs | Parameterized compromise between LMD and FMD; tunable staleness threshold |

The Ethereum consensus mini-spec originally used IMD-GHOST but switched to LMD in
November 2018 due to superior stability properties.

```text
    IMD: All attestations count         LMD: Only latest counts

    V0: slot 5 → head B                V0: slot 5 → head B  (overwritten)
    V0: slot 8 → head C                V0: slot 8 → head C  ← active
    V0: slot 11 → head E               V0: slot 11 → head E ← active

    V0 contributes 3 votes!            V0 contributes 1 vote.
    Validators who attest more          Equal influence regardless
    often have outsized influence.      of attestation frequency.
```

---

## ethlambda Implementation Reference

This section covers ethlambda-specific details: scheduling, Beacon Chain differences,
source code locations, and performance.

### Tick-Based Scheduling

ethlambda divides time into **4-second slots**, each split into **4 intervals** (1 second
each). Fork choice operations are scheduled at specific intervals:

```text
                          ONE SLOT (4 seconds)
    ┌──────────────┬──────────────┬──────────────┬──────────────┐
    │  Interval 0  │  Interval 1  │  Interval 2  │  Interval 3  │
    │   (t+0s)     │   (t+1s)     │   (t+2s)     │   (t+3s)     │
    ├──────────────┼──────────────┼──────────────┼──────────────┤
    │              │              │              │              │
    │ IF PROPOSER: │ NON-PROPOSER:│ update_safe  │ accept_new   │
    │  accept new  │  produce     │ _target()    │ _attestations│
    │  attestations│  attestation │              │ ()           │
    │  + propose   │              │ (2/3 vote    │              │
    │  block       │              │  threshold)  │ update_head()│
    │              │              │              │              │
    │ update_head()│              │              │              │
    │              │              │              │              │
    └──────────────┴──────────────┴──────────────┴──────────────┘

    ◄─────────────── Slot N ──────────────────────────────────────►
```

**Detailed sequence:**

```text
    Interval 0 ─ Slot boundary
    │
    ├── Am I the proposer for this slot?
    │   ├── YES: promote new → known attestations
    │   │        run fork choice → update_head()
    │   │        build block using known attestations
    │   │        publish block to network
    │   └── NO:  (wait for block from proposer)
    │
    Interval 1 ─ Attestation production
    │
    ├── Non-proposers:
    │   └── Create attestation with:
    │       • head   = current fork choice head
    │       • target = safe_target (conservative, 2/3 backed)
    │       • source = latest_justified checkpoint
    │       Publish attestation to gossipsub
    │
    Interval 2 ─ Safe target update
    │
    ├── Recalculate safe_target using 2/3 supermajority threshold
    │   └── Only blocks with ≥ ⌈2V/3⌉ attestation weight qualify
    │       (V = total validators)
    │
    Interval 3 ─ End of slot
    │
    ├── Promote new → known attestations
    └── Run fork choice → update_head()
```

### Differences from the Ethereum Beacon Chain

ethlambda is a lean consensus client with several simplifications compared to the
Ethereum Beacon Chain:

| Aspect | ethlambda | Ethereum Beacon Chain |
|--------|-----------|----------------------|
| **Vote weight** | Equal: 1 vote per validator | Proportional to effective balance (up to 32 ETH) |
| **Proposer boost** | None | Yes: newly proposed blocks get temporary bonus weight |
| **Equivocation handling** | Not in fork choice | Equivocating validators' weight excluded |
| **Attestation frequency** | Every slot | Once per epoch |
| **Committee structure** | All validators attest each slot | Validators split into per-slot committees |
| **Slot duration** | 4 seconds | 12 seconds |

**No proposer boost.** The Beacon Chain adds a "proposer boost", a temporary weight bonus
given to newly proposed blocks to prevent balancing attacks. ethlambda does not implement
this. Instead, proposer fairness is handled through the two-stage attestation pipeline
(the proposer's own attestation enters as "new", not "known").

**No balance weighting.** In the Beacon Chain, a validator with 32 ETH of effective balance
has more fork choice weight than one with 16 ETH. In ethlambda, every validator has exactly
equal weight (1 vote = 1 unit of weight), simplifying the algorithm and analysis.

**No equivocation discounting.** The Beacon Chain's fork choice detects validators who
equivocate (attest to conflicting blocks in the same slot) and excludes their weight. This
addresses the "nothing at stake" problem where validators can costlessly vote for multiple
forks. ethlambda does not implement this in its fork choice.

### Key Files

| File | Component |
|------|-----------|
| `crates/blockchain/fork_choice/src/lib.rs` | Core LMD-GHOST algorithm (`compute_lmd_ghost_head`) |
| `crates/blockchain/src/store.rs` | Store: head update, safe target, attestation promotion |
| `crates/blockchain/src/lib.rs` | BlockChain actor: tick scheduling, interval dispatch |
| `crates/common/types/src/attestation.rs` | `AttestationData` type (head, target, source, slot) |
| `crates/common/types/src/state.rs` | `Checkpoint` (root + slot), `State` |
| `crates/storage/src/api/` | `LiveChain` table, `StorageBackend` trait |

### Data Flow Summary

```text
     ┌───────────┐         ┌──────────────┐             ┌───────────────┐
     │ Gossipsub │────────▶│ New          │──(promote)─▶│ Known         │
     │ (network) │         │ Attestations │             │ Attestations  │
     └───────────┘         └──────────────┘             └───────┬───────┘
                                                                │
     ┌───────────┐                                              │
     │ LiveChain │──── { root → (slot, parent) } ───────────────┤
     │  (index)  │                                              │
     └───────────┘                                              │
                                                                ▼
                                                  ┌─────────────────┐
     ┌───────────┐                                │ compute_lmd_    │
     │ Justified │──── start_root ───────────────▶│ ghost_head()    │
     │Checkpoint │                                │                 │
     └───────────┘                                └────────┬────────┘
                                                           │
                                                    ┌──────┴──────┐
                                                    │             │
                                                    ▼             ▼
                                              ┌──────────┐ ┌───────────┐
                                              │   HEAD   │ │   SAFE    │
                                              │ (min=0)  │ │  TARGET   │
                                              └──────────┘ │ (min=2V/3)│
                                                           └───────────┘
```

### Performance Characteristics

| Operation | Time Complexity | Description |
|-----------|----------------|-------------|
| Weight accumulation | O(A × D) | A = attestations, D = max chain depth from justified root |
| Greedy descent | O(D × B) | D = depth, B = max branching factor |
| Attestation promotion | O(V) | V = total validators |
| LiveChain lookup | O(B) | B = non-finalized blocks |

In practice with a small validator set and bounded non-finalized chain length,
all operations complete in sub-millisecond time. The `// TODO: add proto-array
implementation` comment in the source indicates a future optimization path:
proto-array is an O(1) amortized fork choice algorithm used by most Beacon Chain
clients.
