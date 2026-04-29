# 3SF-mini: Justification & Finalization

ethlambda uses **3SF-mini** (Three-Stage Finality, minimal version) for justification
and finalization. Unlike the Ethereum Beacon Chain's epoch-based Casper FFG, 3SF-mini
operates at the **slot level**: any slot can be justified, not just epoch boundaries.

## Quick Example: Three Slots to Finality

4 validators, slot N already finalized and justified.

```text
                             source  target
                                │       │
                                ▼       ▼
    Slot N        ──[ N-2 ]──[ N-1 ]──[ N ]
                       F        J       H

                                     source    target
                                        │         │
                                        ▼         ▼
    Slot N+1      ──[ N-2 ]──[ N-1 ]──[ N ]────[ N+1 ]
                       F        F       J         H

                                               source     target
                                                  │          │
                                                  ▼          ▼
    Slot N+2      ──[ N-2 ]──[ N-1 ]──[ N ]────[ N+1 ]────[ N+2 ]
                       F        F       F         J          H

    H = head    J = justified    F = finalized
```

At each slot, validators vote for the newest block as their **target**, citing
the latest justified checkpoint as their **source**:

- **Slot N+1:** Votes `source=N, target=N+1`. Three of four vote
  (3×3=9 >= 2×4=8), so **N+1 is justified**.
- **Slot N+2:** Votes `source=N+1, target=N+2`. Three of four vote, so
  **N+2 justified**. N+1 and N+2 are consecutive justifiable slots and both
  are justified, so **N+1 is finalized**.

In the ideal case, each block carries attestations that justify the parent slot
and finalize the one before it. In practice, forks, missed slots, and delayed
votes can break this cadence. The rest of this document explains the rules that
make this work, and what happens when things go wrong.

## Concepts

| Term | Meaning |
|------|---------|
| **Justified** | A checkpoint backed by at least two-thirds of validator votes |
| **Finalized** | A checkpoint that can never be reverted |
| **Source** | The latest justified checkpoint (vote origin) |
| **Target** | The checkpoint being voted for (vote destination) |
| **Justifiable** | A slot that *could* become justified (per the 3SF-mini schedule) |

## Justification via Supermajority

A checkpoint becomes **justified** when at least two-thirds of validators attest to it as a target:

```text
                   JUSTIFICATION
                   ─────────────

    Validators:  V0  V1  V2  V3  V4  V5  V6  V7  V8
                  │   │   │   │   │       │   │
                  └───┴───┴───┴───┴───────┴───┘
                              │
                    7 out of 9 votes
                  (3×7=21 >= 2×9=18) ✓
                              │
                              ▼
                     ┌──────────────┐
                     │ Checkpoint C │
                     │ JUSTIFIED ✓  │
                     └──────────────┘
```

The threshold is computed as: `3 × vote_count >= 2 × validator_count`

> **In ethlambda:** Justification and finalization are processed inside
> `process_attestations()` in `crates/blockchain/state_transition/src/lib.rs`,
> called from `process_block()`. The supermajority check is
> `3 * vote_count >= 2 * validator_count`.

Attestations must also pass validity checks before they count:
- Source checkpoint must already be justified
- Target must not already be justified
- Neither source nor target may have a zero-hash root
- Source slot < Target slot (time flows forward)
- Both checkpoints must reference known blocks
- Target slot must be **justifiable** per the 3SF-mini schedule (see below)

## The Justifiability Schedule

Not every slot can be justified, only slots at specific distances from the last
finalized slot. This is the novel part of 3SF-mini.

A slot is **justifiable** if `delta = slot - finalized_slot` matches any rule:

> **In ethlambda:** The function `slot_is_justifiable_after(slot, finalized_slot)` in
> `crates/blockchain/state_transition/src/lib.rs` implements this check. It uses
> `isqrt()` for perfect square detection and the identity `4n(n+1) + 1 = (2n+1)²`
> for pronic number detection.

```text
    ┌───────────────────────────────────────────────────────┐
    │             JUSTIFIABILITY RULES                      │
    │                                                       │
    │  Rule 1:  delta ≤ 5          (always justifiable)     │
    │                                                       │
    │  Rule 2:  delta = n²         (perfect squares)        │
    │           1, 4, 9, 16, 25, 36, 49, 64, 81, 100, ...   │
    │                                                       │
    │  Rule 3:  delta = n(n+1)     (pronic numbers)         │
    │           2, 6, 12, 20, 30, 42, 56, 72, 90, 110, ...  │
    │                                                       │
    └───────────────────────────────────────────────────────┘
```

Visualizing the first 40 slots after finalization (✓ = justifiable):

```text
    delta: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20
           ✓  ✓  ✓  ✓  ✓  ✓  ✓  ·  ·  ✓  ·  ·  ✓  ·  ·  ·  ✓  ·  ·  ·  ✓
           ╰─ delta ≤ 5 ──╯  2×3      3²       3×4         4²          4×5

    delta: 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40
           ·  ·  ·  ·  ✓  ·  ·  ·  ·  ✓  ·  ·  ·  ·  ·  ✓  ·  ·  ·  ·
                       5²             5×6               6²
```

| delta | Rule | Formula | Gap since previous |
|-------|------|---------|--------------------|
| 0–5   | 1    | ≤ 5     | -  |
| 6     | 3    | 2×3     | 1  |
| 9     | 2    | 3²      | 3  |
| 12    | 3    | 3×4     | 3  |
| 16    | 2    | 4²      | 4  |
| 20    | 3    | 4×5     | 4  |
| 25    | 2    | 5²      | 5  |
| 30    | 3    | 5×6     | 5  |
| 36    | 2    | 6²      | 6  |

**Key property:** Gaps between justifiable slots grow, but never become infinite.
As more time passes since finalization, the network gets progressively wider windows
to accumulate votes. This creates a natural backpressure: if the network is struggling
to reach a two-thirds majority (e.g., due to partitions or validator dropouts), the increasing
gaps give more time for the supermajority to form.

## Finalization

A justified checkpoint becomes **finalized** when it is the source of a justification
whose target is the **next justifiable slot**. In other words, there must be **no
justifiable slots between source and target**: the two must be consecutive entries in
the justifiability schedule.

> **In ethlambda:** The `try_finalize()` function iterates over slots between
> source and target and calls `slot_is_justifiable_after` on each. If any slot
> is justifiable, finalization fails (source and target aren't consecutive).
> The check uses `original_finalized_slot` (the finalized slot at the start of
> block processing), not the current one, since finalization can advance
> mid-processing.

```text
                    FINALIZATION CHECK
                    ──────────────────

    Example 1: Finalization FAILS

    Finalized=10   Source=13 (justified)   Target=16 (justified)

    [ 10 ] · · · [ 13 ]  14   15  [ 16 ]
                          ▲    ▲
                          │    └── delta=5 ≤ 5 → justifiable!
                          └────── delta=4 ≤ 5 → justifiable!

    Justifiable slots exist between S and T → NOT FINALIZED ✗
    (13 and 16 are not consecutive justifiable slots)


    Example 2: Finalization SUCCEEDS

    Finalized=10   Source=16 (justified)   Target=19 (justified)

    [ 10 ] · · · [ 16 ]  17   18  [ 19 ]
                          ▲    ▲
                          │    └── delta=8 → not justifiable ✓
                          └────── delta=7 → not justifiable ✓

    No justifiable slots between S and T → S is FINALIZED ✓
    (16 and 19 are consecutive: delta=6=2×3, then delta=9=3²)
```

The reasoning: if a justifiable slot exists between source and target, validators
could have directed their votes to that intermediate slot instead, potentially on a
different fork. By requiring source and target to be consecutive justifiable slots,
the protocol ensures that no alternative justification path can exist between them.

### Justifiable Slot Backoff

The justifiability schedule acts as a backoff mechanism to increase finalization rate
during periods of asynchrony. By "diluting" the possible targets of a justification
vote (via the `slot_is_justifiable_after` function), the protocol increases the window
during which votes for a given slot can be included, improving the chances of achieving
the required two-thirds majority.

Since finalization requires two consecutively justifiable slots to both be justified,
this backoff isn't immediately reset after finalization occurs; it only lowers over
time when synchrony is restored.

**Example:** Extended asynchrony with gradual recovery.

```
    F=0. Justifiable slots grow sparser as delta increases:

    delta ≤ 5:     0   1   2   3   4   5                  (gap = 1)
    delta 6–20:    6       9       12          16          20   (gap = 3–4)
    delta 20–36:   20          25          30              36   (gap = 5–6)
    ...
    delta ~1000:   900     930     961     992      1024        (gap = 30–32)
                   30²    30×31   31²    31×32      32²
```

**Phase 1: Long asynchrony, slow progress.**

```
    Validators vote, but with many justifiable targets, votes scatter
    and no single slot reaches >=2/3. As gaps widen, votes concentrate.

    Near slot 1000, the 32-slot gap between 992 and 1024 means
    no competing justifiable target exists for 32 slots after 992.
    All votes funnel toward 1024 once it is built.
```

**Phase 2: Slot 992 finalized.**

```
    Slot 992 justified (source = earlier justified slot).
    Slot 1024 justified (source = 992).

    slot:  0  ...  992              1024
           F        J    ·······     J
                    ▲                ▲
                 source ──────────▶ target

    Slots 993–1023: any justifiable from F=0?
      Perfect squares? 31²=961 (before), 32²=1024 (boundary). None.
      Pronic? 31×32=992 (boundary), 32×33=1056 (after). None.
    No justifiable slots between them → slot 992 FINALIZED ✓
```

**Phase 3: Partial reset. Backoff shrinks but doesn't vanish.**

```
    New F=992. Justifiable slots shift:

    slot: 992 993 994 995 996 997 998 ··· 1001 ··· 1004 ··· 1008 ··· 1022 ··· 1028
           F   ✓   ✓   ✓   ✓   ✓   ✓      ✓       ✓       ✓       ✓       ✓
              ╰── delta ≤ 5 ──╯  2×3     3²      3×4     4²      5×6     6²

    Dense slots 993–998 are already in the past!
    Near the current slot (~1024), justifiable slots are ~6 apart:

    ...  1022     1028     1034     1041  ...
         δ=30     δ=36     δ=42     δ=49
         5×6      6²       6×7      7²
         └──6──┘  └──6──┘  └──7──┘

    Gaps shrank from 32 → 6, but didn't reset to 1.
```

**Phase 4: Further finalization closes the gap.**

```
    Justify 1022 and 1028, finalize 1022. New F=1022.

    From F=1022, at slot ~1028 (delta = 6):

    slot:  1022  1023  1024  1025  1026  1027  1028
            F     ✓     ✓     ✓     ✓     ✓     ✓
                  ╰────── delta ≤ 5 ──────╯    2×3

    Gaps are back to 1. Fast finalization resumes.

    Summary of gradual recovery:

    ┌───────────────────┬──────┬───────┬───────┬──────────────┐
    │ Finalization step │  F   │ Head  │ Delta │ Nearby gaps  │
    ├───────────────────┼──────┼───────┼───────┼──────────────┤
    │ Before any        │    0 │ ~1000 │ ~1000 │ 31–32        │
    │ After 1st (992)   │  992 │ ~1024 │   ~32 │ 6–7          │
    │ After 2nd (1022)  │ 1022 │ ~1028 │    ~6 │ 1            │
    └───────────────────┴──────┴───────┴───────┴──────────────┘

    Each finalization step reduces the delta between the finalized
    slot and the chain head, progressively tightening the gaps.
```

When finalization advances, the following cleanup occurs:

- `justified_slots` window shifts forward (old slots pruned)
- `LiveChain` entries for finalized slots are pruned
- Gossip signatures and aggregation proofs for finalized blocks are cleaned up
- Future fork choice runs start from the finalized slot's successor

> **In ethlambda:** The `justified_slots` bitlist uses relative indexing (index 0 =
> `finalized_slot + 1`). When finalization advances, `shift_window()` in
> `crates/blockchain/state_transition/src/justified_slots_ops.rs` drops the
> now-finalized prefix. The attestation target is also walked back to the nearest
> justifiable slot via `slot_is_justifiable_after` in `crates/blockchain/src/store.rs`.

## End-to-End: From Head Selection to Finalization

This section connects [LMD-GHOST fork choice](lmd_ghost.md) with 3SF-mini.
The [quick example above](#quick-example-three-slots-to-finality) showed the happy
path; here we focus on what happens when things go wrong.

### Recap: Attestation Anatomy

Each attestation carries three checkpoints, each determined by a different mechanism:

```text
    ┌────────────────────────────────────────────────────────────────┐
    │                       ATTESTATION                              │
    │                                                                │
    │  head    Newest block the validator sees                       │
    │          ← LMD-GHOST with min_score = 0                        │
    │                                                                │
    │  target  Block the validator wants justified next              │
    │          ← Derived from safe target, walked back to nearest    │
    │            justifiable slot (feeds into 3SF-mini)              │
    │                                                                │
    │  source  Latest justified checkpoint                           │
    │          ← Read from store state                               │
    └────────────────────────────────────────────────────────────────┘
```

The **safe target** is computed by running LMD-GHOST with a two-thirds vote threshold.
Only blocks backed by a supermajority qualify, so the safe target is always at or
behind the head. The attestation **target** is derived by walking back from the head
toward the safe target (max 3 steps), then to the nearest justifiable slot. See
[Safe Target Selection](lmd_ghost.md#safe-target-selection) for details.

> **In ethlambda:** `get_attestation_target()` in `crates/blockchain/src/store.rs`
> implements this walk-back. `JUSTIFICATION_LOOKBACK_SLOTS = 3` provides a liveness
> guarantee: even if the safe target is stuck, the target eventually advances once
> the head moves far enough ahead.

### Lagging Safe Target (Fork with Delayed Convergence)

When validators disagree about the head, the safe target lags behind: no single
branch has two-thirds support. This delays justification until the fork resolves.

```text
    Setup: 9 validators, finalized=100, justified=101
    Safe target threshold: >=6 votes (2/3 of 9)
```

**Slots 102–103: Fork splits votes. No progress.**

```text
                         ┌──[ B102a ]──[ B103a ]     V0–V4 (5)
    [ F=100 ]──[ J=101 ]─┤
                         └──[ B102b ]──[ B103b ]     V5–V8 (4)
```

Neither branch clears two-thirds → safe target stuck at B101. Walk-back from head
always lands on source (B101). **No attestation can advance justification.**

**Slot 104: V7 and V8 switch sides. Fork resolves.**

V7 and V8 receive B102a (delayed by the partition) and switch to the a-branch.

```text
                         ┌──[ B102a ]──[ B103a ]──[ B104a ]     V0–V4, V7, V8 (7)
    [ F=100 ]──[ J=101 ]─┤
                         └──[ B102b ]──[ B103b ]──[ B104b ]     V5–V6  (2)
```

B102a subtree now has 7 votes >= 6 → **safe target = B102a**. Walk-back from B104a
lands on B102a (2 steps). Slot 102 is justifiable (delta=2 ≤ 5).

```text
    source=101 ──▶ target=102    7/9 votes → 3×7=21 >= 2×9=18 → JUSTIFIED ✓
    Finalization: no slots between 101 and 102 → 101 FINALIZED ✓
```

After slot 104: **finalized=101, justified=102.**

**Slots 105–106: Full convergence and recovery.**

All 9 validators on the a-branch. Slot 105: target=B104a → **B104a JUSTIFIED**.
But finalization fails: slot 103 (between source=102 and target=104) is justifiable
but was never justified (lost in the fork).

Slot 106: target=B105a → **B105a JUSTIFIED**. No justifiable slots between 104 and
105 → **104 FINALIZED**. Finalization jumped from 101 to 104, skipping 102 and 103.

```text
    FORK WITH DELAYED CONVERGENCE
    ═════════════════════════════

    Slot:     100   101   102   103   104   105   106
    Status:    F     J     ·     ·     ·     ·     ·
                                fork ──────┤
                                          resolves
    Head:      ·    B101  B102a B103a B104a B105a B106a
    Safe:      ·    B100  B101  B101  B102a B104a B105a
                          stuck ─────┘  ▲
                                        │
                           V7+V8 switch, safe target unsticks

    Justified:  ·    101   ─     ─    102   104   105
    Finalized:  ·     ·    ─     ─    101   ─     104
                                                   ▲
                              finalization jumps ──┘
                               (102,103 skipped; 103 was never justified)
```

## Comparison with Casper FFG

Both 3SF-mini and Casper FFG are finality gadgets built on the same foundation:
supermajority links between checkpoints. They differ fundamentally in their unit of
time and what that implies for validator participation. For a thorough treatment of
Casper FFG as used in Ethereum, see the
[eth2book chapter on Casper FFG](https://eth2book.info/capella/part2/consensus/casper_ffg/).

### Slots vs Epochs: The Core Architectural Split

**3SF-mini: Every Validator, Every Slot**

In 3SF-mini, **all validators vote in every slot**. A checkpoint can be justified at
any slot (subject to the justifiability schedule), and finalization can happen as soon
as two consecutive justifiable slots are both justified.

```text
    3SF-mini  (4-second slots, 4 validators)

    Slot 100        Slot 101        Slot 102        Slot 103
    ┌───────┐       ┌───────┐       ┌───────┐       ┌───────┐
    │V0 V1  │       │V0 V1  │       │V0 V1  │       │V0 V1  │
    │V2 V3  │       │V2 V3  │       │V2 V3  │       │V2 V3  │
    └───┬───┘       └───┬───┘       └───┬───┘       └───┬───┘
        │               │               │               │
     4 votes         4 votes         4 votes         4 votes
     per slot        per slot        per slot        per slot

    Every validator participates in every slot.
    >=2/3 threshold checked per-slot → can justify any slot.
```

This is simple and fast, but it means every validator must produce and verify a vote
every slot. The total message load scales as `validators × slots`.

**Casper FFG: Validators Split Across an Epoch**

Ethereum's beacon chain has ~1,000,000 active validators. Having all of them vote every
12-second slot would be unmanageable. Instead, Casper FFG groups 32 slots into an
**epoch**, and splits the validator set across the slots within it:

```text
    Casper FFG  (12-second slots, 32 per epoch, ~900k validators)

    Epoch N
    ┌─────────────────────────────────────────────────────────────┐
    │ Slot 0     Slot 1     Slot 2    ...    Slot 30    Slot 31   │
    │ ┌──────┐   ┌──────┐   ┌──────┐        ┌──────┐   ┌──────┐   │
    │ │~28125│   │~28125│   │~28125│  ...   │~28125│   │~28125│   │
    │ │valids│   │valids│   │valids│        │valids│   │valids│   │
    │ └──┬───┘   └──┬───┘   └──┬───┘        └──┬───┘   └──┬───┘   │
    │    │           │           │               │           │    │
    └────┼───────────┼───────────┼───────────────┼───────────┼────┘
         └───────────┴───────────┴───┬───────────┴───────────┘
                                     │
                            All ~900k votes
                          collected over 32 slots
                                     │
                                     ▼
                              Epoch checkpoint
                              (first slot of epoch)

    Each validator attests exactly ONCE per epoch.
    The full >=2/3 tally is only meaningful at epoch boundaries.
```

Each validator is shuffled into a **committee** assigned to one specific slot. Within
that slot, the committee may be further split (up to 64 sub-committees) for parallel
aggregation. The result: each validator only attests once per epoch, and the network
processes ~28,000 attestations per slot instead of ~900,000.

**The trade-off:**

| | **3SF-mini** | **Casper FFG** |
|---|---|---|
| **Who votes when** | All validators, every slot | Each validator once per epoch (in its assigned slot) |
| **Messages per slot** | `N` (all validators) | `N / 32` (one committee) |
| **Supermajority known after** | 1 slot (all votes in) | 1 epoch (need all 32 committees) |
| **Fastest finalization** | 2 slots = **8 seconds** | 2 epochs = **~12.8 minutes** |
| **Practical validator limit** | Hundreds–thousands | Millions |

Epochs exist because of a scalability constraint, not a protocol-theory preference. If
you could process a million votes per slot, Casper FFG wouldn't need epochs at all. 3SF-mini
sidesteps this by targeting a smaller validator set, which lets it operate at slot granularity.

### Finalization Logic

Both require a chain of justified checkpoints, but the rules differ in what they check.

**Casper FFG** uses **k-finality**. The original rule (k=1) requires a direct supermajority
link from a checkpoint to its immediate successor: justify epoch N+1 with source=N, and N
is finalized. Ethereum generalizes this to **k=2**, which handles the case where the network
falls slightly behind:

```text
    Casper FFG — 1-finality (ideal case):

    Epoch N       Epoch N+1
    ┌─────┐       ┌─────┐
    │ CP  │══════▶│ CP  │       Supermajority link N → N+1
    │ J ✓ │       │     │
    └─────┘       └─────┘

    Processing this link:
      1. Epoch N+1 becomes JUSTIFIED (target of a supermajority link)
      2. Epoch N becomes FINALIZED (direct successor justified)


    Casper FFG — 2-finality (one epoch behind):

    Epoch N       Epoch N+1     Epoch N+2
    ┌─────┐       ┌─────┐       ┌─────┐
    │ CP  │       │ CP  │       │ CP  │
    │ J ✓ │       │ J ✓ │       │     │
    └─────┘       └─────┘       └─────┘
       │                           │
       └══════ supermajority ══════┘
               link N → N+2

    The direct link N→N+1 didn't form in time.
    Instead, a link forms from N→N+2. Processing this link:
      1. Epoch N+2 becomes JUSTIFIED (target of a supermajority link)
      2. Epoch N becomes FINALIZED (all intermediates are justified)
```

The 2-finality rule is a recovery mechanism: even if the network missed the ideal one-epoch
finalization window, it gets a second chance. Ethereum tracks the justification status of the
last 4 epoch boundaries to detect both cases. In practice, most finalization happens via
1-finality during normal operation; 2-finality kicks in during brief network hiccups.

**3SF-mini** takes a different approach entirely:

```text
    Slot S        Slot T
    ┌─────┐       ┌─────┐
    │ CP  │──────▶│ CP  │       No justifiable slots exist
    │ J ✓ │       │ J ✓ │       between S and T
    └─────┘       └─────┘
    ∴ Slot S is FINALIZED

    Rule: Finalized when NO intermediate checkpoints could exist
```

Instead of checking that intermediate checkpoints *are justified*, 3SF-mini checks that no
intermediate checkpoints *could exist at all*. This is a stronger guarantee: validators'
votes between source and target could only have gone to the target, since there's nowhere else
to direct them. This structural property is also why 3SF-mini doesn't need Casper's
surround-vote slashing condition.

Casper's k-finality is essentially a tolerance parameter: "how many epochs behind can we be
and still finalize?" Ethereum chose k=2, meaning it tolerates one missed epoch. 3SF-mini
doesn't need this concept because the justifiability schedule itself adapts. Instead of
tolerating missed windows, it makes the windows wider when the network is struggling.

### Adaptive Backoff (unique to 3SF-mini)

Casper FFG has a fixed checkpoint every epoch, regardless of network conditions. 3SF-mini's
justifiability schedule adapts: gaps between justifiable slots grow under prolonged asynchrony
(via the perfect square and pronic number rules), creating natural vote concentration when the
network is struggling to reach a two-thirds majority. Casper FFG has no equivalent; its epoch spacing is the
same whether the network is healthy or partitioned. See
[Justifiable Slot Backoff](#justifiable-slot-backoff) for a detailed walkthrough.
