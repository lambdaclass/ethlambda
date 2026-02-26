# 3SF-mini: Justification & Finalization

ethlambda uses **3SF-mini** (Three-Stage Finality, minimal version) for justification
and finalization. Unlike the Ethereum Beacon Chain's epoch-based Casper FFG, 3SF-mini
operates at the **slot level**: any slot can be justified, not just epoch boundaries.

## Concepts

| Term | Meaning |
|------|---------|
| **Justified** | A checkpoint backed by ≥2/3 validator votes |
| **Finalized** | A checkpoint that can never be reverted |
| **Source** | The latest justified checkpoint (vote origin) |
| **Target** | The checkpoint being voted for (vote destination) |
| **Justifiable** | A slot that *could* become justified (per the 3SF-mini schedule) |

## Justification via Supermajority

A checkpoint becomes **justified** when ≥2/3 of validators attest to it as a target:

```text
                   JUSTIFICATION
                   ─────────────

    Validators:  V0  V1  V2  V3  V4  V5  V6  V7  V8
                  │   │   │   │   │       │   │
                  └───┴───┴───┴───┴───────┴───┘
                              │
                    7 out of 9 votes
                  (3×7=21 ≥ 2×9=18)  ✓
                              │
                              ▼
                     ┌──────────────┐
                     │ Checkpoint C │
                     │ JUSTIFIED ✓  │
                     └──────────────┘
```

The threshold is computed as: `3 × vote_count ≥ 2 × validator_count`

> **In ethlambda:** Justification and finalization are processed inside
> `process_attestations()` in `crates/blockchain/state_transition/src/lib.rs`,
> called from `process_block()`. The supermajority check is
> `3 * vote_count >= 2 * validator_count`.

Attestations must also pass validity checks before they count:
- Source checkpoint must already be justified
- Target must not already be justified
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
           ╰─ delta ≤ 5 ──╯  2×3   3²    3×4            4²       4×5

    delta: 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40
           ·  ·  ·  ·  ✓  ·  ·  ·  ·  ✓  ·  ·  ·  ·  ·  ✓  ·  ·  ·  ·
                       5²             5×6                6²=6×6
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
| 36    | 2+3  | 6²=6×6  | 6  |

**Key property:** Gaps between justifiable slots grow, but never become infinite.
As more time passes since finalization, the network gets progressively wider windows
to accumulate votes. This creates a natural backpressure: if the network is struggling
to reach 2/3 consensus (e.g., due to partitions or validator dropouts), the increasing
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
the required 2/3 majority.

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
    and no single slot reaches 2/3. As gaps widen, votes concentrate.

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

## Worked Example: Justification and Finalization

```text
    Setup: 4 validators (V0–V3), finalized at slot 100

    Slot 100: [FINALIZED] ← anchor
    Slot 101: Block proposed, justifiable? delta=1 ≤ 5 → YES
    Slot 102: Block proposed, justifiable? delta=2 ≤ 5 → YES
```

**Round 1: Justify slot 101.**

Validators attest with `source=100, target=101`. 3 of 4 vote:

```text
    source          target
    (slot 100)      (slot 101)
       │               │
       ▼               ▼
    [  100  ]─────▶[  101  ]    3/4 votes → 3×3=9 ≥ 2×4=8 → JUSTIFIED ✓
```

**Round 2: Justify slot 102 and finalize slot 101.**

Validators attest with `source=101, target=102`:

```text
    source          target
    (slot 101)      (slot 102)
       │               │
       ▼               ▼
    [  101  ]─────▶[  102  ]    3/4 votes → JUSTIFIED ✓
       │
       └── Finalization check:
           Slots between 101 and 102 (exclusive): NONE
           No justifiable slots between them → slot 101 FINALIZED ✓
```

**After finalization of slot 101:**

- `justified_slots` window shifts forward (old slots pruned)
- `LiveChain` entries for slots ≤101 are pruned
- Gossip signatures and aggregation proofs for finalized blocks are cleaned up
- Future fork choice runs start from slot 101's successor, never looking further back

> **In ethlambda:** The `justified_slots` bitlist uses relative indexing (index 0 =
> `finalized_slot + 1`). When finalization advances, `shift_window()` in
> `crates/blockchain/state_transition/src/justified_slots_ops.rs` drops the
> now-finalized prefix. The attestation target is also walked back to the nearest
> justifiable slot via `slot_is_justifiable_after` in `crates/blockchain/src/store.rs`.

## End-to-End: From Head Selection to Finalization

The sections above cover justification and finalization in isolation. This section
shows how the full consensus cycle works from start to finish, connecting
[LMD-GHOST fork choice](ghost-fork-choice.md) with 3SF-mini.

### Recap: Attestation Anatomy

Each attestation carries three checkpoints, each determined by a different mechanism:

```text
    ┌────────────────────────────────────────────────────────────────┐
    │                       ATTESTATION                              │
    │                                                                │
    │  head    Newest block the validator sees                       │
    │          ← LMD-GHOST with min_score = 0                       │
    │                                                                │
    │  target  Block the validator wants justified next              │
    │          ← Derived from safe target, walked back to nearest    │
    │            justifiable slot (feeds into 3SF-mini)              │
    │                                                                │
    │  source  Latest justified checkpoint                           │
    │          ← Read from store state                               │
    └────────────────────────────────────────────────────────────────┘
```

The **safe target** is computed by running LMD-GHOST with a >2/3 vote threshold,
where V is the total number of validators. Only blocks backed by a supermajority
qualify, so the safe target is always at or behind the head. See
[Safe Target Selection](ghost-fork-choice.md#safe-target-selection) for details.

The attestation **target** is then derived from the safe target via a walk-back:

```text
    ATTESTATION TARGET DERIVATION
    ─────────────────────────────

    Start at head
        │
        ▼
    Walk back toward safe target (max 3 steps)
        │
        ▼
    Walk back to nearest justifiable slot
        │
        ▼
    Final target
```

> **In ethlambda:** `get_attestation_target()` in `crates/blockchain/src/store.rs`
> implements this walk-back. The max walk-back distance is controlled by
> `JUSTIFICATION_LOOKBACK_SLOTS = 3`, which provides a liveness guarantee: even if
> the safe target is stuck, the target eventually advances once the head moves far
> enough ahead. An additional clamp step ensures the result is never behind the
> latest justified checkpoint (source), guarding against races where justification
> advances between safe target updates.

### Example 1: Full Synchrony (Safe Target One Slot Behind Head)

When all validators are online and see the same chain, the safe target tracks
one slot behind the head: the previous block has had a full slot for attestations
to accumulate, giving it >2/3 support. Finalization proceeds at the fastest
possible rate: one finalization per slot.

```text
    Setup: 9 validators, finalized at slot 100, justified at slot 101
    All validators online, all see the same chain
```

**Slot 102: Block B102 proposed.**

```text
    Chain:  ─[ F=100 ]──[ J=101 ]──[ B102 ]──
                                       ▲
                                      head
```

| Step | What happens |
|------|-------------|
| Head selection | LMD-GHOST (min_score=0): all 9 validators' latest heads point at B102 → **Head = B102** |
| Safe target | LMD-GHOST (min_score=7): B101 has accumulated 9 votes > 6 over the previous slot → **Safe target = B101** |
| Attestation target | Walk back from B102 toward B101: one step → B101. But B101 = source (already justified). Clamp → **Target = B101** |

Since target = source, these attestations cannot advance justification. This is
normal. Validators still broadcast the attestation because its **head** field
contributes to fork choice, even when the target can't make progress.

But B102 also carries attestations **from the previous slot** (slot 101's
validators targeted B102 before it was the head). Those attestations have
`source=J(101), target=B102`:

```text
    Justification of B102 (from slot 101 attestations included in block B102):

    source          target
    (slot 101)      (slot 102)
       │               │
       ▼               ▼
    [ J=101 ]─────▶[ B102 ]    7/9 votes → 3×7=21 > 2×9=18 → JUSTIFIED ✓
       │
       └── Finalization check:
           Slots between 101 and 102 (exclusive): NONE
           No justifiable slots between them → J(101) FINALIZED ✓
```

After slot 102: **finalized=101, justified=102.**

**Slot 103: Block B103 proposed.**

```text
    Chain:  ─[ F=101 ]──[ J=102 ]──[ B103 ]──
                                       ▲
                                      head
```

| Step | Result |
|------|--------|
| Head | B103 (9 votes, unanimous) |
| Safe target | B102 (9 votes from slot 102 attestations > 6) |
| Attestation target | Walk back from B103 to B102. Slot 102 justifiable (delta=102−101=1 ≤ 5). But B102 is already justified = source. Clamp → Target = B102 |

Again, the current slot's attestations can't advance justification. But block B103
carries attestations from slot 102 targeting B103 (`source=J(102), target=B103`):

```text
    7/9 votes for B103 → JUSTIFIED ✓

    Finalization check (source=102, target=103, original_finalized=101):
        Slots between 102 and 103 (exclusive): NONE
        → J(102) FINALIZED ✓
```

After slot 103: **finalized=102, justified=103.**

```text
    FULL SYNCHRONY TIMELINE
    ═══════════════════════

    Slot:      100     101      102      103      104
    Block:     B100    B101     B102     B103     B104
                F      J→F      J→F      J→F      J
                │       │        │        │        │
    Justified:  ·      by B101  by B102  by B103  by B104
    Finalized:  ·       ·       F=101    F=102    F=103
                                 ▲        ▲        ▲
                                 │        │        │
                            Each block justifies the current slot
                            AND finalizes the previous one.

    Safe:      ·       B100     B101     B102     B103
                                 │        │        │
                         always one slot behind the head
```

**Key property:** In full synchrony, the safe target tracks exactly one slot behind
the head. Justification comes from the *previous* slot's attestations (carried
in the current block), and finalization follows immediately because consecutive
slots are always consecutive justifiable slots when delta ≤ 5. This gives the
fastest possible finalization rate: **one finalization per slot**.

### Example 2: Lagging Safe Target (Fork with Delayed Convergence)

When validators disagree about the head (e.g., due to a fork or network partition),
the safe target can lag behind the head. No single branch has >2/3 support, so
the safe target stays stuck at the last point where everyone agrees. This delays
justification until the fork resolves.

```text
    Setup: 9 validators, finalized at slot 100, justified at slot 101
    Threshold for safe target: >2/3 of 9 → need >6 → 7 votes
```

**Slot 102: Fork! Two blocks proposed at the same slot.**

```text
                         ┌──[ B102a ]     V0–V4 (5 validators)
    [ F=100 ]──[ J=101 ]─┤
                         └──[ B102b ]     V5–V8 (4 validators)
```

| Step | Result |
|------|--------|
| Head | B102a (5 votes > 4 votes for B102b) |
| Safe target | B102a has 5 < 7, B102b has 4 < 7. Neither clears >2/3 → **Safe target = B101** (stuck at justified checkpoint) |
| Attestation target | Walk back from B102a to B101 (1 step). B101 = source → **Target = source. No progress.** |

**Slot 103: Fork persists.**

```text
                         ┌──[ B102a ]──[ B103a ]     V0–V4 (5)
    [ F=100 ]──[ J=101 ]─┤
                         └──[ B102b ]──[ B103b ]     V5–V8 (4)
```

Head = B103a. Safe target still B101. Walk-back from B103a to B101 takes 2 steps.
Target = source again. **Still no justification progress.**

**Slot 104: V7 and V8 switch sides. Fork resolves.**

V7 and V8 receive B102a (delayed by the partition) and switch to the a-branch.
Now the a-branch has 7 validators (V0–V4 + V7 + V8).

```text
                         ┌──[ B102a ]──[ B103a ]──[ B104a ]     V0–V4, V7, V8 (7)
    [ F=100 ]──[ J=101 ]─┤
                         └──[ B102b ]──[ B103b ]──[ B104b ]     V5–V6  (2)
```

| Step | Result |
|------|--------|
| Head | B104a (7 votes subtree > 2 votes) |
| Safe target | B102a subtree now has 7 votes > 6 → included. But B103a only has 5 (V7/V8 attested to B102a, not B103a) → excluded. **Safe target = B102a** |
| Attestation target | Walk back from B104a toward B102a: 2 steps (B104a → B103a → B102a). Slot 102 justifiable (delta=2 ≤ 5). 102 > source 101 ✓ → **Target = B102a** |

Now attestations can advance justification:

```text
    source          target
    (slot 101)      (slot 102)
       │               │
       ▼               ▼
    [ J=101 ]─────▶[ B102a ]    7/9 votes → 3×7=21 > 2×9=18 → JUSTIFIED ✓
       │
       └── Finalization check:
           Slots between 101 and 102 (exclusive): NONE
           → J(101) FINALIZED ✓
```

After slot 104: **finalized=101, justified=102.**

**Slot 105: Full convergence. V5–V6 rejoin the a-branch.**

```text
    [ F=101 ]──[ J=102a ]──[ B103a ]──[ B104a ]──[ B105a ]     All 9 validators
```

| Step | Result |
|------|--------|
| Head | B105a (unanimous) |
| Safe target | B104a (9 votes > 6) |
| Attestation target | Walk from B105a to B104a (1 step). Slot 104 justifiable (delta=104−101=3 ≤ 5). 104 > source 102 ✓ → **Target = B104a** |

Attestations targeting B104a reach supermajority → **B104a JUSTIFIED ✓**

Finalization check (source=102, target=104, original_finalized=101):

```text
    Slots between 102 and 104 (exclusive): [103]
    Is slot 103 justifiable after F=101?  delta = 103−101 = 2 ≤ 5 → YES

    Justifiable slot exists between source and target → FINALIZATION FAILS ✗
```

Slot 103 is justifiable but was **never justified** (it was lost in the fork).
This blocks finalization because the protocol can't be sure an alternative
justification path through slot 103 doesn't exist.

**Slot 106: Catching up.**

Head = B106a. Safe target = B105a. Target walks back to B105a (1 step).
Slot 105 justifiable (delta=4 ≤ 5). 105 > source 104 ✓.

Attestations: `{source=J(104), target=B105a}` → **B105a JUSTIFIED ✓**

Finalization check (source=104, target=105, original_finalized=101):

```text
    Slots between 104 and 105 (exclusive): NONE
    → J(104a) FINALIZED ✓
```

After slot 106: **finalized=104, justified=105.**

Finalization jumped from 101 to 104, skipping slots 102 and 103. This is safe:
finalization only guarantees that finalized blocks are permanent, not that every
intermediate slot was individually finalized.

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

    Compared to full synchrony:
    ┌──────────────┬────────────────┬─────────────────────┐
    │              │ Full synchrony │ Fork (this example) │
    ├──────────────┼────────────────┼─────────────────────┤
    │ Finalized by │                │                     │
    │   slot 104   │ 103            │ 101                 │
    │   slot 106   │ 105            │ 104                 │
    │ Slots lost   │ 0              │ ~2 slots behind     │
    └──────────────┴────────────────┴─────────────────────┘
```

**Key observations:**

1. **Safe target is the bottleneck.** While stuck at B101, no attestation could
   advance justification because the walk-back always landed on source. Justification
   only resumed once enough validators converged to push the safe target forward.

2. **Forks create justification gaps.** Slot 103 was justifiable but never justified
   (the fork split votes). This gap prevented finalization of slot 102, even after
   it was justified. The protocol had to "skip over" the gap by finding two later
   consecutive justifiable slots (104 and 105) that were both justified.

3. **Recovery is quick.** Once the fork resolved and safe target advanced,
   justification and finalization caught up within two slots. The protocol doesn't
   need to re-justify missed slots; it just needs any two consecutive justifiable
   slots to both be justified.
