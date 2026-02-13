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
