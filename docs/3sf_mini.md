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

```text
    ┌─────────────────────────────────────────────────────────┐
    │             JUSTIFIABILITY RULES                        │
    │                                                         │
    │  Rule 1:  delta ≤ 5          (first 5 always OK)        │
    │                                                         │
    │  Rule 2:  delta = n²         (perfect squares)          │
    │           1, 4, 9, 16, 25, 36, 49, 64, 81, 100, ...    │
    │                                                         │
    │  Rule 3:  delta = n(n+1)     (pronic numbers)           │
    │           2, 6, 12, 20, 30, 42, 56, 72, 90, 110, ...   │
    │                                                         │
    └─────────────────────────────────────────────────────────┘
```

Visualizing the first 40 slots after finalization (✓ = justifiable):

```text
    delta: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20
           ✓  ✓  ✓  ✓  ✓  ✓  ✓  ·  ·  ✓  ·  ·  ✓  ·  ·  ·  ✓  ·  ·  ·  ✓
           ╰──────── R1 ────────╯  R3     R2     R3              R2        R3

    delta: 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40
           ·  ·  ·  ·  ✓  ·  ·  ·  ·  ✓  ·  ·  ·  ·  ·  ✓  ·  ·  ·  ·
                       R2              R3                 R2+R3
```

| delta | Rule | Formula | Gap since previous |
|-------|------|---------|--------------------|
| 0–5   | 1    | ≤ 5     | —  |
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

### Justifiable Slot Backoff

The justifiability schedule acts as a backoff mechanism to increase finalization rate
during periods of asynchrony. By "diluting" the possible targets of a justification
vote (via the `slot_is_justifiable_after` function), the protocol increases the window
during which votes for a given slot can be included, improving the chances of achieving
the required 2/3 majority.

Since two consecutive justified **justifiable** slots are needed to finalize, this
backoff isn't immediately reset after finalization occurs; it only lowers over time
when synchrony is restored.

**Example:**

```
    Finalized slot = 0.  Justifiable slots (✓):

    slot:  0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20
           F  ✓  ✓  ✓  ✓  ✓  ✓  ·  ·  ✓  ·  ·  ✓  ·  ·  ·  ✓  ·  ·  ·  ✓
```

**Phase 1: Slot 1 justified, but no progress for a while.**

```
    slot:  0  1  2  3  4  5  6  7  8  9  ... 15
           F  J  ·  ·  ·  ·  ·  ·  ·  ·      ·
              ▲
              └── Justified (source=0, 2/3 votes)

    Slots 2–15: votes arrive with differing targets,
    no single slot accumulates 2/3 → no new justification.
```

**Phase 2: Backoff helps. Slot 16 justified (gap = 4 slots since last justifiable).**

```
    slot:  0  1  ...  12  13  14  15  16  17  18  19
           F  J        ✓   ·   ·   ·   ✓   ·   ·   ·
                                        ▲
                            ┌───────────┘
                            Justified (source=1)

    Slot 16 is built. Validators begin voting for it (source=1, target=16).
    During slots 17–19 there is no new justifiable target to compete with
    slot 16, so all votes funnel toward it, giving 2/3 enough time to
    converge on a single target.

    Can we finalize slot 1?
      Justifiable slots between 1 and 16: 2, 3, 4, 5, 6, 9, 12
      These are unjustified gaps → slot 1 NOT finalized yet.
```

**Phase 3: Slot 20 justified, slot 16 finalized.**

```
    slot:  0  1  ...  16  17  18  19  20
           F  J        J   ·   ·   ·   J
                       ▲               ▲
                       source ────────▶ target

    Justified (source=16, target=20).

    Can we finalize slot 16?
      Slots between 16 and 20: 17, 18, 19
      Justifiable? 17: delta=17 → ✗  18: delta=18 → ✗  19: delta=19 → ✗
      But wait: are 16 and 20 consecutive *justifiable* slots?
        Next justifiable after 16: 20 (delta=20 = 4×5 ✓)
      Yes! No justifiable gaps → slot 16 FINALIZED ✓
      (and all slots before it)
```

**After finalization of slot 16, backoff resets.**

```
    New finalized slot = 16.  Justifiable slots shift:

    slot:  16  17  18  19  20  21  22  23  24  25  26
            F   ✓   ✓   ✓   ✓   ✓   ✓   ·   ·   ✓   ·
                ╰──────── delta ≤ 5 ────────╯

    The gaps shrink back to 1 slot apart; fast finalization
    resumes as long as the network stays synchronous.
```

## Finalization

A justified checkpoint becomes **finalized** when there are **no unjustifiable gaps**
between its source and target. The intuition: if every slot between source and target
*could have been* justified, then the chain of justifications is unbroken, and the
source is safe to finalize.

```text
                    FINALIZATION CHECK
                    ──────────────────

    Finalized    Source (justified)    Target (justified)
        │              │                     │
        ▼              ▼                     ▼
    ┌───┬───┬───┬──────┬───┬───┬───┬───┬────┐
    │ F │   │   │  S   │   │   │   │   │ T  │
    └───┴───┴───┴──────┴───┴───┴───┴───┴────┘
    slot                ◄─── check ───►
    10   11  12  13     14  15  16  17  18

    For each slot between S and T (exclusive: 14, 15, 16, 17):
      Is it justifiable after F (slot 10)?
        14: delta=4 ≤ 5  → justifiable ✓
        15: delta=5 ≤ 5  → justifiable ✓
        16: delta=6 = 2×3 → justifiable ✓
        17: delta=7       → NOT justifiable ✗  ← gap found!

    Result: S is NOT finalized (unjustifiable gap at slot 17)
```

The logic behind this: if slot 17 *cannot* be justified, then an attacker could
potentially create an alternative justified chain that diverges at slot 17, undermining
the source's finality. Only when every intermediate slot *could have* been justified
is the chain of justifications considered airtight.

```text
    Alternative scenario (no gaps):

    Source: slot 13 (delta from F=10: 3)
    Target: slot 16 (delta from F=10: 6)

    Check slots 14, 15:
      14: delta=4 ≤ 5 → justifiable ✓
      15: delta=5 ≤ 5 → justifiable ✓

    No unjustifiable gaps → S is FINALIZED ✓
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
           No unjustifiable gaps → slot 101 FINALIZED ✓
```

**After finalization of slot 101:**
- `justified_slots` window shifts forward (old slots pruned)
- LiveChain entries for slots ≤101 are pruned
- Gossip signatures and aggregation proofs for finalized blocks are cleaned up
- Future fork choice runs start from slot 101's successor, never looking further back
