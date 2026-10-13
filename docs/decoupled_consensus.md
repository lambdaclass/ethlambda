# Decoupled consensus: Goldilocks

ethlambda implements **Goldilocks**: Goldfish with locks as the available
chain (AC), composed with the height-based finality gadget (FG) of the
decoupled consensus protocol formalized in
[`fradamt/verified-consensus`](https://github.com/fradamt/verified-consensus).
It replaces LMD-GHOST + Casper FFG on the beacon chain and LMD-GHOST +
3SF-mini on the lean chain, as an opt-in mode of each.

Two independent voting processes:

```text
finalized  ⪯  confirmed (locked)  ⪯  head
   (FG)            (AC)              (AC)
```

| Process | Who votes | When | What it decides |
|---|---|---|---|
| Goldfish (AC) | slot `s`'s committee `𝒦_s` | `t_s + Δ` | the head; the confirmation update at `t_s + 6Δ` forms locks |
| Locks (AC) | nobody: derived from the committee votes | every confirmation update and fork-choice run | the anchor every walk starts from, and the confirmed output |
| Finality gadget | every validator, only when it has something new to say | `t_s + 2Δ` | heights, justifications and finalizations through each block's chain state σ |

A slot is `4Δ`: proposal at `t_s`, vote at `t_s + Δ`, support cutoff and
attestation instant at `t_s + 2Δ`, view freeze at `t_s + 3Δ`.

Compared with the previous design (Goldfish + the graded stabilization
gadget, one combined attestation per round): asynchrony resilience after one
slot instead of one round, attestations only from the FG and only per height,
and a fork choice that never reads network attestations.

## The available chain

### Locks give the anchor, votes give the walk

Every fork-choice run (proposal, vote, confirmation, the reported head) starts
at the **anchor**: the deepest live lock inside the frame the FG imposes (see
below), or the frame's root when no lock is live there. From the anchor, the
Goldfish walk descends by the slot's votes, as before.

### Two ways to lock, two ways to unlock

| Rule | When | Effect |
|---|---|---|
| Fast lock | the confirmation update of slot `s` sees at least `n/2` of the whole committee `𝒦_s` supporting `B` | lock the deepest such `B` of the frame until `s + k` |
| Slow lock | the confirmation updates of `k` consecutive slots each confirmed a block | lock their deepest common ancestor until `s + k` |
| Fast unlock | before a fork-choice run, at least `n/2` of the committee oppose the lock | the lock steps back to its deepest ancestor with fewer than `n/2` opponents, keeping its deadline |
| Expiry | `k` slots pass without renewal | the lock is dropped |

`n` is the committee size, not the participation. A fast lock's `n/2`
supporters are enough to unlock any lock that conflicts with it, which is
what keeps live locks compatible after GST and makes a fast lock a safe FG
target.

The **confirmed** output is the anchor of the head's walk when it is a live
lock, else `Σ.F`, so `F ⪯ confirmed ⪯ head` holds by construction. The beacon
execution layer hears it as `safe`.

### The confirmation update (slot `s`, at `t_s + 6Δ`)

It reads the slot's votes with the time-shifted quorum: support from votes
resolved before `t_s + 2Δ` whose voter cast nothing else before `t_s + 6Δ`,
participation from every vote received before `t_s + 6Δ`. Then, in order:

1. fast unlock over the late votes;
2. fast lock: the deepest frame block with `≥ n/2` support becomes
   `fg_confirmed` and is locked (none: `fg_confirmed` is empty this slot);
3. the Goldfish confirmation: the majority walk from the anchor, confirming
   its end block when it holds a majority of the participants;
4. slow lock, when this is the `k`-th consecutive slot with a confirmation.

## The finality gadget

### Attestations are pure finality votes

`(validator, h, T, timeout, h_f, T_f)`: a height pair and a finality pair,
either of which may be absent. No round, no safe block. The chain state σ and
its transition are the FG's, unchanged:

| On chain | Effect |
|---|---|
| 2/3 target votes for `(h, T)` | justify `T` (unless `h` is nonjustifiable), advance the height |
| 2/3 targets + timeouts, `δ_t` slots after the height's entry | advance the height, no justification |
| 2/3 finality votes for the pending `(h_j, J)` | finalize `J` |

### What the FG reads from the AC

At `t_s + 2Δ`, right after the confirmation update of `s − 1`:

- **height pair** from the state of `fg_confirmed`: `(h, T_h)`, a timeout when
  the validator's record already targeted another entry at `h` or the height
  is nonjustifiable;
- **finality pair** from the state of the head: the latest justification on
  the head chain.

The record Λ (`ethlambda_decoupled::Record`) decides the pairs exactly as
before (E1/E2 safety), and a validator **attests only when one of the pairs
is new** (`Record::preview`). A slot without a fast lock leaves the height
pair out without retracting the last one. On a chain without height progress
nothing is new, so the attestation traffic of a stalled finality dies down by
itself; a reorg to another entry at the same height is new, and becomes a
timeout naming that entry.

Network attestations feed only the pool proposals draw from. A proposal
carries the pooled attestations that set a bit its parent's state lacks.

### What the AC reads from the FG: the frame

```text
J at h_max − 1?   a block at h_max not on J?   root   height floor
no                —                            F      h_max − 1
yes               no                           J      h_max − 1
yes               yes (a contest)              F      h_max
```

The filtered tree is the descendants of the root whose subtree reaches the
floor. A justification revealed late pulls the root to it; a contest sends it
back to `F` and raises the floor, so branches that still need votes at
`h_max − 1` drop out and finality votes for `J` block nothing. A contest never
goes away: the `(h_max, J)` it spent stays spent, even if finality later
prunes the contesting branch. Each height changes the frame at most twice
before it rises.

## Code map

```text
crates/blockchain/decoupled/       ethlambda-decoupled: the protocol, chain-agnostic
  src/params.rs                    k, K, D, δ_t; the Δ grid
  src/types.rs                     BlockInput, Electorate, Tick (+ re-exported payloads)
  src/chain_state.rs               σ: state_transition, process_attestation, height events
  src/store.rs                     Σ: on_tick, on_block, on_goldfish_vote, on_attestation,
                                   update_finality, the frame (J/contest rule), accessors
  src/locks.rs                     CommitteeSizes, stances, fast unlock, lock bookkeeping
  src/fork_choice.rs               filtered tree, goldfish score, the walk from the anchor,
                                   head, confirmed
  src/duties.rs                    proposal, goldfish_vote_head, update_confirmation (locks),
                                   attestation_input
  src/validator_client.rs          Λ: finality_pair, height_pair, preview/create, E1/E2
  src/simulation.rs                in-process network tests
crates/common/types/src/decoupled.rs        payloads both chains embed (votes, attestation
                                            data, σ), DecoupledStatus
crates/common/types/src/lean_decoupled.rs   lean wire containers and XMSS epoch grid
crates/blockchain/src/decoupled_lean.rs     lean chain actor
crates/common/types/src/beacon/containers/decoupled.rs   the beacon `decoupled` fork
```

## The engine

`ethlambda_decoupled::Store` is the cumulative store Σ. Hosts:

1. call `advance_to(now_tick)` before every handler, where a tick is
   `floor((now − genesis) / Δ)`;
2. run the duties the returned `TickEvents` ask for, in order (propose, vote,
   attest), reading `proposal()`, `goldfish_vote_head()` and
   `attestation_input()`, and feed what they sign back through the handlers;
3. check signatures, committee membership and the proposer schedule before
   calling a handler;
4. declare the committee sizes (`Store::with_committee_sizes`) when the slot
   committee is not every validator.

### Choices and assumptions

The slides specify the mechanisms; these are the details this implementation
fixed where they leave room. Each is a parameter or a local rule.

- **Lock lifetime.** A lock formed by the update of slot `s` anchors every
  run over votes of slots `s ..= s + k − 1`: the updates of `s + 1 ..= s + k − 1`
  and the votes and proposals of slots `s + 2 ..= s + k`. Renewal is forming
  the same lock again (the later deadline wins). `k = 4` by default (the
  slides' example), at least 2.
- **When locks step back.** At `t_s` over the proposer's view of slot `s − 1`
  (the pool), at `t_s + Δ` over the voter's view, and inside each update over
  its late votes. Stepping back more often only drops locks honest votes
  oppose, so the extra runs cannot unlock what honest voters support.
- **Opposition.** A member's stance is the deepest common ancestor of the
  processed heads of its votes in the slot (an equivocator opposes whatever
  its votes disagree on). Votes for unprocessed heads count neither way. A
  lock that would step back to `F` or below is dropped.
- **Fast-lock candidates.** Only blocks of the filtered tree, so a lock and
  the height pair it supplies never come from a branch the FG has ruled out.
- **Slow lock.** The `k` confirmations must be of consecutive slots; the lock
  is their deepest common ancestor.
- **Confirmed output.** The locked anchor of the head's walk, or `F`. A live
  `J` root without a lock is not reported as confirmed.
- **Attestation instant.** Every slot at `t_s + 2Δ`, after the update of
  `s − 1` (`fg_confirmed` is "the latest confirmation update's").
- **"Something new".** Tracked per pair kind; an absent pair is not news.
  Re-gossiping an attestation that never landed on chain is not implemented:
  gossip and every node's pool carry it, and a proposer includes it whenever
  its parent lacks the bit.
- **FG unchanged.** Nonjustifiable heights under finality debt (`K = 5`,
  `D = 2`) stay; `δ_t` defaults to `2k` slots, the time conflicting locks
  need to drain away after GST.
- **Pool.** At most 8 attestations per validator (the oldest evicted);
  attestations that can no longer count anywhere (height pair below
  `h_max − 1` and finality pair at or below `h_F`) are dropped.

## Lean: `ethlambda node --decoupled`

Enabled by `DECOUPLED_CONSENSUS: true` in the genesis config (or
`--decoupled`). Optional `DECOUPLED_LOCK_PERIOD`,
`DECOUPLED_NONJUSTIFIABLE_PERIOD`, `DECOUPLED_FINALITY_DEBT`,
`DECOUPLED_TIMEOUT_DELAY` override the defaults (`--decoupled.lock-period`
overrides the first).

- **Validators, committees, proposers.** Every validator weighs one, the
  slot committee is every validator, and the proposer of slot `s` is
  `s mod n`, as on 3SF-mini lean.
- **Wire.** New containers (`lean_decoupled`) on the topics
  `decoupled_block`, `decoupled_vote`, `decoupled_attestation`, plus a
  `decoupled_blocks_by_root/1` req/resp protocol for missing parents. The
  3SF-mini containers and topics are untouched; a decoupled network is
  ethlambda-only.
- **Blocks** are `(slot, proposer_index, parent_root, body)` with the
  previous slot's signed votes, a support bitlist and signed attestations.
  There is no state root: σ names its own block, so a block cannot commit to
  it.
- **XMSS epochs.** A validator signs a Goldfish vote every slot and at most
  one attestation per slot: the vote of slot `s` at epoch `2s`, an
  attestation signed in slot `s` at `2s + 1`. Attestation data names no
  slot, so `SignedDecoupledAttestation` carries the slot it was signed in;
  a node remembers a verified attestation by its whole envelope. A key
  generated for `2^n` epochs lasts `2^(n−1)` slots.
- **No aggregation.** Signatures are individual. Since an attestation is
  only cast when something is new, a block carries about one per validator
  per height.
- **Actor.** `DecoupledLean` runs beside a keyless 3SF-mini `BlockChain`. It
  ticks every `Δ`, skips duties of ticks already past, persists imported
  blocks and each validator's record (with the last voted and attested
  slots, so a restart never signs twice at one epoch), and replays them on
  restart as a joining node.
- **Status.** `GET /lean/v0/decoupled/status` serves head, confirmed,
  `fg_confirmed`, the live locks, the frame root and floor, finalized,
  justified and the heights.

Local devnet: `tooling/decoupled-devnet/lean-local.sh start|status|stop`.

## Beacon: the `decoupled` fork

A beacon fork named `decoupled`, between fulu and gloas in `ForkName`
(storage selector 8), with `DECOUPLED_FORK_VERSION`/`DECOUPLED_FORK_EPOCH`
and the protocol keys `DECOUPLED_LOCK_PERIOD` (default 4),
`DECOUPLED_NONJUSTIFIABLE_PERIOD` (5), `DECOUPLED_FINALITY_DEBT` (2) and
`DECOUPLED_TIMEOUT_DELAY` (8) in the config.
`ethlambda beacon --decoupled-fork-epoch 0 --decoupled-lock-period 4`
overrides a generated config. Only activation at genesis is supported.

| Piece | Choice |
|---|---|
| State | fulu's container, unchanged. σ is derived by each node and kept beside the state; the FFG fields stay at their fork-boundary values |
| Block body | electra's 13 fields + `goldfish_votes`, `goldfish_support`, `combined_attestations`; `attestations` and `attester_slashings` must be empty. `blob_kzg_commitments` stays at index 11 and the body at 16 fields, so fulu's column sidecars and inclusion proofs carry over |
| Votes on the wire | `SignedGoldfishVote` on `goldfish_vote`, `SignedCombinedAttestation` (the FG attestation; the name predates Goldilocks) on `combined_attestation` (global topics); LMD attestation subnets and aggregates are not subscribed |
| Votes in blocks | BLS aggregates per identical data: Goldfish votes per `(slot, head)` with bits over `𝒦_{s−1}` (the slot's beacon committees concatenated), attestations per `AttestationData` with bits over the registry; one support bit per vote aggregate. An aggregate must name at least one pair |
| Signing | `DOMAIN_GOLDFISH_VOTE` (0x10) at the vote's epoch, `DOMAIN_COMBINED_ATTESTATION` (0x11) at `DECOUPLED_FORK_EPOCH` (the data names no slot, and the fork has no successor) |
| Committee, proposer, weights | `𝒦_s` = the slot's beacon committees, whose size the engine derives from the active count (`slot_committee_size`); the proposer schedule is the beacon one; FG weights = effective balance in increments of the genesis registry, fixed for the run |
| Block validity | fulu's, plus: protocol fields well formed, every vote of slot `B.slot − 1` by a committee member, aggregate signatures valid |
| Epoch processing | fulu's minus justification and finalization, inactivity updates, and rewards and penalties |
| Fork choice | the engine's head, not LMD-GHOST; blocks enter the engine after the beacon state transition accepted them |
| Execution layer | `forkchoiceUpdated` head = the engine head, safe = the confirmed (locked) tip, finalized = `Σ.F` |
| Engine placement | `DecoupledNode` (`state_transition::beacon::decoupled_node`), shared by the chain actor, the p2p layer and the Beacon API |
| Restart | the stored blocks are replayed in slot order into a fresh engine |

The validator client's duty inputs are computed at their protocol instant
(the vote head at `t_s + Δ`, the attestation input at `t_s + 2Δ`) and cached,
so a validator client asking a moment later reads what the protocol
prescribes for that instant. `GET /eth/v1/decoupled/status` serves the node's
view.

Local devnet: `tooling/decoupled-devnet/beacon-kurtosis.yaml` (kurtosis with
the ethlambda-enabled ethereum-package) and `Dockerfile.dev`.

### Validator client (`crates/validator/src/decoupled.rs`)

At decoupled slots the VC makes no LMD attestation or aggregate. It runs:

| Duty | Who | When | Beacon node endpoints |
|---|---|---|---|
| Goldfish vote | validators with an attester duty in the slot (`𝒦_s`) | `t_s + Δ` (2500 bps) | `GET /eth/v1/validator/decoupled/goldfish_vote_data?slot=`, `POST /eth/v1/beacon/pool/goldfish_votes` |
| Attestation | every active validator whose record finds something new | `t_s + 2Δ` (5000 bps), every slot | `GET /eth/v1/validator/decoupled/attestation_input?slot=`, `POST /eth/v1/beacon/pool/combined_attestations` |

The anti-slashing record Λ is `ethlambda_decoupled::Record`, one per
validator pubkey, at `<validators-dir>/decoupled/<0xpubkey>.json` with the last
slot voted and the last slot attested. Every change is written (tmp file,
fsync, rename) before the signature it licenses exists; a record that does not
parse makes that validator refuse to sign rather than reset. An input with
nothing new leaves the record untouched and signs nothing.
