# Decoupled consensus: Goldilocks

ethlambda implements **Goldilocks**: Goldfish with locks as the available
chain (AC), composed with a height-based finality gadget (FG), as the
Goldilocks specification defines them (`goldilocks-spec.pdf`: the node in
figure 2, the FG in figures 3 to 5, the AC in figures 6 to 8). The engine
follows that pseudocode function by function. It replaces LMD-GHOST + Casper
FFG on the beacon chain and LMD-GHOST + 3SF-mini on the lean chain, as an
opt-in mode of each.

Three tips, one chain:

```text
finalized (FG)   confirmed (AC)   head (AC)
```

`F` is an ancestor of both AC tips. The confirmed tip need not be an ancestor
of the head: the head walks the current votes from the anchor, while the
confirmed tip is the record of the latest unvetoed confirmation.

| Process | Who votes | When | What it decides |
|---|---|---|---|
| Goldfish (AC) | slot `s`'s committee `𝒦_s` | `t_s + Δ` | the head; the confirmation update at `t_s + 6Δ` confirms a block and writes lock entries |
| Locks (AC) | nobody: derived from the committee votes | written by confirmation updates, revoked at `t_s + Δ`, expired at their deadline | the anchor every walk starts from |
| Finality gadget | every validator, once per round, only with a new height pair | the action time `a_r = T_r + 6Δ` | heights, justifications and finalizations through each block's chain state σ |

A slot is `4Δ`: proposal at `t_s`, revocation then vote at `t_s + Δ`,
support cutoff and the confirmation update of `s − 1` at `t_s + 2Δ`, view
freeze at `t_s + 3Δ`. A round is `R` slots; its action time
`a_r = T_r + 6Δ` is the confirmation update of its first slot, half way into
slot `rR + 1` (with `R = 1`, every slot from 1 on).

## The available chain

### Lock entries give the anchor, votes give the walk

`𝒜.lock_entries` holds entries `(B, d)`. An entry is live while `d > t` and
`B` extends `Φ.F`; a block is locked when it is an ancestor of (or is) the
block of a live entry. Every walk of a duty (proposal, vote, the FG action's
head) starts at the **anchor**: the deepest locked block of the full viable
tree, or `Φ.fc_root` when there is none, also when the walk itself runs over a
smaller tree (the voter's).

| Rule | When | Effect |
|---|---|---|
| Write | the confirmation update of slot `s` confirms `C` and no live entry conflicts with `C` | one entry on the deepest block of the path `Φ.F → C` that passes the fast test (`2·score ≥ \|𝒦_s\|`) or the slow test (it is an ancestor of the saved confirmations of the previous `k − 1` slots), with deadline `t_{s+k} + 5Δ` |
| Revocation | `t_s + Δ`, before the vote, over every held slot-`(s − 1)` vote | each live entry moves back to the deepest non-genesis `B'` with `Φ.F ⪯ B'` that fewer than half of `𝒦_{s−1}` oppose, keeping its deadline; deleted when there is none |
| Expiry | the first tick at or after the deadline | the entry is removed |

An opponent of `B'` is a non-equivocating validator with a resolved vote whose
head **conflicts** with `B'`: a vote for an ancestor or a descendant does not
oppose, an equivocator (two distinct votes held) never opposes, and an
unresolved vote counts neither way.

### The confirmation update (slot `s'`, at `t_{s'} + 6Δ`)

1. Support counts the votes resolved before `t_{s'} + 2Δ` of validators with
   no second vote before `t_{s'} + 6Δ`; the participants are the validators
   with a vote before `t_{s'} + 6Δ`.
2. The walk starts at `Φ.F` and descends in `Φ.tree` through children with a
   strict majority of the participants. Its end `C`, when it holds the
   majority itself, is the result; it is saved for the slow test even when
   vetoed.
3. A live entry that conflicts with `C` vetoes it. Otherwise the confirmation
   record advances (an ancestor of the record leaves it, an extension or a
   conflicting block replaces it), `𝒜.fast_blocks` becomes the path blocks
   that pass the fast test, and at most one entry is written (the table
   above).

`AC_CONFIRMED`, the **confirmed** tip, is the record while it extends `Φ.F`,
else `Φ.F`. The beacon execution layer hears it as `safe`.

## The finality gadget

### Attestations

`(validator, h, T, timeout, h_f, T_f)`: a height pair at `h ≥ 1` and a
finality pair that is absent or below it (`h_f < h`). Handlers drop any other
form. The chain state σ keeps `pending_finality`, the last `K_W`
justifications above `h_F`, each with its own finality participation:

| On chain | Effect |
|---|---|
| 2/3 finality votes for a pending `(j, T)` | finalize the greatest such `T`, drop pending pairs at or below it |
| 2/3 target votes for the chain's own `(h, T_h)` | justify `T_h`, append it to `pending_finality` (newest `K_W` kept), advance the height |
| 2/3 targets + timeouts, `δ_t` slots after the entry | advance the height, no justification |

A block may carry an attestation only when it is valid against the parent's
state: it names the chain's own entry at the current height, or it is a vote
below the current height whose finality pair is pending. Otherwise the block
is refused.

### The FG action (`a_r`, once per round)

- **source**: the deepest block of `𝒜.fast_blocks` in the full viable tree,
  or none, in which case the validator does not attest;
- **height pair** `(h_c, T_c)` from the source's state; **finality pair**
  `(h_j, J, h_F)` from the state of the head, the walk over the full viable
  tree with the current slot's votes.

The record Λ (`ethlambda_decoupled::Record`: `target`, `timeout`, `lock`,
`sent`) decides the pairs. An attestation needs a height pair; a target is
sent only as the first vote at its height, each entry is named at most once at
a height, and the finality pair is attached only below the height pair. On a
chain without height progress nothing is sent, so the attestation traffic of
a stalled finality dies down by itself.

Network attestations feed only the pool. A proposal on `H` carries every
pooled attestation valid against `σ[H]` that `H`'s chain does not carry yet,
in pool order.

### The FG frame

```text
h_max = h_j + 1?   a block at h_max not on J?   fc_root   head height floor
no                 —                            F         h_max − 1
yes                no                           J         h_max − 1
yes                yes (a contest)              F         h_max
```

The viable tree is the descendants of `fc_root` with a viable head (state
height at least the floor) among their descendants. The contest is read from
the current tree, so it ends if finality prunes the contesting branch.
Finality acceptance requires a viable descendant under the same floor.

## Code map

```text
crates/blockchain/decoupled/       ethlambda-decoupled: the protocol, chain-agnostic
  src/params.rs                    k, R, K_W, δ_t; the Δ grid, action times, deadlines
  src/types.rs                     BlockInput, Electorate, Tick (+ re-exported payloads)
  src/chain_state.rs               σ: valid_attestation, state_transition, height events
  src/store.rs                     Σ and 𝒜: on_tick, on_block, on_goldfish_vote,
                                   on_attestation, update_finality, the frame
  src/locks.rs                     CommitteeSizes, lock entries, revoke_locks, get_anchor
  src/fork_choice.rs               viable tree, goldfish score and eligibility, GHOST,
                                   head, AC_CONFIRMED
  src/duties.rs                    proposal, proposal_attestations, goldfish_vote_head,
                                   update_confirmation, source, attestation_input
  src/validator_client.rs          Λ: finality_pair, height_pair, create_attestation, E1/E2
  src/simulation.rs                in-process network tests
crates/common/types/src/decoupled.rs        payloads both chains embed (votes, attestation
                                            data, σ), DecoupledStatus
crates/common/types/src/lean_decoupled.rs   lean wire containers and XMSS epoch grid
crates/blockchain/src/decoupled_lean.rs     lean chain actor
crates/common/types/src/beacon/containers/decoupled.rs   the beacon `decoupled` fork
```

## The engine

`ethlambda_decoupled::Store` holds Σ and 𝒜. Hosts:

1. call `advance_to(now_tick)` before every handler, where a tick is
   `floor((now − genesis) / Δ)`;
2. run the duties the returned `TickEvents` ask for, in order (propose, vote,
   attest), reading `proposal()`, `goldfish_vote_head()` and
   `attestation_input()`, and feed what they sign back through the handlers;
3. check signatures, committee membership and the proposer schedule before
   calling a handler;
4. declare the committee sizes (`Store::with_committee_sizes`) when the slot
   committee is not every validator.

### Parameters and departures

| Item | Value or rule | Why |
|---|---|---|
| `k` | 4 (at least 2) | the slides' example |
| `R` | 2 (at least 1) | the specification's floor `max{2, ⌈(6Δ + Δ_F)/4Δ⌉}` with `Δ_F = Δ`; `R = 1` is allowed although the specification excludes it: `a_r` then falls in the next round's slot, and every slot from 1 on acts at its confirmation update |
| `K_W` | 2 (at least 2) | the specification's floor; the honest steady state finalizes `j` in the block that justifies `j + 1` |
| `δ_t` | `2k` slots | the specification leaves it open; the time conflicting locks need to drain after GST |
| Pool bound | 8 attestations per validator, and attestations that cannot be valid against any viable head are dropped | resource bound; the specification's pool is unbounded |
| Lock entries | entries on one block keep the later deadline | locks, revokes and expires exactly as the separate entries |
| User-facing head | the walk over the current slot's votes once it has any, else the previous slot's | the specification only defines the heads of duties |
| Beacon committees | `𝒦_s` is the slot's beacon committees, not `V` | the beacon host keeps its committee schedule |

## Lean: `ethlambda node --decoupled`

Enabled by `DECOUPLED_CONSENSUS: true` in the genesis config (or
`--decoupled`). Optional `DECOUPLED_LOCK_PERIOD`, `DECOUPLED_SLOTS_PER_ROUND`,
`DECOUPLED_PENDING_FINALITY_WINDOW`, `DECOUPLED_TIMEOUT_DELAY` override the
defaults (`--decoupled.lock-period` and `--decoupled.slots-per-round`
override the first two; on beacon, `--decoupled-lock-period` and
`--decoupled-slots-per-round`).

The round length `R` must outlast the attestations' delivery `Δ_F`: the
specification asks `R ≥ ⌈(6Δ + Δ_F) / 4Δ⌉`. With aggregated attestations
(below) the aggregates miss the first block after the action time, so with
`R = 2` the block raising the height is confirmed only after the next
action time, and validators attest every other round. On a local devnet
(16 validators, 2 subnets, 8 s slots, four nodes proving on one machine)
subnet aggregates landed about 6.5 s (`3.3Δ`) after the action time, which
makes the bound `R = 3`; it restores one attestation per round and took
the state around slot 30 from max height 8 and finalized slot 21 (`R = 2`)
to max height 10 and finalized slot 24.

- **Validators, committees, proposers.** Every validator weighs one, the
  slot committee is every validator, and the proposer of slot `s` is
  `s mod n`, as on 3SF-mini lean.
- **Wire.** New containers (`lean_decoupled`) on the topics
  `decoupled_block`, `decoupled_vote`, `decoupled_attestation_{subnet}` and
  `decoupled_aggregate`, plus a `decoupled_blocks_by_root/1` req/resp
  protocol for missing parents. The 3SF-mini containers and topics are
  untouched; a decoupled network is ethlambda-only.
- **Blocks** are `(slot, proposer_index, parent_root, body)` with the
  previous slot's signed votes, a support bitlist and up to
  `MAX_BLOCK_AGGREGATES` aggregated attestations, each signed in a slot
  before the block's. There is no state root: σ names its own block, so a
  block cannot commit to it.
- **XMSS epochs.** A validator signs a Goldfish vote every slot and at most
  one attestation per slot: the vote of slot `s` at epoch `2s`, an
  attestation signed in slot `s` at `2s + 1`. A vote signs the vote's root;
  an attestation signs its *data's* root, so every validator with one view
  signs one message and the signatures aggregate. Attestation data names no
  slot, so attestation envelopes carry the slot they were signed in; a node
  remembers a verified attestation or aggregate by its whole envelope. A
  key generated for `2^n` epochs lasts `2^(n−1)` slots.
- **Attestation aggregation** (`decoupled_aggregation.rs`). Goldfish votes
  stay individual: a block carries them one interval after they are cast,
  too soon for a proof. Attestations go through two levels of leanVM
  aggregation, with signing staggered so proving overlaps arrival:

  ```text
  a_r = t_s + 2Δ   every validator's attestation decided from one input
  a_r + g·spacing  subgroup g = (v / C) mod N signs, on subnet v mod C
  aggregator       each time an N-th of its subnets' validators is pending,
                   fold them into its running proof (the last proof a child)
  final deadline   (or everyone in) last batch; publish on decoupled_aggregate
  all subnets in   (or merge deadline) every aggregator merges the subnet
                   proofs, one proof per data, and publishes it
  proposer         the engine picks attestations; the block carries the
                   fewest held aggregates covering them
  ```

  Defaults: `N = 4` subgroups, spacing `Δ/2` (the four subgroups sign over
  the second half of the action slot), final deadline half a `Δ` after the
  last subgroup, merge deadline two `Δ` after that (a slot after `a_r`),
  merges of up to leanVM's 16 children per level. `--attestation-subgroups`,
  `--attestation-subgroup-spacing-ms`, `--max-aggregation-children` and
  `--global-aggregation-deadline-ms` change them; `--is-aggregator` and
  `--aggregate-subnet-ids` pick who aggregates what (default: the subnets of
  the node's own validators). Every node verifies each aggregate once and
  feeds the engine one attestation per participant. A network with no
  aggregator still votes and confirms but never justifies, since blocks
  carry attestations only as aggregates.
- **Actor.** `DecoupledLean` runs beside a keyless 3SF-mini `BlockChain`. It
  ticks every `Δ`, skips duties of ticks already past, persists imported
  blocks and each validator's record (with the last voted and attested
  slots, so a restart never signs twice at one epoch), and replays them on
  restart as a joining node.
- **Status.** `GET /lean/v0/decoupled/status` serves head, confirmed, the
  source, the live lock entries, the frame root and floor, finalized,
  justified and the heights.

Local devnet: `tooling/decoupled-devnet/lean-local.sh start|status|stop`.

## Beacon: the `decoupled` fork

A beacon fork named `decoupled`, between fulu and gloas in `ForkName`
(storage selector 8), with `DECOUPLED_FORK_VERSION`/`DECOUPLED_FORK_EPOCH`
and the protocol keys `DECOUPLED_LOCK_PERIOD` (default 4),
`DECOUPLED_SLOTS_PER_ROUND` (2), `DECOUPLED_PENDING_FINALITY_WINDOW` (2) and
`DECOUPLED_TIMEOUT_DELAY` (8) in the config.
`ethlambda beacon --decoupled-fork-epoch 0 --decoupled-lock-period 4`
overrides a generated config. Only activation at genesis is supported.

| Piece | Choice |
|---|---|
| State | fulu's container, unchanged. σ is derived by each node and kept beside the state; the FFG fields stay at their fork-boundary values |
| Block body | electra's 13 fields + `goldfish_votes`, `goldfish_support`, `combined_attestations`; `attestations` and `attester_slashings` must be empty. `blob_kzg_commitments` stays at index 11 and the body at 16 fields, so fulu's column sidecars and inclusion proofs carry over |
| Votes on the wire | `SignedGoldfishVote` on `goldfish_vote`, `SignedCombinedAttestation` (the FG attestation; the name predates Goldilocks) on `combined_attestation` (global topics); LMD attestation subnets and aggregates are not subscribed |
| Votes in blocks | BLS aggregates per identical data: Goldfish votes per `(slot, head)` with bits over `𝒦_{s−1}` (the slot's beacon committees concatenated), attestations per `AttestationData` with bits over the registry; one support bit per vote aggregate. An attestation must be well formed |
| Signing | `DOMAIN_GOLDFISH_VOTE` (0x10) at the vote's epoch, `DOMAIN_COMBINED_ATTESTATION` (0x11) at `DECOUPLED_FORK_EPOCH` (the data names no slot, and the fork has no successor) |
| Committee, proposer, weights | `𝒦_s` = the slot's beacon committees, whose size the engine derives from the active count (`slot_committee_size`); the proposer schedule is the beacon one; FG weights = effective balance in increments of the genesis registry, fixed for the run |
| Block validity | fulu's, plus: protocol fields well formed, every vote of slot `B.slot − 1` by a committee member, aggregate signatures valid. The engine then refuses a block whose attestations are not valid against the parent's σ; the block stays in the beacon store but never enters the fork choice, and neither do its descendants |
| Epoch processing | fulu's minus justification and finalization, inactivity updates, and rewards and penalties |
| Fork choice | the engine's head, not LMD-GHOST; blocks enter the engine after the beacon state transition accepted them |
| Execution layer | `forkchoiceUpdated` head = the engine head, safe = `AC_CONFIRMED`, finalized = `Σ.F` |
| Engine placement | `DecoupledNode` (`state_transition::beacon::decoupled_node`), shared by the chain actor, the p2p layer and the Beacon API |
| Restart | the stored blocks are replayed in slot order into a fresh engine |

The validator client's duty inputs are computed at their protocol instant
(the vote head at `t_s + Δ`, the attestation input at `a_r`) and cached, so a
validator client asking a moment later reads what the protocol prescribes for
that instant. `GET /eth/v1/decoupled/status` serves the node's view.

Local devnet: `tooling/decoupled-devnet/beacon-kurtosis.yaml` (kurtosis with
the ethlambda-enabled ethereum-package) and `Dockerfile.dev`.

### Validator client (`crates/validator/src/decoupled.rs`)

At decoupled slots the VC makes no LMD attestation or aggregate. It runs:

| Duty | Who | When | Beacon node endpoints |
|---|---|---|---|
| Goldfish vote | validators with an attester duty in the slot (`𝒦_s`) | `t_s + Δ` (2500 bps) | `GET /eth/v1/validator/decoupled/goldfish_vote_data?slot=`, `POST /eth/v1/beacon/pool/goldfish_votes` |
| Attestation | every active validator whose record finds a new height pair | `a_r` (5000 bps of slot `rR + 1`, slots with `slot mod R = 1`) | `GET /eth/v1/validator/decoupled/attestation_input?slot=`, `POST /eth/v1/beacon/pool/combined_attestations` |

The anti-slashing record Λ is `ethlambda_decoupled::Record`, one per
validator pubkey, at `<validators-dir>/decoupled/<0xpubkey>.json` with the last
slot voted and the last slot attested. Every change is written (tmp file,
fsync, rename) before the signature it licenses exists; a record that does not
parse makes that validator refuse to sign rather than reset. An input the
record makes nothing of leaves it untouched and signs nothing.
