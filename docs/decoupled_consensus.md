# Decoupled consensus (EIP-8453)

ethlambda implements the fork choice, finality gadget rules and validator
signing rules of **EIP-8453 ("Decoupled Consensus")** as specified on
[consensus-specs](https://github.com/ethereum/consensus-specs) branch
`decoupled-consensus` at commit
`0f4fa3ffdd26ec083ff4dba65645d81433178413`
(`specs/_features/eip8453/{fork-choice,beacon-chain,validator,p2p-interface}.md`,
built on gloas/heze's payload-aware fork choice). Names below are the spec's.

The engine is chain-agnostic. The lean chain runs it today as an opt-in mode
(`ethlambda node --decoupled`), replacing LMD-GHOST + 3SF-mini; the beacon
chain's EIP-8453 fork will drive the same engine from its `BeaconState`.

It replaces an earlier engine that followed Section 7 of the paper formalized
in `fradamt/verified-consensus` (Goldfish, a graded stabilization gadget with a
`safe` vote, a nonjustifiable period and finality debt). None of that remains.

## The protocol in brief

EIP-8453 composes two parts:

| Part | Who votes | When | What it decides |
|---|---|---|---|
| Finality gadget (FG) | every validator, once per round of `SLOTS_PER_ROUND` slots | its attestation slot | heights, justifications, finalizations, through the chain state of every block |
| Available chain (AC) | slot `s`'s head vote committee | `t_s + Δ` | the head; the confirmation of `s` at `t_{s+1} + 2Δ`, and the locks it creates |

A slot is `4Δ`: proposal at `t_s`, head vote at `t_s + Δ`
(`HEAD_VOTE_DUE_BPS`), support cutoff at `t_s + 2Δ` (`SUPPORT_CUTOFF_BPS`),
view freeze at `t_s + 3Δ` (`VIEW_FREEZE_BPS`).

- **FG.** Heights advance by target block. A block's chain state counts the
  attestations it carries: a quorum (`has_quorum`: `p > 0` and `3p ≥ 2W`) of
  target votes justifies the current target, adds it to a pending-finality
  window of `PENDING_FINALITY_WINDOW` and moves to the next height; a quorum of
  target votes and timeouts moves on only `TIMEOUT_DELAY_SLOTS =
  SLOTS_PER_ROUND` slots after the target; the highest pending justification
  whose finality pairs reach a quorum is finalized.
- **AC.** The head is a GHOST walk over committee *seats*, inside the FG frame
  (rooted at the justified block when it is the latest, uncontested height,
  else at the finalized one; height floor `max_height − 1`, or `max_height`
  during an FG contest), from an anchor that the live locks set. The previous
  slot is confirmed at the support cutoff by a walk from the finalized node;
  a confirmation takes a *fast* lock (half of all seats support it) or a
  *slow* lock (it is under every saved confirmation of the last
  `SLOW_LOCK_WINDOW − 1` slots), which lives until a head vote deadline
  `SLOW_LOCK_WINDOW + 1` slots later, vetoes conflicting confirmations, and
  moves to an ancestor (`unlock`) when half the seats oppose it.
- **Validators** attest with the deepest viable node of the fast-confirmed
  path as their FG source, and keep a `FinalitySigningRecord` that never lets
  them sign a slashable pair.

## Code map

```text
crates/blockchain/decoupled/             ethlambda-decoupled: the protocol, chain-agnostic
  src/params.rs                          Δ grid, BPS due times, SLOTS_PER_ROUND, windows
  src/types.rs                           BlockInput, FgCheckpoints, Anchor, HeadVote, AcVote,
                                         HeadVoteCommittees, Electorate (+ re-exported payloads)
  src/store.rs                           Store, get_forkchoice_store, on_tick, on_block,
                                         on_execution_payload_envelope, on_head_vote_message,
                                         record_head_vote_committee, update_finality, pruning
  src/fork_choice.rs                     nodes (children, get_ancestor, is_ancestor,
                                         is_compatible, get_deepest_node), payload tiebreaker,
                                         FG frame/contest/viability, GHOST walks, scores,
                                         head-walk anchor, voter subtree, confirmed head
  src/views.rs                           vote resolution, p2p/block/proposer views, merge
  src/confirmation.rs                    live locks, fast/slow locks, update_confirmation,
                                         update_locks_and_confirmation, unlock
  src/duties.rs                          get_ac_proposal, get_ac_vote_head, get_ac_frame,
                                         get_head, get_confirmed_node, head_vote_data
  src/validator_client.rs                FinalitySigningRecord, get_finality_vote,
                                         get_height_vote, get_finality_attestation_data,
                                         slashing predicates
  src/chain_state.rs                     lean's FG chain state: process_attestation,
                                         process_height_events, advance_height, has_quorum
  src/tests.rs, src/simulation.rs        spec-function unit tests, in-process networks
crates/common/types/src/decoupled.rs        HeightCheckpoint, AttestationData, HeadVoteData,
                                            HeadVoteMessage, ForkChoiceNode, PayloadStatus,
                                            DecoupledStatus
crates/common/types/src/lean_decoupled.rs   lean wire containers and XMSS epoch grid
crates/blockchain/src/decoupled_lean.rs     lean chain actor
```

## The engine

`ethlambda_decoupled::Store` is the spec's fork choice `Store`. A host:

1. builds it with `Store::new(params, committees, anchor)`
   (`get_forkchoice_store`): the anchor is trusted as justified and finalized
   at its post-state's target height;
2. calls `advance_to(now_tick)` before every handler, where a tick is
   `floor((now_ms − genesis_ms) / Δ_ms)` and `Δ = SLOT_DURATION_MS / 4`. Each
   tick runs `on_tick`: `unlock(s − 1)` at the head vote deadline and
   `update_confirmation(s − 1)` at the support cutoff, both before the clock
   moves;
3. runs the duties the returned `TickEvents` ask for: `propose` at a slot's
   start (`get_ac_proposal`), `head_vote` at its deadline
   (`get_ac_vote_head`, signed as `head_vote_data`), `support_cutoff` for FG
   attestations (`get_ac_frame` → `finality_attestation_input` →
   `FinalitySigningRecord::attest`); and feeds what it signs back through the
   handlers;
4. runs each block's state transition, checks signatures and committees, and
   hands the engine only fork-choice content (`BlockInput`): the block's
   parent payload status, its carried head votes with their support bits, and
   its post-state's FG checkpoints.

### What a host supplies

| Input | Lean | Beacon (to integrate) |
|---|---|---|
| Time | ticks of `Δ = slot / 4` | same, from `SLOT_DURATION_MS` |
| FG checkpoints per block (`FgCheckpoints`) | `chain_state::ChainStates::import` | `state.target_checkpoint`, `justified_checkpoint`, `finalized_checkpoint` (an empty target root is filled with the block's root, as `process_slot` would) |
| Committee seats (`HeadVoteCommittees`) | `EveryValidator { n }`: one seat each, every slot | `recorded(HEAD_VOTE_COMMITTEE_SIZE)` and `record_head_vote_committee(slot, get_head_vote_committee(state, slot))` before each message or block vote of that slot |
| FG weights (`Electorate`) | one per validator | read from `BeaconState` (`get_validator_weight`); the engine never sees them |
| Payload status | none: every block builds on `Empty`, no payload is ever verified | `BlockInput::parent_payload_status` (`get_parent_payload_status`), `on_execution_payload_envelope(root, inclusion_list_satisfied)`, `set_payload_inclusion_list_satisfaction` |
| Signatures, gossip rules | XMSS, first message per key | BLS, `validate_head_vote_gossip` |

`get_confirmed_execution_block_hash` is left to the beacon host: it maps
`get_confirmed_node()` to the confirmed block's bid (`block_hash` when `Full`,
`parent_block_hash` otherwise).

### Implementation choices

- **Time in ticks of `Δ`.** The three due times are the quarter points of a
  slot, so every threshold the spec compares a receipt time against (strict
  `<`) and every lock deadline it compares the clock against (strict `>`) is
  on the grid. Stamping an object received between two grid instants with
  the earlier one gives the same answers. A configuration whose BPS are not
  multiples of 2500 does not compile (`params::bps_to_ticks`).
- **`on_tick` order.** `update_confirmation` reads `store.time_ms` before the
  clock moves, as the spec's `on_tick` does; with every tick run in order that
  is the previous tick, which gives the same live locks as the spec's
  millisecond clock. A store that has never ticked jumps straight to the first
  time it is given rather than replaying the past.
- **Payload-aware nodes, literally.** Nodes are `(root, payload_status)` with
  gloas's `get_node_children`, `get_ancestor` and `is_ancestor`. Without
  payloads a block has a `Pending` and an `Empty` node; the `Empty` step is
  always taken (`is_previous_slot_payload_decision`, or the same support as
  its `Pending` node), so the walk is the block tree's.
- **`should_extend_payload`.** EIP-8453's `on_block` no longer calls
  `update_proposer_boost_root`, so `proposer_boost_root` stays empty and the
  heze rule reduces to "verified and satisfies the inclusion list".
- **`get_deepest_node` ties** (same slot and pending-ness) go to the greater
  root, then the greater payload status; the spec leaves them to Python's
  `max`.
- **Scores are precomputed per walk:** each supporter's seats are marked on
  its node's ancestors once, instead of evaluating `is_ancestor` per node and
  vote. `get_viable_subtree`, the head-walk anchor and the voter subtree mark
  ancestors the same way.
- **Pruning.** The spec never prunes. At each slot start the engine drops
  blocks outside the finalized block's subtree (they are read again only as
  carriers of the current slot's votes, which a block of an earlier slot is
  not), remembers strict ancestors of the finalized block by root only (so a
  child of one is refused, not fetched), and drops head vote messages and
  committees older than the previous slot, saved confirmations older than the
  slow lock window, and expired locks. Every spec reader already ignores what
  is dropped (`in fg_frame.tree`, the finalized-descent checks).
- **Handler results.** `on_block` returns `Duplicate` where the spec returns
  silently, and checks `slot > parent.slot` (the state transition's
  `process_block_header`) since ancestry walks by slot.
  `on_head_vote_message` checks the parts of `is_valid_head_vote_message` it
  can (payload status, committee membership from the recorded committee); a
  vote of a slot with no recorded committee is refused, and a block vote of
  one weighs zero seats (the spec asserts the committee is there).
- **No vote caps.** The fork-choice pool takes every distinct message, as
  `on_head_vote_message` does; the gossip rule "first head vote per
  `(slot, validator)`" belongs to the host.
- **No head vote at the genesis slot.** `get_ac_vote_head` answers the
  finalized node's `Empty` branch there, which a same-slot vote may not name,
  so `TickEvents::head_vote` is false at slot 0.
- **The signing record never prunes.** `FinalitySigningRecord` has no API that
  drops entries; finality signing locks do not expire.

### What the spec leaves open, and what the engine does

- **FG attestation deadline and source observation** (validator.md TODO):
  `TickEvents::support_cutoff` marks the earliest instant `get_ac_frame` may
  be read, right after the confirmation it depends on. Lean attests then, in
  each validator's slot of the round.
- **Proposal helper** (full/empty choice, inclusion-list checks, aggregate
  selection beyond `MAX_HEAD_VOTES`): `get_ac_proposal` returns the head node
  and the p2p view; selection is the host's.
- **Head-vote deadline helper, assignment lookahead, aggregation selection,
  `head_vote_aggregate` and `attestation_aggregate` topics, head-vote
  rewards**: host or not applicable to the engine.

## Lean: `ethlambda node --decoupled`

Enabled by `DECOUPLED_CONSENSUS: true` in the genesis config (or
`--decoupled`). `DECOUPLED_SLOTS_PER_ROUND` (or
`--decoupled.slots-per-round`) sets `SLOTS_PER_ROUND`, and with it
`TIMEOUT_DELAY_SLOTS`; the default is the minimal preset's 4, which suits
4-second slots. Every other parameter is the spec's
(`PENDING_FINALITY_WINDOW = 4`, `SLOW_LOCK_WINDOW = 4`, the BPS).

- **Validators, committees, proposers.** Every validator weighs one in FG
  quorums and holds one seat in every slot's head vote committee (so
  `get_head_vote_committee_seats_count` is `n`). The proposer of slot `s` is
  `s mod n`, as on 3SF-mini lean. Validator `v` attests in slot
  `round · R + (v mod R)` of each round (`lean_decoupled::attestation_slot`),
  lean's stand-in for `compute_attestation_committee_slot`.
- **Chain state.** `chain_state.rs` is the FG part of the beacon state on
  lean: `process_attestation` (an attestation that is not well formed or not
  valid makes the block invalid, as the spec asserts), `process_height_events`
  and `advance_height`, minus rewards, flags and the inactivity leak. The
  target of a new height is filled with the advancing block's root
  immediately: lean's chain state is never committed to by its own block. The
  genesis state is `upgrade_to_eip8453`'s: height 1 targets genesis, which is
  justified and finalized at height 0.
- **Wire.** New containers (`lean_decoupled`) on topics `decoupled_block`,
  `decoupled_head_vote`, `decoupled_fg_attestation`, plus
  `decoupled_blocks_by_root/1` for missing parents. A block is
  `(slot, proposer_index, parent_root, body)` with the previous slot's signed
  head votes (one voter each), their support bits and signed FG attestations.
  Head votes carry the spec's payload status byte. FG attestations carry the
  round they were cast in, which fixes the XMSS epoch they are signed at. The
  3SF-mini containers and topics are untouched; a decoupled network is
  ethlambda-only.
- **Gossip.** The actor keeps the first head vote per `(slot, validator)` and
  the first FG attestation per `(round, validator)`, as p2p-interface.md's
  gossip rules do; a second message from one key reaches the fork choice only
  inside a block.
- **Proposals** build on `get_ac_proposal`'s head, carry the previous slot's
  p2p head votes with its support indices, and include the pooled FG
  attestations that `process_attestation` accepts on the head's chain state
  and that add target, progress or pending-finality participation.
- **XMSS epochs.** A validator signs a head vote every slot and an FG
  attestation once per round, and an XMSS key may sign one message per epoch.
  The attestation key therefore signs on a doubled grid: the head vote of slot
  `s` at epoch `2s`, the attestation cast in slot `s` at `2s + 1`. Blocks keep
  the proposal key at `epoch = slot`. A key generated for `2^n` epochs lasts
  `2^(n−1)` slots.
- **No aggregation.** Signatures are individual (1208 bytes each); leanVM
  aggregation by `(epoch, message)` is the scale follow-up.
- **Actor.** `DecoupledLean` runs beside a keyless 3SF-mini `BlockChain`,
  which keeps the storage, RPC and p2p wiring it already owns. It ticks every
  `Δ`, skips duties of ticks already past (an XMSS epoch skipped is never
  reused), persists imported blocks and each validator's signing state (the
  record, the last voted slot and the last attested round, written before
  signing), and replays blocks on restart as a joining node: its locks and
  saved confirmations start empty.
- **Status.** `GET /lean/v0/decoupled/status` serves the head, the confirmed
  node and `latest_confirmed`, the finalized and justified checkpoints,
  `max_height`, whether the FG is in a contest, and the live lock count.

Local devnet: `tooling/decoupled-devnet/lean-local.sh start|status|stop`.

## Beacon

The beacon chain's EIP-8453 fork (types and state transition, built on Heze)
runs this engine as its fork choice, fed as the "What a host supplies" table
says; the FG rules come from `BeaconState` rather than `chain_state.rs`.

```text
crates/blockchain/state_transition/src/beacon/
  eip8453_fork_choice.rs     the host: Δ ticks on the schedule-aware slot clock,
                             BlockInput from a block and its post-state, anchors,
                             is_finalized_ancestor, get_latest_attestation_committee_slot,
                             the execution hashes (get_confirmed_execution_block_hash)
  eip8453_node.rs            SharedEip8453Node: the engine, the gossip Seen sets,
                             the signed head votes and single attestations behind it,
                             duty inputs recorded at their instants
  eip8453_block_production.rs  pack_attestations, assemble_block
  gossip/{head_vote,fg_attestation}.rs  the two new topics' rules, and `submit`
  gossip/block.rs            EIP-8453's modified beacon_block rules
crates/blockchain/src/beacon_eip8453.rs   the chain actor: install, replay, tick,
                                          feed, head and checkpoints, forkchoiceUpdated
crates/blockchain/src/beacon_eip8453_network_tests.rs  in-process networks
```

- **Time.** The engine's tick is `4 * slot + quarter` from the beacon slot
  clock (heze's slot duration change included), so its `slot_of` agrees with
  the beacon slot. The chain actor ticks every quarter slot from a slot
  before the fork.
- **Blocks.** `fork_choice::on_block` runs an EIP-8453 block's state
  transition and gloas's payload bookkeeping only; the actor then records the
  head vote committees of the votes it carries (from its post-state) and
  hands the engine its `BlockInput`. Envelopes reach the engine once
  verified, with their inclusion list verdict.
- **The fork transition and restarts** both anchor the engine at the store's
  finalized block and replay the stored blocks above it; at the transition a
  lock is seeded on the last LMD-GHOST head. See `docs/spec_deviations.md`
  (EIP-8453) for both.
- **Head and finality.** The actor writes the engine's head (with its
  payload status) and the gadget's justified and finalized blocks to the
  store, which prunes on the finalized one, and sends `forkchoiceUpdated`
  with the head node's payload, the confirmed node's (safe) and the finalized
  block's.
- **Gossip.** `head_vote` and `attestation_{subnet_id}` are validated off the
  actor and applied to the shared node; validator clients' own messages go
  through the same rules (`submit`) and are then published.
