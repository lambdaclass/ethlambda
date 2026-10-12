# Decoupled consensus

ethlambda implements the *decoupled consensus protocol* of Section 7 of the
paper formalized and machine-checked in
[`fradamt/verified-consensus`](https://github.com/fradamt/verified-consensus)
(its `docs/PROTOCOL.md` is the reference pseudocode; section names below
follow it). It replaces LMD-GHOST + Casper FFG on the beacon chain and
LMD-GHOST + 3SF-mini on the lean chain, as an opt-in mode of each.

The protocol has three layers, nested at every node and every time:

```text
finalized  ⪯  stable  ⪯  confirmed  ⪯  head
  (FG)         (SG)       (Goldfish)
```

| Layer | Who votes | When | What it decides |
|---|---|---|---|
| Goldfish (available chain) | slot `s`'s committee `𝒦_s` | `t_s + Δ` | the head; confirmation at `t_s + 6Δ` |
| Stabilization gadget (SG) | every validator, once per round of `R` slots | `a_r = T_r + 6Δ` | three relative-majority grades per round, which anchor the Goldfish walk and veto conflicting confirmations |
| Finality gadget (FG) | the same combined attestation | `a_r` | heights, justifications and finalizations through each block's chain state σ |

A slot is `4Δ`: proposal at `t_s`, vote at `t_s + Δ`, support cutoff at
`t_s + 2Δ`, view freeze at `t_s + 3Δ`.

## Code map

```text
crates/blockchain/decoupled/       ethlambda-decoupled: the protocol, chain-agnostic
  src/params.rs                    R, η_SG, K, D, δ_t; the Δ grid and grade cutoffs
  src/types.rs                     BlockInput, Electorate, Tick (+ re-exported payloads)
  src/chain_state.rs               σ: state_transition, process_attestation, height events
  src/store.rs                     Σ: on_tick, on_block, on_goldfish_vote, on_sg_vote,
                                   update_finality, accessors (stable, confirmed)
  src/fork_choice.rs               viability, FG root, filtered tree, goldfish score, ghost
  src/grades.rs                    supports/opposes per validator, saved grades, SG root
  src/duties.rs                    proposal, goldfish_vote_head, update_confirmation,
                                   attestation_input
  src/validator_client.rs          Λ: finality_pair, height_pair, create/record, E1/E2
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
   `floor((now − genesis) / Δ)`: every public time is a multiple of `Δ`, and an
   object processed between two public times is stamped with the earlier one;
2. run the duties the returned `TickEvents` ask for, in order (propose, vote,
   attest), reading `proposal()`, `goldfish_vote_head()` and
   `attestation_input()`, and feed what they sign back through the handlers;
3. check signatures, committee membership and the proposer schedule before
   calling a handler. The engine checks only what the protocol's handlers
   check (slot and round windows, duplicates, the two-vote caps, the parent,
   descent from `Σ.F`, rounds of carried attestations).

The validator client's record Λ is a separate value
(`ethlambda_decoupled::Record`), owned by whoever holds the keys:
`create_attestation` decides the height and finality pairs from an
`AttestationInput`, records, then releases. An honest record never yields E1
or E2 evidence (`honest_records_never_produce_evidence`).

### Implementation choices in the engine

- **Time in units of Δ.** All protocol instants are integer ticks; strict
  cutoffs compare stamps, exactly as the formal model's `stampedBefore`.
- **Per-validator stances for grades.** A validator's support set is the
  ancestors of the deepest common ancestor of the heads it supports, and its
  opposition set is everything, nothing, or the complement of such a set. The
  deepest graded block is then found by marking ancestors of support tips
  down to `Σ.F`, instead of evaluating the quantified `supports`/`opposes`
  for every block. Grades are monotone towards the root, so this finds the
  same block.
- **Finality clip at read time.** Saved grades are clipped to `Σ.F` whenever
  they are read, which is equivalent to clipping them when `Σ.F` moves.
- **Pruning.** When `Σ.F` advances, branches that conflict with it are
  dropped: the admission guard refuses their children. Every reader treats
  all strict ancestors of `Σ.F` alike, so a saved grade on a dropped branch
  stands as the anchor. Ancestors of `Σ.F` are kept (a stale vote for one
  still opposes `Σ.F`'s descendants). Pool entries older than any rule reads
  are dropped every tick.
- **Defaults.** `η_SG = 2`, `K = 5` (the smallest value at which the formal
  finality claims are non-vacuous, MODELING_CHOICES §7), `D = 2`,
  `δ_t = 2R`. `R` is per chain: 3 on lean, 4 on the beacon devnet.

## Lean: `ethlambda node --decoupled`

Enabled by `DECOUPLED_CONSENSUS: true` in the genesis config (or
`--decoupled`). Optional `DECOUPLED_SLOTS_PER_ROUND`, `DECOUPLED_SG_WINDOW`,
`DECOUPLED_NONJUSTIFIABLE_PERIOD`, `DECOUPLED_FINALITY_DEBT`,
`DECOUPLED_TIMEOUT_DELAY` override the defaults.

- **Validators, committees, proposers.** Every validator weighs one, the
  slot committee is every validator, and the proposer of slot `s` is
  `s mod n`, as on 3SF-mini lean.
- **Wire.** New containers (`lean_decoupled`) on new topics
  `decoupled_block`, `decoupled_vote`, `decoupled_attestation`, plus a
  `decoupled_blocks_by_root/1` req/resp protocol for missing parents. The
  3SF-mini containers and topics are untouched, so interop with other lean
  clients in 3SF-mini mode is unaffected; a decoupled network is
  ethlambda-only.
- **Blocks** are `(slot, proposer_index, parent_root, body)` with the
  previous slot's signed votes, a support bitlist and signed attestations.
  There is no state root: the only consensus state is σ, which names its own
  block (`L`, and `T_h ← L` on a height advance), so a block cannot commit to
  it. The genesis block's parent root is the 3SF-mini genesis state root, so
  it commits to the genesis time and the validator set.
- **XMSS epochs.** A validator signs a Goldfish vote every slot and a
  combined attestation once per round, and an XMSS key may sign one message
  per epoch. The attestation key therefore signs on a doubled grid: the vote
  of slot `s` at epoch `2s`, the attestation of the round opening at slot
  `o` at `2o + 1`. Blocks keep the proposal key at `epoch = slot`. A key
  generated for `2^n` epochs lasts `2^(n−1)` slots.
- **No aggregation.** Signatures are individual (1208 bytes each). leanVM
  aggregation costs seconds per proof and a block carries the previous
  slot's votes three intervals after they are cast; at devnet scale the
  bytes are fine. Aggregating by `(epoch, message)` is the scale follow-up.
- **Actor.** `DecoupledLean` runs beside a keyless 3SF-mini `BlockChain`,
  which keeps the storage, RPC and p2p wiring it already owns. It ticks every
  `Δ`, skips duties of ticks already past (an XMSS epoch skipped is never
  reused), persists imported blocks and each validator's record (with the
  last voted slot and attested round, so a restart inside a slot never signs
  twice at one epoch), and replays them on restart as a joining node.
- **Status.** `GET /lean/v0/decoupled/status` serves head, confirmed,
  stable, finalized, justified and the heights.

Local devnet: `tooling/decoupled-devnet/lean-local.sh start|status|stop`.

## Beacon: the `decoupled` fork

*(in progress)*

### Validator client (`crates/validator/src/decoupled.rs`)

At decoupled slots the VC makes no LMD attestation or aggregate. It runs:

| Duty | Who | When | Beacon node endpoints |
|---|---|---|---|
| Goldfish vote | validators with an attester duty in the slot (`𝒦_s`) | `t_s + Δ` (2500 bps) | `GET /eth/v1/validator/decoupled/goldfish_vote_data`, `POST /eth/v1/beacon/pool/goldfish_votes` |
| Combined attestation | every active validator, when `slot % R == 1` | `a_r`, 5000 bps into the round's second slot | `GET /eth/v1/validator/decoupled/attestation_input`, `POST /eth/v1/beacon/pool/combined_attestations` |

Proposals use `produceBlockV3` as before; the node names `decoupled`.

The anti-slashing record Λ is `ethlambda_decoupled::Record`, one per
validator pubkey, at `<validators-dir>/decoupled/<0xpubkey>.json` with the last
slot voted and the last round attested. Every change is written (tmp file,
fsync, rename) before the signature it licenses exists; a record that does not
parse makes that validator refuse to sign rather than reset. The VC never
re-implements the pair rules: `Record::create_attestation` decides them from the
node's `AttestationInput`.
