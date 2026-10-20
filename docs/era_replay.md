# Era replay

`ethlambda replay-era` replays real chain history from `.era` files through the
Beacon Chain state transition. Era files carry every block of 8192 slots plus
the state at the end of them, so they are history that no node has to still
hold, unlike `benchmark import`, which reads a running node's Beacon API. The
command exists to catch state-transition divergences on real data across every
fork, including the upgrade itself.

## What a run checks

For era `N`, file `N` holds the blocks of slots `[(N-1)*8192, N*8192)` and the
state at slot `N*8192`. The command decodes the state stored in file `N-1`,
then applies each block of file `N` in slot order with
`stf::state_transition(.., validate_result = true, ..)` and one `CommitteeCache`
for the whole run:

| Check | Where |
|---|---|
| Proposer signature, randao, attestations, sync aggregate, deposits, exits | every block, always on |
| Block `state_root` equals the post-state's root | every block |
| Block root equals `block_roots[slot % 8192]` of the stored end state | after the era |
| `state_roots[N*8192 - 1]` of the stored state equals our state's root at the last slot before the boundary | after the era |
| Our full state root at `N*8192` equals the stored state's | after the era, only when slot `N*8192` is empty |

The execution payload is not run: the engine answers `valid`, so structural
payload checks (parent hash, `prev_randao`, timestamp, commitment limit) run and
the EL verdict does not.

### The block at the end slot

An era state is the state with the block at its own slot applied, and that
block is stored in the next file. Two consequences: a starting state may
already contain the first block of file `N` (blocks at or below the state's slot
are skipped and counted as `blocks_already_in_state`), and the closing state
may include a block we do not have. The `state_roots` check needs nothing from
file `N+1`, which is why it is the primary end-of-era check; the full-state
comparison runs only when the stored state's `latest_block_header` is older than
`N*8192`, i.e. the slot is empty.

### Chaining and fork upgrades

Consecutive `--era` values continue from the same in-memory state without
re-decoding. A fork upgrade is exercised by our own `process_slots`: replaying
era 1607 (mainnet) from file 1606's electra state, advancing to slot
`1607*8192` runs the fulu upgrade, and the result is compared with the fulu state
stored in file 1607 when that slot is empty. Era 1608 then applies the first
fulu blocks. A non-consecutive era starts fresh from its predecessor's file.

Fork files are `F = fork_epoch / 256`. File `F` holds the **last pre-fork**
blocks (slots up to the fork epoch), and the upgrade happens in our closing
`process_slots`, so replaying `F` exercises the upgrade at the very end. The
first post-fork blocks are in file `F+1`, which is why CI chains `F+F+1`:

| Network | altair | bellatrix | capella | deneb | electra | fulu | gloas |
|---|---|---|---|---|---|---|---|
| mainnet | 290 (not in CI, see Known limits) | 566 | 758 | 1053 | 1422 | 1607 | n/a |
| sepolia | in era 0 | in era 0 | 222 | 518 | 869 | 1065 | 1379 |
| hoodi | genesis | genesis | genesis | genesis | 8 | 198 | n/a |

An era whose closing state is at or past a fork this build cannot process
(Sepolia gloas, era 1379 and later) is refused up front with the last
replayable era named. The check reads `GLOAS_FORK_EPOCH` from the network's
`config.yaml`, which `Config` itself drops.

## Command line

```
ethlambda replay-era --network <mainnet|sepolia|hoodi|dir> --era-dir <dir> \
    --era <N> [--era <N2> ...] [--download] [--max-blocks K] [--report <path.json>]
```

| Flag | Meaning |
|---|---|
| `--network` | Resolved like `beacon`'s: a built-in name or a directory of published files. Its `CONFIG_NAME` names the era files and the host |
| `--era-dir` | Where `<config-name>-<NNNNN>-<8 hex>.era` files are read from and downloaded to |
| `--era` | Repeatable. A number, or `latest` (newest era the host lists; needs `--download`) |
| `--download` | Fetch missing files from `https://<network>.era.nimbus.team/`, matching the `<network>-<NNNNN>-` prefix in the index page. Written to `.part`, renamed on success |
| `--max-blocks` | Smoke mode: stop the era after K applied blocks. Per-block checks still run; the end-of-era checks are skipped and reported as `skipped`. Takes a single `--era`; combining it with several is a CLI error, since a smoke run stops mid-era and cannot chain |
| `--report` | JSON array with one entry per era: network, era, `blocks_applied`, `blocks_already_in_state`, `skipped_empty_slots`, `elapsed_secs`, `apply_secs`, `mean_ms_per_block`, the oracle checks with their outcome, and `error` |

Every era needs two files, its own and its predecessor's: about 1.5 GB for a
recent mainnet era. The command logs one line per era start and end and a
progress line every 512 blocks, and exits non-zero on any failure, after
writing the report. A mismatch names the era, slot, expected and actual roots.

The e2store reader (`bin/ethlambda/src/era/e2store.rs`) reads the trailing slot
indices first and then seeks to single records, so a file is never held in memory
whole; only the one state being decoded is.

## CI

`.github/workflows/era_replay.yml` runs on pushes to `main` that touch the
state transition, the types, the ssz-tree or the era module, and on manual
dispatch. It builds nothing: it waits for `docker_publish.yaml`'s
`ghcr.io/lambdaclass/ethlambda:sha-<7>` tag and runs `replay-era` in it, one job
per entry:

| Network | Entries |
|---|---|
| mainnet | 566, 758, 1053, 1422, 1607+1608, latest (full eras) |
| sepolia | 222, 518, 869, 1065+1066, 1378 (full eras) |
| hoodi | 8, 198+199, latest (full eras, need the #648 cache, see Known limits) |

Hoodi era 8 is the last deneb blocks, with the electra upgrade (epoch 2048) in
our closing `process_slots`; `198+199` is the fulu upgrade (epoch 50688) plus
the first fulu era.

Each job uploads its `report.json`; a failed push run posts the commit, the
failing entries and the run URL to Slack. Manual dispatch takes an `image` and
an `eras` override of space-separated `network:era[+era...][@K]` entries, where
`@K` adds `--max-blocks K` (single era only), e.g.
`mainnet:290 hoodi:199 hoodi:9@512`.

## Known limits

- **Phase0 is quadratic.** Mainnet era 290 is excluded from the matrix, see
  "Phase0 eras are not practical yet" below. The override can still request it.
- **Full Hoodi eras depend on #648.** Without the per-epoch
  total-active-balance cache from #648, a deneb-era block costs about 4.6 s
  against 0.65 s on mainnet, because `get_base_reward_per_increment` scans the
  whole registry once per attestation (`stf/deneb.rs:359`,
  `stf/electra.rs:764`). A full era would then exceed the job limit.
- **Smoke runs do not cross fork boundaries.** A `--max-blocks` run stops
  mid-era, so it never reaches the closing `process_slots` where the upgrade
  runs, and it skips the end-of-era checks. The CI matrix has no smoke entries;
  they are available through the `eras` override (`@K`).

## Measured runtimes

Measured on an Apple-silicon laptop with the `release-fast` binary, one core
busy (`mean ms/block` covers block decode, the state transition and epoch
processing; downloads and the end-of-era checks are excluded):

| Run | Result |
|---|---|
| Sepolia era 1, full (7627 blocks, crosses altair and bellatrix) | 116 s, 15.2 ms/block, all three end-of-era checks as below |
| Sepolia eras 2+3+4, chained | about 120 s each, 15 ms/block, `state_roots` and `block_roots` passed; `Continuing from the previous era's in-memory state` logged |
| Sepolia era 31, full (slot 253952 empty) | 108 s, 15.9 ms/block, `state_roots`, `block_roots` and `full_state_root` all passed |
| Mainnet era 1888 (latest, fulu blocks), `--max-blocks 64` | 653 ms/block, every proposer signature and `state_root` passed; 1.5 GB download in about 2 min |
| Hoodi era 8, `--max-blocks 256` | 4.6 s/block (1178 s; a second replay was running on the machine) |

A full recent era is 8192 blocks, so mainnet at 0.65 s/block is about 90 minutes
and Hoodi at 4.6 s/block is about 10 hours: a full Hoodi era does not fit the
330 minute job limit of a hosted runner at that speed, which is why the matrix
relies on #648.

### Phase0 eras are not practical yet

The beacon STF's phase0 epoch processing is quadratic in the validator count:
`get_base_reward` calls `get_total_active_balance`, which walks the whole
registry, once per validator per reward component
(`stf/epoch/rewards.rs`). Mainnet era 2 (about 20k validators) spends roughly
30 s per epoch boundary, 512 blocks in 484 s, and mainnet era 290 (about 280k
validators) did not finish its first epoch boundary in 30 minutes. Phase0 eras
past the first few hundred need that total hoisted out of the per-validator
loop first; the spec fixtures are far too small to show it. Eras from altair
on do not have the problem.

The end-of-era checks, as observed on real files: slot `N*8192` held a block in
every boundary checked except era 31 on Sepolia, so `full_state_root` is usually
skipped and `state_roots[last slot]` plus `block_roots` carry the check.

### File format notes

Verified against real nimbus files: the slot index marks an empty slot by
pointing at byte 0 (the Version record) rather than by offset 0 as the
specification says, so both are read as empty. Block and state records are
snappy framed; offsets are relative to the index record's own start.
