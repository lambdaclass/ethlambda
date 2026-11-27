# PQ timing export

On a network that schedules the PQ fork, `ethlambda beacon --pq-timing-output
<DIR>` records when PQ attestations and aggregates reach the node, what
validation makes of them, and every attestation proof the node makes, as
events in a local directory.

The format is the one the PQ devnets' clients share: schema 1 of Lighthouse's
[`scripts/pq-measurement`](https://github.com/sigp/lighthouse/tree/pq-devnet-1/scripts/pq-measurement),
which Prysm, Teku and Lodestar write too. One report script then draws every
client's runs side by side, which is how the devnets compare aggregation
timings between clients. The Prometheus metrics in
[metrics.md](./metrics.md#pq-aggregation-timing) answer the same questions as
distributions; this export keeps each event.

## Recording a run

```sh
ethlambda beacon --network /path/to/devnet --pq-timing-output /data/pq-timing ...
```

Each start creates one run directory under it, named
`<start time in ns>-<16 hex digits>`, and logs it as `Recording PQ timing`.
The flag is off by default, a directory that cannot be created is a startup
error, and on a network that does not schedule PQ the flag only logs a warning.

Stop the node normally (`SIGTERM` or ctrl+c) and the run is finished: its last
chunk is closed and listed in `run.json`, which gets an `ended_unix_ns`. A node
that is killed leaves its last chunk as `events-NNNNNN.jsonl.zst.partial`,
which no manifest lists; it is flushed every 10 seconds, so it still decodes up
to its last flush.

## Reading a run

Lighthouse's report script reads a run directory as it is:

```sh
python3 -m pip install 'matplotlib>=3.10,<4' 'zstandard>=0.20,<1'
python3 scripts/pq-measurement/plot.py /data/pq-timing/<run> --output reports
```

It needs Python 3.10 or newer. A chunk is also readable by hand:
`zstd -dc events-000001.jsonl.zst | jq .`

## The run directory

| File | What it is |
|---|---|
| `run.json` | The manifest, rewritten whole whenever a chunk is finished and every 10 seconds |
| `events-NNNNNN.jsonl.zst` | A finished chunk: zstd-compressed JSON lines, one event each |
| `events-NNNNNN.jsonl.zst.partial` | The chunk being written |

A chunk is finished after 64 MiB of events (before compression) or five
minutes. A run keeps at most 8 GiB of finished chunks: past that the oldest
are removed, and `recorder_status` says how many and which events they held.

`run.json` holds:

- **What ran**: `schema_version` (1), `run_id`, `client` (`ethlambda`),
  `ethlambda_version`, `network`, `genesis_time`, `genesis_slot`,
  `genesis_validators_root`, `started_unix_ns`, `ended_unix_ns`, and
  `observer` (always `false`: every event is this node's own workload).
- **The prover**: `prover_backend`, `leanvm_revision`,
  `leanvm_protocol_version`, `prover_log_inv_rate`, `prover_threads` (null
  when `--pq-prover-threads` left the count to leanVM) and
  `prover_threads_configured`. `prover_cpu_profile` is null, since leanVM
  picks its CPU tier itself; `prover_cpu_profile_requested` is `LEANVM_TIER`
  when that is set.
- **`hardware`**: architecture, operating system, kernel, CPU model, cores,
  CPU affinity and memory, and the cgroup's CPU quota and memory limit, so a
  container reports what it was given. Read from `/proc` and the cgroup v2
  tree: off Linux most of it is null.
- **`timing`**: where in a slot this node does each step, in nanoseconds from
  the start of the vote's slot. A report draws its reference lines there.
- **`receive_point`**: where a receipt is stamped (see `message_received`).
- **`chunks`**: the finished chunks, each with its name, size and the first
  and last sequence numbers it holds. A reader takes the events from these.
- **`recorder_status`**: events submitted, events dropped by class, chunks
  removed, and whether a write failed (after which the export stops).

`timing` on a 12-second slot:

| Key | Value | What happens then |
|---|---|---|
| `slot_ns` | 12 s | |
| `attestation_ns` | 3 s | Attestations are due |
| `committee_collection_ns` | 4.8 s | The first aggregator seat stops collecting and proves |
| `aggregator_delay_ns` | 0.6 s | Each following seat does so this much later |
| `aggregate_ns` | 7.2 s | The first seat broadcasts |
| `initial_merge_ns` | 20 s | The merge ahead of the block two slots later starts |
| `proposal_lag_slots` | 2 | A block's newest votes are two slots old |

## Events

Every line has `seq` (the order events were submitted in), `kind`, `wall_ns`
(UNIX time) and `mono_ns` (a monotonic clock, from the run's start), and
`reference_slot`: the slot of the votes the event is about, which is what a
report places it on a timeline by.

| `kind` | When | Fields of its own |
|---|---|---|
| `message_received` | A PQ attestation or aggregate arrived from gossip | `message_kind` (`individual`, `aggregate`), `message_id`, `source` (`network`), `slot`, `committee`, `subnet`, `message_bytes`, `byte_basis` (`decoded_ssz`), `signer_count`, `vote_data_root` |
| `validated` | That message got its verdict | `message_kind`, `message_id`, `outcome`, `receipt_to_validation_ns` |
| `proof_started` | leanVM is about to be called | the job's fields, `queue_wait_ns`, and the proof's inputs |
| `proof_finished` | It returned | the job's fields, `outcome` (`success`, `failed`), `backend_duration_ns`, `late`, `proof_bytes`, `proof_id` |
| `candidate_ready` | The proof is where its consumer takes it from | the job's fields, `proof_id` |
| `job_outcome` | A proof that was due was not made | the job's fields, `outcome` |
| `proposal_snapshot` | Block production took what it has for the block | `outcome` (`candidate`, `no_candidate`), `sequence_id`, `proof_id`, `proof_bytes`, `records`, `packed_ahead` |

**Receipts.** `message_received` is stamped when gossipsub delivered the
message: before Snappy decompression and SSZ decode, and after gossipsub's
duplicate cache, so each message is received once. It is recorded for every
vote that decodes, whatever validation then decides. This node's own
attestations and aggregates are not in the export: gossip never hands a node
its messages back.

**Verdicts.** `outcome` is `accepted`, `rejected`, `ignored`, `duplicate` (the
node had already seen the vote, or an accepted aggregate covers its bits) or
`queue_dropped` (no validation permit was free). A single attestation for a
block still being imported waits for it and gets its verdict then, so its
`receipt_to_validation_ns` includes that wait.

**Jobs.** The proof events share the fields of the job they belong to:
`job_id`, `work`, `round`, `slot`, `reference_slot`, `origin` (`production`),
`scenario` (`production`), `sequence_id` (`production:<slot>`) and
`enqueued_wall_ns`. `work` is what the proof is of:

| `work` | `round` | The proof | `slot` | `reference_slot` |
|---|---|---|---|---|
| `committee` | 1 | One committee's signatures, for an aggregator seat of this node | the votes' | the same |
| `initial` | 1 | A block's attestation proofs merged ahead of its slot | the block's | two slots before |
| `improvement` | 2 | The same at block production, when the merge ahead cannot be used | the block's | two slots before |

A committee job's events also carry `committee`, `aggregator_position` (the
seat) and `signatures`, and its two proof events `committee_size`. A merge's
proof events carry `input_proof_count`, `records` (attestations) and `claims`
(signatures).

- **`queue_wait_ns`**: for a committee, the time since its seat's cutoff, so a
  seat's second committee waits for its first; for a merge, the wait for the
  one merge permit and a blocking thread.
- **`backend_duration_ns`**: the call into leanVM, which includes any wait for
  a proof it was already making: it makes one at a time.
- **`late`**: a committee proof finished after its seat's broadcast time (it
  is discarded), or a merge outlived its budget (the block packs one
  committee's attestation).
- **`proof_id`**: the SHA-256 of the proof, which follows a proof from the job
  that made it to the snapshot of the block that carries it. No proof or
  signature is exported.
- **`candidate_ready`**: a committee's aggregate is in the pool the validator
  client's `aggregate_attestation` reads, or a block's packing is complete.
  `backend_call` is `false` for a packing of one proof, which is the block's
  as it is and makes no proof event.
- **`job_outcome`**: `already_proven` (an earlier seat of this node proved
  every vote collected), `unproved` (the seat's time ran out first), or
  `skipped` (a merge with no time left, or with another merge holding
  leanVM; its `reason` says which).

## What it costs

Nothing is built for a node that does not record: each emitter returns after
one atomic load. For one that does, an event is a JSON object pushed onto a
queue of 16,384; a writer thread serializes, compresses and writes. A full
queue drops the event and never waits: the drop is counted in
`recorder_status.dropped` and in `lean_beacon_pq_timing_dropped_events_total`.

## What is not recorded

- **An observer mode.** The other clients' `--pq-measurement` makes a node
  without validators prove what the network sends, every third slot, and
  publish nothing. ethlambda records only its real workload, so a node with no
  aggregators or proposers writes receipts and verdicts and no proof events.
- **`fallback` proofs.** Some clients prove a committee's raw signatures while
  packing a block. ethlambda's block production merges aggregates only, so it
  never emits that kind of work.
- **A later verdict of the same message.** Each message gets one `validated`
  event; none is `deferred`.
