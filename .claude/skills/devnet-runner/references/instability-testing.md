# Testing Network Instability and Non-Finality

Simulate validator failures, observe consensus degradation, and measure recovery. Useful for benchmarking block processing under load, testing finalization stall behavior, and validating fixes like parallel signature verification.

## Overview

The lean consensus protocol requires a supermajority (3 out of 4 validators in a 4-node devnet) to justify and finalize slots. Pausing containers with `docker pause` simulates sudden validator failures without destroying state, allowing clean recovery with `docker unpause`.

## Prerequisites

- A running devnet (local or long-lived) with 4 ethlambda nodes
- Know which node is the aggregator (`--is-aggregator` flag, typically `ethlambda_3`)
- The aggregator must remain running, since it aggregates attestation signatures into proofs

## Quick Start: Induce Non-Finality

```bash
# 1. Verify all nodes are healthy
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep ethlambda

# 2. Pause 2 non-aggregator nodes (causes loss of supermajority)
docker pause ethlambda_0 ethlambda_1

# 3. Verify they're paused
docker inspect ethlambda_0 --format '{{.State.Paused}}'
# Should output: true

# 4. Observe: finalization stalls, attestation backlog accumulates
docker logs --tail 20 ethlambda_2 2>&1 | sed 's/\x1b\[[0-9;]*m//g'

# 5. Recover: unpause both nodes
docker unpause ethlambda_0 ethlambda_1
```

## What Happens When You Pause 2 of 4 Nodes

### Immediate effects
- Block production continues from the 2 active validators (slots assigned to paused validators are missed)
- Attestation signatures from paused validators stop arriving
- The aggregator can only aggregate attestations from 2 validators

### Within ~20 slots
- Justification stalls (need 3/4 supermajority, only have 2/4)
- Finalized and justified slots stop advancing
- Attestation target falls behind the head (nodes vote for the last justified checkpoint)

### Steady state (50+ slots)
- Blocks carry up to 36 attestations (backlog from all prior slots)
- Block processing time increases proportionally with attestation count
- Target-to-head gap grows linearly (~1 slot per slot)

### Observable metrics

```bash
# Check finalization progress (should be stuck)
docker logs --tail 20 ethlambda_2 2>&1 | \
  sed 's/\x1b\[[0-9;]*m//g' | grep 'Fork Choice Tree' -A 6 | tail -8

# Check attestation target gap (should be growing)
docker logs ethlambda_2 2>&1 | \
  sed 's/\x1b\[[0-9;]*m//g' | grep 'Published attestation' | \
  sed 's/.*slot=\([0-9]*\).*target_slot=\([0-9]*\).*/\1 \2/' | \
  awk 'NF==2 {print "slot=" $1 " target=" $2 " gap=" $1-$2}' | tail -10
```

## Extracting Block Processing Data

Extract attestation count and block processing time from all nodes for analysis:

```bash
for c in ethlambda_0 ethlambda_1 ethlambda_2 ethlambda_3; do
  docker logs "$c" 2>&1 | sed "s/\x1b\[[0-9;]*m//g" | awk -v node="$c" '
NR==FNR {
    if (/Received block from gossip|Published block to gossipsub/) {
        match($0, /slot=[0-9]+/); s=substr($0, RSTART+5, RLENGTH-5)
        match($0, /attestation_count=[0-9]+/); a=substr($0, RSTART+18, RLENGTH-18)
        att[s]=a
    }
    next
}
function to_ms(raw) {
    if (index(raw, "ms") > 0) { gsub(/ms/, "", raw); return raw+0 }
    if (index(raw, "µs") > 0) { gsub(/µs/, "", raw); return (raw+0)/1000 }
    gsub(/s/, "", raw); return (raw+0)*1000
}
/Processed new block/ {
    match($0, /slot=[0-9]+/); s=substr($0, RSTART+5, RLENGTH-5)
    match($0, /block_total=[^ ]+/); bt_raw=substr($0, RSTART+12, RLENGTH-12)
    match($0, /sig_verification=[^ ]+/); sv_raw=substr($0, RSTART+17, RLENGTH-17)
    bt=to_ms(bt_raw); sv=to_ms(sv_raw)
    if (s in att) ac=att[s]; else ac=0
    print node "," s "," ac "," bt "," sv
}
' <(docker logs "$c" 2>&1 | sed "s/\x1b\[[0-9;]*m//g") \
  <(docker logs "$c" 2>&1 | sed "s/\x1b\[[0-9;]*m//g")
done > block_data.csv
```

Output CSV format: `node,slot,attestation_count,block_total_ms,sig_verification_ms`

**Important:** The `block_total` field uses mixed units (`ms` for milliseconds, `s` for seconds, `µs` for microseconds). The awk `to_ms` function above normalizes everything to milliseconds.

## Quick Stats from Extracted Data

```bash
# Max block processing time
awk -F',' '{if($4>max){max=$4; line=$0}} END{print "MAX:", line}' block_data.csv

# Post-pause stats (replace 50 with your pause slot)
PAUSE_SLOT=50
awk -F',' -v ps="$PAUSE_SLOT" '$2>ps {sum+=$4; n++; if($4>max)max=$4}
  END{print "Post-pause: n=" n " avg=" sum/n "ms max=" max "ms"}' block_data.csv

# Attestation count distribution
awk -F',' '{print $3}' block_data.csv | sort -n | uniq -c | sort -rn | head -10
```

## Test Scenarios

### Scenario 1: Measure Signature Verification Scaling

**Goal:** Measure how block processing time scales with attestation count.

1. Start a 4-node devnet, let it stabilize (~20 slots)
2. Record the pause slot: `PAUSE_SLOT=<current_slot>`
3. Pause 2 non-aggregator nodes
4. Wait for attestation backlog to build (100+ slots)
5. Extract data and plot attestation count vs block processing time
6. Unpause nodes, observe recovery

**Expected results (sequential verification):**
- Pre-pause: ~90ms median, 0-6 attestations per block
- Post-pause: ~1,400ms median, 36 attestations per block
- Linear relationship between attestation count and processing time

**Expected results (parallel verification with rayon):**
- Pre-pause: ~65ms median, 0-6 attestations per block
- Post-pause: ~290ms median, 36 attestations per block
- ~4.8x speedup on an 8-core machine

### Scenario 2: Finalization Stall and Recovery

**Goal:** Verify that finalization resumes after paused validators rejoin.

1. Start a 4-node devnet, wait for finalization to start advancing (slot ~10+)
2. Note the current finalized slot
3. Pause 2 nodes
4. Confirm finalization stalls (finalized slot stops advancing for 50+ slots)
5. Unpause both nodes simultaneously
6. Verify finalization resumes within ~20 slots

### Scenario 3: Aggregator Failure

**Goal:** Observe the effect of losing the aggregator.

1. Start a 4-node devnet, confirm blocks include aggregated attestations (`attestation_count > 0`)
2. Pause the aggregator (`ethlambda_3`)
3. Observe: blocks are produced with `attestation_count=0`, finalization stalls immediately
4. Unpause the aggregator
5. Verify aggregation resumes and finalization recovers

**Note:** This is more severe than pausing non-aggregators because no attestation proofs are produced at all, not just a supermajority loss.

## Important Notes

### docker pause vs docker stop

| | `docker pause` | `docker stop` |
|---|---|---|
| Process state | Frozen (SIGSTOP) | Terminated (SIGTERM) |
| Container state | Still "Up" | Exited |
| Data preserved | Yes | Yes (if volume-mounted) |
| Recovery | `docker unpause` (instant) | `docker start` (full restart, needs checkpoint sync) |
| Gossipsub mesh | Peers detect timeout after ~30s | Peers detect disconnect immediately |
| Use case | Simulate temporary network partition | Simulate node crash |

**Prefer `docker pause`** for instability testing because:
- Recovery is instant (no re-peering, no checkpoint sync needed)
- The paused node's state is exactly preserved
- Simulates a network partition more accurately than a crash

### Never pause the aggregator unless testing aggregator failure

Without the aggregator, blocks contain zero attestation proofs. This is a different failure mode than losing non-aggregator validators. For signature verification benchmarking, always keep the aggregator running.

### Supermajority thresholds

| Validators | Supermajority (3/4) | Max paused for finality |
|-----------|--------------------|-----------------------|
| 4         | 3                  | 1                     |
| 6         | 5                  | 1                     |
| 8         | 6                  | 2                     |
| 12        | 9                  | 3                     |

Pausing 2 of 4 nodes guarantees non-finality. Pausing 1 of 4 still allows finalization (3/4 supermajority met).
