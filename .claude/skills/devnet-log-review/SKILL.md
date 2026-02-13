---
name: devnet-log-review
description: Review and analyze devnet run results. Use when users want to (1) Analyze devnet logs for errors and warnings, (2) Generate a summary of a devnet run, (3) Identify interoperability issues between clients, (4) Understand consensus progress and block production, (5) Debug forks and finalization issues.
---

# Devnet Log Review

Analyze and summarize devnet run results from lean consensus testing.

## Quick Start

**Run the analysis script:**
```bash
# From project root (with logs in current directory)
.claude/skills/devnet-log-review/scripts/analyze-logs.sh

# Or specify logs directory
.claude/skills/devnet-log-review/scripts/analyze-logs.sh /path/to/logs
```

This produces a structured summary with:
- Error/warning counts per node
- Block production statistics
- Consensus progress
- Proposer assignments

## Log File Locations

| File | Content |
|------|---------|
| `devnet.log` | Combined output from `spin-node.sh` (genesis generation + all node output) |
| `{client}_{n}.log` | Individual node logs (e.g., `zeam_0.log`, `ream_0.log`, `ethlambda_0.log`) |

## Analysis Scripts

| Script | Description |
|--------|-------------|
| `analyze-logs.sh [dir]` | Main entry point - runs all analyses, outputs markdown summary |
| `count-errors-warnings.sh [dir]` | Count errors/warnings per node (excludes benign patterns) |
| `count-blocks.sh [dir]` | Count blocks proposed/processed per node (client-aware) |
| `check-consensus-progress.sh [dir]` | Show last slot reached and proposer assignments |
| `show-errors.sh [-n node] [-l limit] [-w] [dir]` | Display error details for investigation |

**Usage examples:**
```bash
# Just count errors/warnings
.claude/skills/devnet-log-review/scripts/count-errors-warnings.sh

# Show errors for specific node
.claude/skills/devnet-log-review/scripts/show-errors.sh -n zeam_0

# Show errors and warnings with limit
.claude/skills/devnet-log-review/scripts/show-errors.sh -w -l 50
```

## Common Investigation Patterns

### Tracing Slot-by-Slot Flow

When investigating issues, trace the complete flow for a specific slot using structured logging fields (`slot=X`).

**Note:** Logs contain ANSI color codes. Strip them first:

```bash
# Strip ANSI codes and grep for a specific slot
sed 's/\x1b\[[0-9;]*m//g' devnet.log | grep -E "slot=3[^0-9]|slot=3$"

# For double-digit slots
sed 's/\x1b\[[0-9;]*m//g' devnet.log | grep -E "slot=12[^0-9]|slot=12$"
```

Structured logging fields follow `key=value` format:
- `slot=N` - Slot number
- `validator_id=N` - Validator index
- `validator=N` - Validator index (in gossipsub messages)
- `proposer=N` - Block proposer index
- `err=...` - Error message

### Comparing Clients at Specific Slots

```bash
# Extract block hashes for specific slots across all clients
for slot in 1 2 3 4 5; do
  echo "=== Slot $slot ==="
  grep -h "slot=$slot[^0-9]\|@ $slot[^0-9]" *.log | grep -oE "0x[a-f0-9]{8}" | sort -u
done

# Check which client has which head at a specific slot
grep -h "head_slot=18\|Head Slot: 18" *.log

# Compare finalization across clients
grep -h "finalized.*slot\|Finalized block.*@" *.log | tail -20
```

### Finding Validators

Each validator proposes blocks when `slot % validator_count == validator_id`.

```bash
# ethlambda - explicit validator_id in logs
grep "We are the proposer" ethlambda_0.log | head -3
# Output: We are the proposer for this slot slot=5 validator_id=5

# zeam - proposer field in attestation logs
grep "packing proposer attestation" zeam_0.log | head -3
# Output: packing proposer attestation for slot=6 proposer=0

# Generic approach - validator_id = slot % validator_count
```

## Analysis Areas

### Fork Analysis

When clients disagree on which blocks are valid, the network splits into forks.

**Quick check for forks:**
```bash
# Compare block hashes at same slot across clients
grep -h "slot=4[^0-9]" *.log | grep -oE "block_root=0x[a-f0-9]{16}" | sort -u

# If you see different hashes → fork exists!
```

**Identifying rejected blocks:**
```bash
# Check signature verification failures
grep -i "signature.*failed\|invalid signature" *.log | head -20

# ethlambda
grep "Failed to process block" ethlambda_0.log

# qlean
grep "Invalid signatures for block" qlean_0.log

# lantern
grep "signature verification failed" lantern_0.log
```

**See [references/FORK_ANALYSIS.md](references/FORK_ANALYSIS.md) for:**
- Understanding fork types (canonical, orphan, invalid)
- Tracing parent-child relationships
- Building fork structure diagrams
- Determining which validators are on which fork

### Finalization Debugging

Finalization should advance every 6-12 slots. If it stalls, investigate:

```bash
# Check finalization progress
grep "finalized_slot=" ethlambda_0.log | tail -20

# If finalized_slot stays same for 50+ slots → finalization stalled
```

**Finalization requires >2/3 supermajority:**
- 6 validators → need 5 votes minimum
- 9 validators → need 7 votes minimum

**See [references/FINALIZATION_DEBUG.md](references/FINALIZATION_DEBUG.md) for:**
- Common causes of finalization stalls
- Validator participation calculations
- Justification chain analysis
- Step-by-step debugging guide

### Error Classification

**See [references/ERROR_CLASSIFICATION.md](references/ERROR_CLASSIFICATION.md) for:**
- Critical errors (genesis mismatch, panics, database corruption)
- Expected/benign messages (TODOs, HandshakeTimedOut to unconfigured nodes)
- Medium severity issues (encoding mismatches, missing blocks)
- State transition errors

### Client Log Patterns

Different clients have different log formats and key patterns.

**See [references/CLIENT_LOG_PATTERNS.md](references/CLIENT_LOG_PATTERNS.md) for:**
- Log format for each client (zeam, ream, ethlambda, grandine, lantern, qlean)
- Key log patterns per client
- Block counting methods
- ANSI color code handling

## Block Proposal Flow (ethlambda)

A healthy block proposal follows this sequence:

1. `We are the proposer for this slot` - Node detects it's the proposer
2. `TODO precompute poseidons in parallel + SIMD` - XMSS aggregate proof starts
3. `packed_pcs_commit` - Proof commitment
4. `Logup data` - Logup protocol data
5. `AIR proof{table=poseidon16}` / `AIR proof{table=poseidon24}` - AIR proofs
6. `Published block` - Block successfully built and published
7. `Published block to gossipsub` - Block broadcast to network

## Summary Report Format

Generate concise summaries (20 lines or less) in this structure:

```markdown
## Devnet Log Summary

**Run:** {N} {client} nodes (`{image}`) | {M} slots ({range})

| Node | Validator | Blocks Proposed | Errors | Warnings | Status |
|------|-----------|-----------------|--------|----------|--------|
| {node_name} | {id} | {count} (slots {list}) | {n} | {n} | {emoji} |

**Issues:**
- {issue 1}
- {issue 2}

**{emoji} {RESULT}** - {one-line explanation}
```

### Status Emoji Guide

| Emoji | Meaning | When to Use |
|-------|---------|-------------|
| 🟢 | Healthy | No errors, blocks processed successfully |
| 🟡 | Warning | Minor issues but consensus working |
| 🔴 | Failed | Critical errors, consensus broken, or blocks failing validation |

### Result Line Examples

- `🟢 PASSED` - All nodes healthy, consensus achieved
- `🟡 PASSED WITH WARNINGS` - Consensus working but minor issues detected
- `🔴 FAILED` - Consensus broken: {reason}

### Key Rules

1. Keep summary under 20 lines
2. Use table for per-node status
3. Status should reflect whether that node's blocks pass validation (🔴 if not)
4. End with single-line result with emoji
5. Don't list "what's working" - focus on issues

## Manual Investigation Commands

Use these when scripts don't provide enough detail:

```bash
# Find which validators proposed blocks
grep -h "proposer\|We are the proposer" *.log | head -20

# Check peer connections
grep -h "peer connected\|Connection established" *.log | head -20

# Check attestations
grep -i "attestation" *.log | head -50

# Search for specific error patterns
grep -i "genesis mismatch\|panic\|fatal" *.log

# Track attestations to unknown blocks (indicates forks)
grep "Unknown.*block:" ethlambda_0.log | grep -oE "0x[a-f0-9]{64}" | sort | uniq -c | sort -rn

# Check which validators are on invalid fork
grep "rejected vote" lantern_0.log | grep -oE "validator=[0-9]+" | sort | uniq -c
```

## Detailed References

For in-depth analysis, see these specialized guides:

- **[FORK_ANALYSIS.md](references/FORK_ANALYSIS.md)** - Comprehensive guide to identifying and analyzing blockchain forks, tracing parent-child relationships, building fork structure diagrams, and determining consensus disagreements
- **[FINALIZATION_DEBUG.md](references/FINALIZATION_DEBUG.md)** - Debugging finalization stalls, validator participation calculations, justification chain analysis, and threshold math
- **[CLIENT_LOG_PATTERNS.md](references/CLIENT_LOG_PATTERNS.md)** - Log formats and key patterns for all clients (zeam, ream, ethlambda, grandine, lantern, qlean), including block counting methods
- **[ERROR_CLASSIFICATION.md](references/ERROR_CLASSIFICATION.md)** - Error types, severity levels, expected vs. critical errors, and interoperability issues

## Progressive Disclosure

This skill uses progressive disclosure to keep context usage efficient:

1. **Start here** (SKILL.md) - Quick start workflow and common patterns
2. **Detailed references** (references/*.md) - Deep dives into specific analysis areas
3. **Scripts** (scripts/) - Automated analysis tools

Load detailed references only when needed for specific investigations.
