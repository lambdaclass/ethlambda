# Engine API integration demo

Runs one **ethlambda** consensus node paired with one **ethrex** execution node
over the Engine API. Every slot, ethlambda builds a block, asks ethrex to
produce the execution payload (`engine_forkchoiceUpdatedV3` + `getPayloadV4`),
embeds it in the Lean block, and ethrex imports it (`newPayloadV4`). The chain
advances and finalizes on both layers.

Single validator → finalizes solo. Good for a quick local demo.

## Prerequisites

- **ethrex** on `PATH` (v15+), or `ETHREX=/path/to/ethrex`.
- A **dual-key (devnet5+) lean genesis bundle**. By default the script looks in
  `lean-quickstart/local-devnet/genesis`. Generate one with:
  ```bash
  cd lean-quickstart && ./generate-genesis.sh local-devnet/genesis
  ```
  (needs the lean-quickstart `main` branch and Docker). To pay block rewards to
  a real address, add to `validator-config.yaml`'s `config` block:
  ```yaml
  suggested_fee_recipient: "0x00000000000000000000000000000000deadbeef"
  ```
- `cargo` (the script builds `ethlambda` in release) unless `SKIP_BUILD=1`.
- `jq` (optional, for the demo commands below).

## Usage

```bash
scripts/engine-api-demo/run.sh          # build + start ethrex and ethlambda
scripts/engine-api-demo/run.sh stop     # stop both
```

Configurable via env vars (see the header of `run.sh`): `ETHREX`,
`LEAN_GENESIS_DIR`, `DATA_DIR`, `GENESIS_OFFSET`, the four ports, `SKIP_BUILD`.

## What to show

1. **EL importing CL-built payloads** — chain climbing, `miner` = the configured
   `suggested_fee_recipient`:
   ```bash
   curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
     --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}' \
     | jq '.result | {number, hash, miner}'
   ```
2. **ethlambda fork-choice tree** (browser): <http://127.0.0.1:5052/lean/v0/fork_choice/ui>
3. **Both layers in lockstep**:
   ```bash
   tail -f "$DATA_DIR/ethlambda.log" | grep -E 'proposer|finalized|head updated'
   tail -f "$DATA_DIR/ethrex.log"    | grep -E 'BLOCK|executed|Fork choice'
   ```

The round-trip invariant: ethrex's FCU `head` equals ethlambda's
`block.body.execution_payload.block_hash`.

## Files

| File | Purpose |
|---|---|
| `run.sh` | Orchestrator (`run` / `stop`); reads the EL genesis hash from ethrex's log, so nothing is hardcoded. |
| `genesis-el.json` | Execution-layer genesis: chainId 9, Shanghai/Cancun/Prague @0 (pre-Amsterdam → no EIP-7928 block-access-list), Prague system contracts only. |

## Notes

- **Fork level.** ethlambda pins the **V4 (Prague)** Engine methods — the
  pre-Amsterdam, no-BAL path. Current ethrex's `newPayloadV5` requires the
  EIP-7928 block-access-list (Amsterdam, off by default), so the EL genesis here
  stops at Prague. Fork-aware version selection (and V5/BAL support) is a future
  refinement.
- `run.sh` re-stamps `GENESIS_TIME` in the lean `config.yaml` on each run.
- Logs and data live under `DATA_DIR` (default `$TMPDIR/ethlambda-el-demo`).
