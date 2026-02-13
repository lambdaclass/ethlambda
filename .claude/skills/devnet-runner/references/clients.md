# Client Reference

Supported lean consensus clients and their configurations.

## Supported Clients

| Client | Description |
|--------|-------------|
| zeam | Zig-based lean consensus client |
| ream | Rust-based lean consensus client |
| qlean | QEMU/Kagome lean implementation |
| lantern | PierTwo's lean consensus client |
| lighthouse | Rust Ethereum consensus client (lean fork) |
| grandine | High-performance consensus client |
| ethlambda | LambdaClass Rust implementation |

## Docker Images

Images are defined in `client-cmds/{client}-cmd.sh`. Edit the `node_docker` variable to change image/tag.

| Client | Default Image |
|--------|---------------|
| zeam | `blockblaz/zeam:devnet1` |
| ream | `ghcr.io/reamlabs/ream:latest` |
| qlean | `qdrvm/qlean-mini:3a96a1f` |
| lantern | `piertwo/lantern:v0.0.1` |
| lighthouse | `hopinheimer/lighthouse:latest` |
| grandine | `sifrai/lean:unstable` |
| ethlambda | `ghcr.io/lambdaclass/ethlambda:local` |

## Default Ports

Ports are configured per-node in `validator-config.yaml`. Typical port assignments:

| Node | QUIC Port | Metrics Port |
|------|-----------|--------------|
| *_0 | 9001 | 8081 |
| *_1 | 9002 | 8082 |
| *_2 | 9003 | 8083 |

**Note:** Adjust ports to avoid conflicts when running multiple nodes.

## Client-Specific Configuration Notes

### zeam

- Image: `blockblaz/zeam:devnet1`
- Native Zig implementation
- Command file: `client-cmds/zeam-cmd.sh`

### ream

- Image: `ghcr.io/reamlabs/ream:latest`
- Rust implementation by Ream Labs
- Command file: `client-cmds/ream-cmd.sh`

### qlean

- Image: `qdrvm/qlean-mini:3a96a1f`
- Uses specific commit hash for stability
- Command file: `client-cmds/qlean-cmd.sh`

### lantern

- Image: `piertwo/lantern:v0.0.1`
- PierTwo implementation
- Command file: `client-cmds/lantern-cmd.sh`

### lighthouse

- Image: `hopinheimer/lighthouse:latest`
- Fork of the standard Rust Lighthouse client
- Command file: `client-cmds/lighthouse-cmd.sh`

### grandine

- Image: `sifrai/lean:unstable`
- High-performance client by Sifrai
- Command file: `client-cmds/grandine-cmd.sh`

### ethlambda

- Image: `ghcr.io/lambdaclass/ethlambda:local`
- Rust implementation by LambdaClass
- Command file: `client-cmds/ethlambda-cmd.sh`

## Changing Docker Images

To use a different image or tag:

1. **Temporary (single run):** Use `--tag` flag:
   ```bash
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0 --tag dev
   ```

2. **Permanent:** Edit `client-cmds/{client}-cmd.sh` and modify `node_docker`:
   ```bash
   node_docker="your-registry/image:tag"
   ```

## Known Issues & Compatibility

### zeam

| Issue | Image Tags Affected | Description |
|-------|---------------------|-------------|
| CLI flag change | devnet2+ | Uses `--api-port` instead of `--metrics_port` for metrics endpoint |
| XMSS prover crash | devnet2 | Missing prover setup files cause panic when producing blocks with signature aggregation |
| Block format incompatibility | devnet2 ↔ ethlambda:local | Cannot deserialize blocks from ethlambda - OutOfMemory error |

### ethlambda

| Issue | Image Tags Affected | Description |
|-------|---------------------|-------------|
| Manifest unknown warning | local | Docker shows "manifest unknown" but falls back to local image - can be ignored |
| NoPeersSubscribedToTopic | all | Expected warning when no peers are connected to gossipsub topics |

## Environment Variables Available to Clients

These are set by `spin-node.sh` and available in client command scripts:

| Variable | Description |
|----------|-------------|
| `$item` | Node name (e.g., `zeam_0`) |
| `$configDir` | Genesis config directory path |
| `$dataDir` | Data directory path |
| `$quicPort` | QUIC port from config |
| `$metricsPort` | Metrics port from config |
| `$privkey` | P2P private key |
