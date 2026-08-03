---
name: multi-server-devnet
description: This skill should be used for managing long-lived lean-consensus devnets that run as detached docker containers on remote hosts — the current setup is one INDEPENDENT single-host devnet per server, federated into one Grafana. Works for any server names and any number of servers/nodes. Trigger when the user asks to "start/reset the devnet(s)", "start a devnet on <server>", "restart the devnet", "rolling restart", "recover stalled nodes", "the devnet stopped finalizing", "investigate the finality stall", "convert nodes to zeam/ream/qlean/grandine/gean/lantern", "multi-client devnet", "add a client to the devnet", "canary a new client/build", "scale the devnet / add a node", "set up grafana/prometheus for the devnets", "pull the latest image on the servers", or "add swap / memory limits to the servers". Distinct from the local single-host `devnet-runner` skill.
version: 0.2.0
---

# Multi-Server Devnet

Operate lean-consensus devnets that run as detached containers
(`docker run -d --restart unless-stopped --network host`) on remote hosts,
surviving SSH disconnects and reboots. This is NOT the local `devnet-runner`
(spin-node.sh) workflow — these are hand-managed detached containers.

## Topology model: one independent devnet per server

The current setup runs **one self-contained devnet per server** — each its own
chain (own genesis, own GENESIS_TIME, own fork-choice, own finality), with no
cross-server peering. They are kept apart by pointing **every ENR at
`127.0.0.1`**, so a node only ever discovers peers on its own host even though
all devnets share the dummy fork digest. One central Grafana/Prometheus
federates all of them, labelled per devnet.

Nothing about the servers is hardcoded. Establish these from the operator:

- `SERVERS` — the SSH targets (any count, any names), one devnet each.
- `SSH_USER` — login user. `docker` is invoked with `sudo`.
- Per-devnet `NODES` (validators on that server) and `SUBNETS`
  (`ATTESTATION_COMMITTEE_COUNT`); these can differ between servers.
- A central host for Grafana + the federating Prometheus (often one of the
  servers); each server's per-host Prometheus remote-writes to it.

Put those values in `scripts/devnet.env` (copy `scripts/devnet.env.example`;
gitignored) instead of retyping them: the operator-side scripts source it via
`scripts/devnet-env.sh`, and an env var exported in the shell still wins over the
file. It is the one place a deployment's hosts, urls, and Grafana ids live.

Per devnet, node `n` (0 ≤ n < NODES) on its host:

- ports: gossip `9000+n`, api `5052+n`, metrics `9200+n` (n is the only index —
  no cross-host BASE offset; each devnet starts numbering at 0).
- **Three-layer naming:**
  - **identity** `node_n` — node-id, `node_n.key`, data-dir, genesis validator
    name; client-agnostic, all genesis artifacts key off it.
  - **container/display** `<client>_n` (e.g. `zeam_8`, `ethlambda_0`) — the docker
    `--name`, and hence cAdvisor's `name` label and promtail's `node` label, so
    Grafana shows the client at a glance. `client_type` is derived from this prefix.
  - **index** `n` — the ports above.
- attests on subnet `n % SUBNETS`.
- genesis dir `/opt/lean-quickstart/genesis` → `/config`, data
  `/opt/lean-quickstart/data/node_n` → `/data`.
- management scripts address a node by index: they find its container via the
  `_n$` name suffix (client prefix may differ), so conversions never rename data
  or node identity.

**Aggregators:** one per subnet — nodes `0 .. SUBNETS-1`, where node `k`
aggregates subnet `k` (`--aggregate-subnet-ids k`). leanVM aggregation is
CPU-heavy, so keep one aggregator per subnet, no more.

**Finality threshold is per devnet:** `ceil(2/3 · NODES)` aligned votes on that
server. Every restart/conversion decision hinges on staying above it for that
devnet only — one server's chain stalling never affects another's.

## Golden rules (each learned from an outage)

1. **Always pass a checkpoint-sync URL on restart:**
   `--checkpoint-sync-url http://127.0.0.1:<healthy-same-devnet-api>/lean/v0/states/finalized`.
   Current images then prefer resuming from the on-disk DB when it's fresh
   (head within `MAX_RESUMABLE_DB_STATE_AGE` slots of wall clock,
   `bin/ethlambda/src/main.rs`) and fall back to checkpoint sync when stale —
   but only if a URL is provided; without one the node re-inits from genesis.
   On older images keep-DB resume panics the consensus actor (`"safe target
   exists"`: process stays up, consensus stops), so wipe-data + checkpoint sync
   remains the safe default and is what `cs-restart.sh` does.
2. **Wait 60s between stopping and starting a running node.** Skipping the
   gossipsub backoff leaves the node out of the attestation meshes — it attests
   but aggregators never hear it, so the vote count stays below threshold and
   finality stalls. Restart one node at a time per devnet; servers in parallel.
3. **One GENESIS_TIME per devnet, kept stable across that devnet's restarts.**
   Each server's chain has its OWN GENESIS_TIME (they deliberately differ).
   Within a devnet, a drifted value forks a node onto a private clock/chain and
   breaks checkpoint sync (`genesis time mismatch`). Regenerating genesis = a new
   chain; restarting nodes must reuse the on-disk value.
4. **Keep the memory guards.** A swapfile per host + per-container memory limits.
   Default every node to `--memory 8g --memory-swap 16g --memory-reservation 2g`
   (raise further for a client that legitimately needs it). A client leak (qlean
   leaks ~1.8 GiB/h) must OOM one container, not starve the whole host. With
   several devnets-per-fleet this matters more, not less — but here each host runs
   only its own devnet.

## Editing genesis / mass restarts needs care

Regenerating genesis or mass `rm -rf` of data dirs is destructive and may be
permission-gated — state the exact scope and let the user confirm. Never invent
a `GENESIS_TIME`; derive it (`now + offset`) at generation or read the live
chain's value. Save crash logs before `docker rm` when debugging a crash
(`sudo sh -c "docker logs X > /opt/lean-quickstart/crash-logs/X.log"` — the
redirect must run under sudo).

## Workflows

Examples assume `SSH_USER` is set and you iterate over `SERVERS`. Per server you
pass its own `NODES`/`SUBNETS`.

### Pull the latest images on all servers
```bash
for h in $SERVERS; do ssh "$SSH_USER@$h" 'sudo docker pull ghcr.io/lambdaclass/ethlambda:devnet5'; done
```
`devnet5` is the current devnet tag; it tracks the chain's leanVM/proof format,
so it (and the other clients' tags in `references/clients.md`) move together on a
bump. If a fresh build is pending, watch it: `gh run watch <id> --repo <repo> --exit-status`.

### Start a fresh devnet on a server (genesis is per-devnet)
Genesis is generated **per devnet on the operator machine** (each needs a
distinct genesis root + GENESIS_TIME), then shipped to the host. Then the host
launches its nodes.

**Order matters: GENESIS_TIME starts ticking mid-generation.** `generate-genesis.sh`
stamps `GENESIS_TIME = now + offset` *early* (before its per-validator loop), so every
step after that burns the countdown. Do the slow, chain-age-dependent teardown FIRST,
then generate, and the offset only has to cover ship + launch + mesh.

```bash
# 0. host-side FIRST (pre-stamp: this is the step that scales with chain age --
#    wiping 54 GB of RocksDB is not something to do against a running clock).
ssh "$SSH_USER@$h" 'N=$(sudo docker ps -aq --filter "name=_[0-9]*$")
  for c in $N; do sudo docker update --restart=no $c; done   # else it respawns
  [ -n "$N" ] && sudo docker rm -f $N
  sudo rm -rf /opt/lean-quickstart/data/node_*'

# 1. operator-side: build this devnet's genesis (127.0.0.1 ENRs, subnet=i%SUBNETS,
#    aggregators 0..SUBNETS-1). KEYS_DIR = canonical hash-sig keys; SRC_VCONFIG = a
#    validator-config holding privkeys for nodes 0..NODES-1.
bash scripts/make-genesis.sh OUTDIR NODES SUBNETS KEYS_DIR SRC_VCONFIG [GT_OFFSET]
#    More than one validator per node: set VALIDATORS_PER_NODE=V (KEYS_DIR must then
#    hold NODES*V key pairs). make-genesis.sh runs subnet-align-validators.py after
#    generate-genesis.sh so each node's validators all sit in ONE subnet -- see that
#    script for why the default contiguous assignment spreads them over every subnet.
#    Needs NODES % SUBNETS == 0. Aggregators stay one-per-subnet (node k -> subnet k).
#    GT_OFFSET defaults to 240s. Measured 2026-07-28, 32 nodes, one host: generation
#    after the stamp 13s (128 val) / 28s (256 val), ship+launch ~105s, mesh ~30s
#    => ~165s. Do NOT pad this to 600-900s "to be safe": that is 7-12 min of dead
#    wall clock per restart and it bought nothing. Raise it only for many hosts or
#    a slow link.

# 2. ship genesis dir to the host's /opt/lean-quickstart/genesis (tar over ssh):
(cd OUTDIR && tar cf - config.yaml genesis.json genesis.ssz nodes.yaml validators.yaml \
  annotated_validators.yaml validator-config.yaml *.key) | \
  ssh "$SSH_USER@$h" 'sudo find /opt/lean-quickstart/genesis -maxdepth 1 \( -name "node_*.key" -o -name "ethlambda_*.key" \) -delete; sudo tar xf - -C /opt/lean-quickstart/genesis'
#   hash-sig keys: sync the per-validator *.ssz once (servers usually hold only a
#   subset). Spot-check with md5sum; Tailscale policy often blocks server↔server
#   ssh, so push Mac→host.

# 3. host-side: launch all nodes (+ canaries). Args: NODES SUBNETS [N:client ...]
scp scripts/start-devnet.sh "$SSH_USER@$h:/tmp/"
ssh "$SSH_USER@$h" "bash /tmp/start-devnet.sh NODES SUBNETS 28:zeam 29:ream 30:qlean 31:lantern"
```
Verify ~2 min after genesis with `scripts/sweep.sh`: head climbing, justified
advancing, then finality. A young devnet can sit at `finalized=0` while justified
jumps (square/pronic-distance slots) — that's the bootstrap regime, not a stall;
leave it alone (see `references/operations.md`).

### Set up / refresh observability
Per host: a Prometheus that scrapes this devnet's nodes with a `network=<name>`
label + `client_type`, remote-writing to the central Prometheus. One central
Prometheus + Grafana federates all devnets; the dashboard filters on `network`.
The host's **node_exporter** is a systemd service (NOT a container) on
`<tailscale_ip>:9122`, installed from `github.com/lambdaclass/monitoring-stack`
(`make inventory TARGET=...` + `make node_exporter`); the per-host prometheus
scrapes it at `<host>:9122`. Install ONLY node_exporter from that repo — its
grafana/prometheus/loki/etc. would collide with this docker stack. cadvisor stays
a container (`172.17.0.1:9098`); its per-container metrics are consumed by the
**Devnet Resources** dashboard (`scripts/resources-dashboard.json`, per-node CPU +
memory). Details + the Node Exporter Full dashboard in `references/operations.md`.
```bash
# operator-side: emit this devnet's prometheus.yml (network label + per-node client_type)
bash scripts/prometheus-config.sh NETWORK NODES HOST_IP CENTRAL_WRITE_URL [N:client ...] > /tmp/prometheus.yml
cat /tmp/prometheus.yml | ssh "$SSH_USER@$h" 'sudo tee /opt/lean-quickstart/observability/prometheus.yml >/dev/null && sudo docker restart prometheus'
```
Relabel gotcha: that file is a single-file bind-mount — edit by full overwrite
(`tee`) + `docker restart prometheus`, never `sed -i`+HUP (inode trap, see
`references/operations.md`). The central Prometheus needs
`--web.enable-remote-write-receiver`; Grafana groups by **job name**, so a
converted node must be relabelled (both `job_name:` and `client_type:`).
`scripts/finality-dashboard.json` is a ready Grafana dashboard (head / justified
/ finalized per devnet, one series per `network`) — drop it in the provisioning
dashboards dir; it auto-loads. `scripts/client-dashboard.json` is the main
per-node dashboard for the same dir (see the inventory below). Every dashboard
picks its datasource through a **template variable** (`ds_prom`/`ds_loki`;
`datasource` on the client dashboard) rather than a pinned uid, so they drop into
any Grafana unedited — no deployment-specific datasource ids in the JSON. Gotcha: that dir
is bind-mounted **read-only** into the container, so Grafana UI edits are
reverted on the next provisioner sweep (~30s) despite `allowUiUpdates: true`.
Edit the JSON and re-copy; treat the repo copy as the source of truth and keep it
in sync, since nothing pulls server-side edits back.

**Logs (Loki + promtail).** Mirrors the metrics path: a per-host **promtail**
ships node-container stdout/stderr to the **central Loki** (a container in the
central docker stack; filesystem store, 7d retention; Grafana has it as a
provisioned datasource). promtail reads via the **Docker daemon API** (docker_sd), so it is
immune to json-file rotation and works on a live devnet with no restart — it only
mounts the socket. Low-card **indexed labels** match prometheus: `network` (same
value), `node` (`<client>_N`, e.g. `zeam_8`), `client_type`, `instance`, `stream`, plus `level`
(extracted from the line). The pipeline (see `promtail-config.sh`) also: strips
ANSI colour codes from the client's pretty-logger output; **merges multi-line
events** (fork-choice tree dumps etc.) into one entry via a `multiline` stage
(`firstline` = a leading ISO timestamp; strip ANSI must run first so it anchors) —
without it each dump line is a separate level-less entry; and attaches
high-cardinality fields (`slot`, `validator`, `proposer`, `block_root`, target/
source slot+root, `peer_id`, …) as Loki **structured metadata** — filterable
(`| slot="123"`) and shown in Grafana's log-detail view, WITHOUT indexing them as
labels (which would explode stream cardinality). Query in Grafana Explore with
e.g. `{network="<devnet>"} | level="ERROR"`, or use the provisioned **Devnet
Logs** dashboard (`scripts/logs-dashboard.json`, uid `devnet-logs`: logs panel +
log-volume-by-level timeline, filters network/node/stream/search).
```bash
# operator-side: emit this host's promtail.yml (network label + push to central Loki)
bash scripts/promtail-config.sh NETWORK HOST_IP LOKI_PUSH_URL [N:client ...] \
  | ssh "$SSH_USER@$h" 'sudo tee /opt/lean-quickstart/observability/promtail.yml >/dev/null'
# host-side: launch (or restart after a config change) the shipper
scp scripts/start-promtail.sh "$SSH_USER@$h:/tmp/"; ssh "$SSH_USER@$h" 'bash /tmp/start-promtail.sh'
```
`LOKI_PUSH_URL` = `http://<central_ip>:3100/loki/api/v1/push`. Keep the canary
`N:client` specs in sync with `prometheus-config.sh` so logs and metrics agree on
`client_type`. Same single-file bind-mount inode trap as prometheus.yml: overwrite
with `tee` then `sudo docker restart promtail`.

**First-start backlog gotcha:** docker_sd has no "since", so on a fresh
`positions.yaml` promtail replays each container's FULL retained history (the
600m×N json files reach back days) — Loki rejects it as too-old and rate-limits,
and the read burns 2+ cores per host (disturbs the devnet). A `drop older_than: 1h`
pipeline stage (baked into `promtail-config.sh`) stops the *shipping*, but promtail
still *reads* the whole backlog. On hosts with large logs, after first launch
**seed the positions to now** so it skips the read:
```bash
ssh "$SSH_USER@$h" 'POS=/opt/lean-quickstart/observability/promtail-data/positions.yaml
  sudo docker stop promtail; N=$(date +%s)
  sudo sed -i -E "s/: \"[0-9]+\"/: \"$((N-300))\"/" "$POS"; sudo docker start promtail'
```
Positions persist (mounted dir), so this is a one-time fixup per host.

**Finality alert (Slack).** `scripts/grafana-finality-alert.yaml.template` provisions
a per-devnet "lost finality" rule into the central Grafana: fires when
`max(head) − max(finalized) > 512` for a `network` (network maxima, so one stuck
canary can't false-fire), 5m `for`, 15m anti-flap, at most one notify per 12h.
Deploy it with `scripts/deploy-finality-alert.sh`, which takes every
deployment-specific value from `devnet.env` (`METRICS_HOST`, `GRAFANA_PROV_DIR`,
`GRAFANA_CONTAINER`, `GRAFANA_BASE_URL`, `PROM_DS_UID`) — nothing host-specific
lives in the template:
```bash
bash scripts/deploy-finality-alert.sh                  # values from devnet.env
DRY_RUN=1 bash scripts/deploy-finality-alert.sh        # render + validate, ship nothing
PROM_DS_UID=other bash scripts/deploy-finality-alert.sh  # one-off override
```
It refuses to ship if any `__PLACEHOLDER__` survived rendering (Grafana would
silently ignore a malformed provisioning file).
`WEBHOOK_FILE` (default `./webhook.txt`) holds the Slack webhook — a **secret**; the
repo `.gitignore` covers `webhook.txt` and the rendered alert file, and the script
renders to a `mktemp` it deletes on exit. Unlike the dashboards, a provisioned alert
rule needs a concrete datasource uid, which is why `PROM_DS_UID` is explicit.

### Recover crashed / frozen / split nodes (no chain reset)
Use `scripts/cs-restart.sh` on the affected server — checkpoint-sync restart with
the 60s backoff and crash-log preservation built in:
```bash
ssh "$SSH_USER@$h" "bash /tmp/cs-restart.sh <CS_PORT> <node>..."
```
`CS_PORT` = a healthy same-devnet node's api (an aggregator stays up — use it).
Restart aggregators last, sourcing checkpoint from a healthy non-aggregator. For
many nodes, launch detached and poll `/tmp/cs-restart.log` (detached-SSH and
pkill-bracket gotchas in `references/operations.md`).

### "Is this node working?" — the all-is-good checklist
A tool to answer, at any time, whether a running node is doing its job — a spot
check on a node, a sanity pass after a config change or conversion, or one input
to a stall investigation. `references/node-health.md` is a per-node checklist
(follows the chain, emits valid+useful attestations, builds non-empty blocks,
aggregates+publishes if an aggregator, on-time duties, peers+mesh, votes landing
in blocks) with a concrete Prometheus query and log grep for each item, plus a
separate devnet-level "finality advances" section that is explicitly *not* a
per-node fault (so a healthy node isn't blamed for a chain-wide stall). For duty
*timing* detail use the `devnet-profiling` skill.

### "A devnet stopped finalizing" — investigate
Do NOT immediately restart. Diagnose that devnet in order (full method in
`references/operations.md`): is it the young-devnet bootstrap regime (justified
still advancing, finalized=0)? → vote count vs `ceil(2/3·NODES)` → which
validator cohort is missing on the aggregator → are missing nodes silent or
voting STALE targets → host memory/CPU via the central Prometheus (reachable even
when that server's SSH is down) → confirm no block rejections (rules out a canary
interop fork). Common causes: a host OOM freezing fork choice; nodes restarted
without the 60s backoff; a frozen canary thinning votes; aggregator backlog. Fix
the cause, then `cs-restart.sh` the affected nodes; deep in the spiral, a fresh
genesis is faster.

### Convert nodes to other clients (zeam/ream/qlean/grandine/gean/lantern)
Node identity stays `node_n`; the container is renamed to `<client>_n` to reflect
the new client (so Grafana/logs show it). Use `scripts/convert.sh` (per-client CLI
shapes + memory limits + 60s backoff; `ACC=<SUBNETS>` env sets committee count):
```bash
ssh "$SSH_USER@$h" "ACC=SUBNETS bash /tmp/convert.sh <CS_PORT> <N:client[:agg]>..."
```
**Canary one node per client type first** and confirm the vote count holds before
scaling — a broken client converted en masse can drop the ethlambda count below
`ceil(2/3·NODES)` and kill that devnet's finality. Keep aggregators on ethlambda
unless deliberately moving them. After converting, relabel Prometheus (see
observability above). Per-client images, flags, and interop status are in
`references/clients.md`. **Re-canary after any leanVM/image bump.**

### Add swap / memory limits
Swap (persistent): `fallocate -l 16G /swapfile && chmod 600 && mkswap && swapon`
+ an `/etc/fstab` line, per host. Live container limits without recreating:
`sudo docker update --memory 8g --memory-swap 16g --memory-reservation 2g <name>`.

## Resources

- `scripts/devnet.env.example` — template for `scripts/devnet.env` (gitignored): this deployment's `SERVERS`, `SSH_USER`, central prometheus/loki urls, and the Grafana ids the alert deploy needs. Copy + fill in once.
- `scripts/devnet-env.sh` — sourced helper that loads `devnet.env` (lookup: `$DEVNET_ENV`, `./devnet.env`, script dir) as defaults; exported vars win.
- `scripts/make-genesis.sh` — operator-side: build one devnet's genesis dir (127.0.0.1 ENRs, per-subnet aggregators, hardlinked keys, runs lean-quickstart `generate-genesis.sh`). Args: `OUTDIR NODES SUBNETS KEYS_DIR SRC_VCONFIG [GT_OFFSET]`. Env `VALIDATORS_PER_NODE` (default 1).
- `scripts/merge-keyshards.py` — operator-side: merge hash-sig key shards into one sequentially-indexed dir + manifest. hash-sig-cli has no `--start-index` (always emits `validator_0..N-1`), so generating a key set across several machines in parallel needs this reindex. Refuses to mix key formats, so a stale 52-byte `Dim46` shard can't poison a 32-byte `Dim42` genesis. Args: `OUTDIR SHARD_DIR...` (shards concatenated in order).
- `scripts/subnet-align-validators.py` — operator-side: rewrite `annotated_validators.yaml` so each node's validators all belong to one subnet. Called automatically by `make-genesis.sh`; identity when `VALIDATORS_PER_NODE=1`. Args: `GENESIS_DIR NODES SUBNETS VALIDATORS_PER_NODE`.
- `scripts/start-devnet.sh` — per-host: launch a full devnet (all-ethlambda + optional canaries, per-subnet aggregators, devnet5 images). Args: `NODES SUBNETS [N:client ...]`.
- `scripts/prometheus-config.sh` — operator-side: emit a per-devnet prometheus.yml with `network` label + per-node `client_type`. Args: `NETWORK NODES HOST_IP CENTRAL_WRITE_URL [N:client ...]`.
- `scripts/promtail-config.sh` — operator-side: emit a per-host promtail.yml (docker_sd → central Loki, labels mirror prometheus, `drop older_than 1h` backlog guard). Args: `NETWORK HOST_IP LOKI_PUSH_URL [N:client ...]`.
- `scripts/start-promtail.sh` — per-host: (re)launch the promtail log shipper (reads `/opt/lean-quickstart/observability/promtail.yml`; env `PROMTAIL_IMG`). Safe on a live devnet (no gossip backoff).
- `scripts/cs-restart.sh` — per-host checkpoint-sync restart of specific nodes (args: `CS_PORT node...`).
- `scripts/agg-restart.sh` — per-host checkpoint-sync restart of aggregator nodes preserving role / swapping image (env `IMAGE`, `SUBNET`; args: `CS_PORT node...`).
- `scripts/convert.sh` — per-host multi-client conversion (env `ACC`; args: `CS_PORT N:client[:agg]...`).
- `scripts/sweep.sh` — operator-side audit: per-devnet head/justified/finalized + client mix from the central Prometheus (env: `CENTRAL_PROM_URL`).
- `scripts/finality-dashboard.json` — Grafana dashboard: head/justified/finalized per devnet (one series per `network`). Provision it into the dashboards dir.
- `scripts/grafana-finality-alert.yaml.template` — Grafana unified-alerting provisioning for the per-devnet "lost finality" rule + Slack contact point. Placeholders (`__SLACK_WEBHOOK_URL__`, `__GRAFANA_BASE_URL__`, `__PROM_DS_UID__`) are filled at deploy time.
- `scripts/deploy-finality-alert.sh` — render + ship that alert to the central Grafana and reload it. Env: `METRICS_HOST`, `GRAFANA_PROV_DIR`, `GRAFANA_CONTAINER`, `GRAFANA_BASE_URL`, `PROM_DS_UID` (all required); arg: `[WEBHOOK_FILE]` (default `./webhook.txt`, a gitignored secret).
- `scripts/logs-dashboard.json` — Grafana dashboard (uid `devnet-logs`): Loki-backed logs panel + log-volume-by-level timeline, filtered by `network`/`node`/`stream`/`search`. Drop into the provisioned dashboards dir; auto-loads in ~30s.
- `scripts/resources-dashboard.json` — Grafana dashboard (uid `devnet-resources`): per-node CPU cores + memory working-set (+8 GiB limit) + %-of-limit (OOM watch), from the cAdvisor metrics the per-host prometheus already scrapes. Filtered by `network`/`name`. Same provisioned dashboards dir.
- `scripts/client-dashboard.json` — Grafana dashboard (uid `lean-ethereum-clients-dashboard`): the main per-node client dashboard. Expanded Overview (start time / validators / committees / head / justified / finalized stats, the three slot graphs, the three finality-delay graphs) plus 13 collapsed sections: devnet configuration, sync status, peers, req/resp + gossip mesh, gossip messages, PQ signatures, aggregation coverage, block production, block proposal internals, fork choice, attestations, state transition, storage + tick health. Filtered by `network` (single-select) / `job` / `instance`; `instance` is the **host**, not the node. Same provisioned dashboards dir.
- `references/node-health.md` — per-node "all is good" checklist (follows chain, valid+useful attestations, non-empty proposals, aggregate+publish, on-time duties, peers+mesh, votes-land-in-blocks) with a Prometheus query + log grep per item, plus a devnet-level finality-advances section. Node-health vs devnet-health.
- `references/operations.md` — topology model, the failure modes behind each golden rule, bootstrap-vs-stall diagnosis, detached-SSH/pkill gotchas, prometheus/grafana wiring, host recovery.
- `references/clients.md` — per-client images, CLI shapes, conversion principle, interop status.

Topology specifics and chain history for the operator's particular deployment
live in their project memory notes; verify versions/interop against the live
chain — status is version-specific.
