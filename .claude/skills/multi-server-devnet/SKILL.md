---
name: multi-server-devnet
description: This skill should be used for managing long-lived lean-consensus devnets that run as detached docker containers on remote hosts — the usual setup is one INDEPENDENT single-host devnet per server, federated into one Grafana, but it also covers a single chain whose node indices are SPLIT across hosts. Works for any server names and any number of servers/nodes. Trigger when the user asks to "start/reset the devnet(s)", "start a devnet on <server>", "reset the cross-server devnet", "restart the devnet on both servers", "restart the devnet", "rolling restart", "recover stalled nodes", "the devnet stopped finalizing", "investigate the finality stall", "convert nodes to zeam/ream/qlean/grandine/gean/lantern", "multi-client devnet", "add a client to the devnet", "canary a new client/build", "scale the devnet / add a node", "set up grafana/prometheus for the devnets", "pull the latest image on the servers", or "add swap / memory limits to the servers". Distinct from the local single-host `devnet-runner` skill.
version: 0.3.0
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

**Variant: one chain spanning several hosts.** A deployment may instead run a
single chain whose node indices are split across hosts (host A owns `0..k`, host
B owns `k+1..N-1`). Everything below still applies with three changes, and
`start-range.sh` / `check-range.sh` / `teardown.sh` exist for exactly this shape:

- **ENRs carry each host's real (e.g. tailnet) IP**, not `127.0.0.1`, or the
  halves never discover each other. Put the per-host ip in the source
  `validator-config.yaml`'s `enrFields.ip`; `make-genesis.sh` pins `127.0.0.1`
  and so is NOT usable as-is — generate from a hand-built validator-config
  instead (keep it: it also carries the node privkeys, so reusing it verbatim
  preserves every node's identity across a reset).
- **Aggregators are no longer "node k → subnet k".** Each host owns a slice of
  the subnets (host B's node `36` may aggregate subnet `4`), so the mapping is
  passed explicitly rather than derived from the index.
- **`ceil(2/3·NODES)` spans both hosts**, so losing one host halts the whole
  chain rather than half of it, and a restart on either half checkpoint-syncs
  from the other.

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
Per-devnet `NODES`/`SUBNETS` are recorded there too, but as the operator's
inventory — the scripts take them as positional args, and the authority on a
running devnet is always its own `genesis/config.yaml`
(`ATTESTATION_COMMITTEE_COUNT`), which `start-devnet.sh` and `convert.sh` check
against.

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
5. **A node must come back with the role it had.** A restart that drops
   `--is-aggregator` leaves its subnet with no aggregator: attestations still
   verify and the logs look healthy, but nobody stores the gossip signatures, so
   blocks are built with `attestation_count=0` and finality dies quietly.
   `cs-restart.sh` preserves the role; `convert.sh` warns when a conversion would
   remove one. After any restart, confirm one `AGG=yes` per subnet with
   `host-check.sh` (or `lean_is_aggregator`). Same for `--log-opt`: every
   `docker run` must cap the json log, or one verbose canary fills the disk.

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
scp scripts/start-devnet.sh scripts/host-check.sh "$SSH_USER@$h:/tmp/"
ssh "$SSH_USER@$h" "bash /tmp/start-devnet.sh NODES SUBNETS 28:zeam 29:ream 30:qlean 31:lantern"
```
`start-devnet.sh` refuses to launch when its `SUBNETS` disagrees with the genesis
on disk, when node data dirs are non-empty (step 0 skipped ⇒ nodes resume an old
DB against a new genesis and fork off; `ALLOW_STALE_DATA=1` overrides), or when a
canary spec names an unknown client — all three otherwise cost the whole devnet.

Verify ~2 min after genesis, host-side first, then across devnets:
```bash
ssh "$SSH_USER@$h" "bash /tmp/host-check.sh NODES"   # every node up + following (exit≠0 = attention)
bash scripts/sweep.sh                                # head/justified/finalized per devnet
```
A young devnet can sit at `finalized=0` while justified jumps
(square/pronic-distance slots) — that's the bootstrap regime, not a stall; leave
it alone (see `references/operations.md`).

### Reset a chain that SPANS hosts (one genesis, node indices split)
Same order as above, but each host owns a slice and the aggregator→subnet map is
explicit. Reuse the existing source `validator-config.yaml` verbatim (real
per-host ENR ips + node privkeys) and re-stamp GENESIS_TIME with lean-quickstart's
`generate-genesis.sh <ABSOLUTE genesis dir> --mode ansible --offset N` — keygen is
skipped when the keys are already there, so only the small artifacts change.

```bash
# 0. stage the new genesis alongside the LIVE one (non-destructive: nothing stops yet).
#    Do the big key sync here, while the old chain still runs.
(cd BUILD_DIR && COPYFILE_DISABLE=1 tar cf - .) | \
  ssh "$SSH_USER@$h" 'sudo rm -rf /opt/lean-quickstart/genesis-new
    sudo mkdir -p /opt/lean-quickstart/genesis-new
    sudo tar xf - -C /opt/lean-quickstart/genesis-new'

# 1. PRE-FLIGHT the image against that staged genesis BEFORE anything is wiped --
#    a pubkey-size mismatch (52B leanSig vs 32B leanVM-main) fails at genesis parse,
#    upstream of every sync path, and no --checkpoint-sync-url can save it.
#    --network none + a throwaway data dir cannot touch the live devnet.
#    Use `docker run -d --name X` + explicit `docker rm -f`: `timeout` kills the
#    docker CLIENT, not the container, so --rm never fires and it leaks.
ssh "$SSH_USER@$h" 'sudo docker run -d --name gval --network none \
  -v /opt/lean-quickstart/genesis-new:/config:ro -v /tmp/gval-data:/data IMAGE \
  --genesis /config/config.yaml ... --node-id node_0'   # want: "Loaded genesis
  # configuration validator_count=N" -> "Loaded validator key pairs" -> "Initialized store"

# 2. teardown per host (containers, archive genesis, wipe data) -- run BEFORE the
#    GENESIS_TIME stamp. Archives genesis to genesis.bak-<ts> so the retired
#    chain's hash-sig keys survive, and promotes genesis-new into place.
ssh "$SSH_USER@$h" 'bash /tmp/teardown.sh'

# 3. re-stamp GENESIS_TIME, reship ONLY the regenerated small files, launch each slice
ssh "$SSH_USER@$hA" "ETH_IMG=IMAGE bash /tmp/start-range.sh 0 31 8 0:0 1:1 2:2 3:3"
ssh "$SSH_USER@$hB" "ETH_IMG=IMAGE bash /tmp/start-range.sh 32 63 8 36:4 37:5 38:6 39:7"
ssh "$SSH_USER@$h" 'bash /tmp/check-range.sh START END'   # range-aware host-check
```
Measured on a 64-node/2-host chain: teardown incl. a 184 GB RocksDB wipe **7s per
host** (`rm -rf` of RocksDB is far cheaper than the genesis-countdown budget
assumes), reship + 32 `docker run` ~25s per host, mesh at full peer count *before*
genesis — so `--offset 300` left minutes of slack. Starting host A before host B
fills A's log with WARN `Failed to negotiate transport protocol(s)` for B's
not-yet-up nodes; benign dial races, peers converge. Grep `ERROR` by level, since
`-i error` also matches those warnings.

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
# host-side: create the scrapers on a NEW host (existing ones are left alone
# unless RECREATE=1 — a config change only needs the restart above)
scp scripts/start-observability.sh "$SSH_USER@$h:/tmp/"; ssh "$SSH_USER@$h" 'bash /tmp/start-observability.sh'
```
Relabel gotcha: that file is a single-file bind-mount — edit by full overwrite
(`tee`) + `docker restart prometheus`, never `sed -i`+HUP (inode trap, see
`references/operations.md`). The central Prometheus needs
`--web.enable-remote-write-receiver`; Grafana groups by **job name**, so a
converted node must be relabelled (both `job_name:` and `client_type:`).
`scripts/devnet-overview-dashboard.json` is a ready Grafana dashboard (head / justified
/ finalized per devnet, one series per `network`) — copy it to the central
Grafana's **dashboards dir** and it auto-loads. `scripts/client-dashboard.json` is
the main per-node dashboard for the same dir (see the inventory below). Every
dashboard picks its datasource through a **template variable** (`ds_prom`/`ds_loki`;
`datasource` on the client dashboard) rather than a pinned uid, so they drop into
any Grafana unedited — no deployment-specific datasource ids in the JSON.

**That dir is NOT `<GRAFANA_PROV_DIR>/dashboards`** — the provisioning tree holds
only the provider yaml (`dashboards.yml`, which declares
`options.path: /var/lib/grafana/dashboards`); the JSONs live in whatever host dir
is bind-mounted there, a sibling of the provisioning tree in this deployment
(`GRAFANA_DASHBOARDS_DIR` in `devnet.env`). Confirm before copying, since dropping
a dashboard in the provisioning dir loads nothing and looks like a silent no-op:
```bash
ssh "$METRICS_HOST" 'sudo docker inspect '"$GRAFANA_CONTAINER"' \
  --format "{{range .Mounts}}{{.Source}} -> {{.Destination}} (ro={{not .RW}}){{println}}{{end}}"'
# ship it (back up first; the provisioner sweeps every ~30s)
ssh "$METRICS_HOST" "cp -p $GRAFANA_DASHBOARDS_DIR/client-dashboard.json{,.bak-\$(date +%Y%m%d-%H%M%S)}"
cat scripts/client-dashboard.json | ssh "$METRICS_HOST" "cat > $GRAFANA_DASHBOARDS_DIR/client-dashboard.json"
```
Verify it landed with
`curl -s $GRAFANA_BASE_URL/api/dashboards/uid/<uid> | jq '.dashboard.version'` (the
version bumps on each sweep that reads a changed file).

**Ship a dashboard under the same FILENAME the skill uses, and keep exactly one
`.json` per uid in that dir.** Grafana keys a provisioned dashboard on its `uid`,
not its filename, so a copy left behind under an old name is invisible in the UI
yet still claims the uid: adding a second file next to it makes two provider files
fight over one uid, which Grafana resolves by logging an error and dropping one.
The failure looks like "my update did not land". This bit us once already: the
finality dashboard was `scripts/finality-dashboard.json` here but had been
deployed as `devnet-overview-dashboard.json`, so copying it under the skill's name
would have collided rather than updated it. The two names are now reconciled on
`devnet-overview-dashboard.json` (the deployed one, since the server is what
operators actually look at). To retire a stale copy, rename it to
`<name>.json.bak-<ts>` in the same step that writes the new file — the provider
only reads `*.json`, which is also why the `.bak-*` backups already in that dir
are inert. Audit with `md5sum` of every server `.json` against `scripts/*.json`;
the names AND the digests should match, with `node-exporter-full.json` the one
expected exception (see the note under the inventory: it is owned upstream).

Filenames are for humans; only the `uid` inside the JSON is load-bearing. Do not
"fix" a filename to look more like its uid — `devnet-overview-dashboard.json`
carries uid `devnet-finality-overview` and that mismatch is harmless, whereas
renaming a live file costs a provisioner re-add (the dashboard's `version` resets
to 1, same uid, so links and alerts survive).

Gotcha: that dir is
bind-mounted **read-only** into the container, so Grafana UI edits are reverted on
the next provisioner sweep (~30s) despite `allowUiUpdates: true`. Edit the JSON and
re-copy; treat the repo copy as the source of truth and keep it in sync, since
nothing pulls server-side edits back.

**Logs (Loki + promtail).** Mirrors the metrics path: a per-host **promtail**
ships node-container stdout/stderr to the **central Loki** (7d retention;
provisioned Grafana datasource). It discovers containers through the **Docker
daemon API**, so it is immune to json-file rotation and safe to deploy on a live
devnet — it only mounts the socket. Indexed labels match prometheus (`network`,
`node` = `<client>_N`, `client_type`, `instance`, `stream`, `level`);
high-cardinality fields (`slot`, `validator`, `block_root`, …) ride as Loki
**structured metadata** instead, so they stay filterable (`| slot="123"`) without
exploding stream cardinality. Query in Grafana Explore
(`{network="<devnet>"} | level="ERROR"`) or use the provisioned **Devnet Logs**
dashboard (`scripts/logs-dashboard.json`).
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

**One trap on first launch:** promtail replays each container's whole retained log
history (docker_sd has no "since"), which Loki rejects as too-old and which burns
2+ cores per host while it reads. `promtail-config.sh` bakes in the `drop
older_than: 1h` guard, but on a host with large logs you also want to seed
`positions.yaml` to "now" once — the pipeline stages, the exact seed command, and
why the stage order matters are in `references/operations.md`.

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
the 60s backoff, per-container crash-log preservation, and **aggregator-role
preservation** built in:
```bash
ssh "$SSH_USER@$h" "bash /tmp/cs-restart.sh <CS_PORT[,CS_PORT2]> <node>..."
ssh "$SSH_USER@$h" "bash /tmp/host-check.sh <NODES>"   # verify after
```
`CS_PORT` = a healthy same-devnet node's api (an aggregator stays up — use it);
comma-separate a second one and ethlambda falls over to it if the first fails.
It reads the topology flags (`--is-aggregator`, `--aggregate-subnet-ids`,
`--attestation-committee-count`) off the container it replaces, so restarting an
aggregator no longer demotes it — the failure that looks like a healthy devnet
which silently stops finalizing. If the container is already gone there is nothing
to read: pass `SUBNETS=<n>` so the rule (nodes `0..SUBNETS-1`) can be re-derived.
Restart aggregators last, sourcing checkpoint from a healthy non-aggregator.
`AGG=` overrides the preserved role when you want to *change* it, and `IMAGE=`
canaries a build on the node (aggregators included):

| | |
|---|---|
| `AGG` unset | preserve the role the container had (default) |
| `AGG=auto SUBNETS=n` | apply the topology rule — repairs a node that lost its role |
| `AGG=<id>` | promote this node to aggregate subnet `<id>` |
| `AGG=off` | demote deliberately |

For many nodes, launch detached and poll `/tmp/cs-restart.log` (detached-SSH and
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
still advancing, finalized=0)? → `host-check.sh` for the per-node picture (who is
down, restarting, or lagging past the sync gate) → vote count vs
`ceil(2/3·NODES)` → which validator cohort is missing on the aggregator → are
missing nodes silent or voting STALE targets → host memory/CPU via the central
Prometheus (reachable even when that server's SSH is down) → confirm no block
rejections (rules out a canary interop fork). Common causes: a host OOM freezing
fork choice; nodes restarted without the 60s backoff; **an aggregator that came
back without its role** (check `lean_is_aggregator`/the `AGG` column — one per
subnet must be `yes`); a frozen canary thinning votes; aggregator backlog. Fix the
cause, then `cs-restart.sh` the affected nodes; deep in the spiral, a fresh genesis
is faster.

### Convert nodes to other clients (zeam/ream/qlean/grandine/gean/lantern)
Node identity stays `node_n`; the container is renamed to `<client>_n` to reflect
the new client (so Grafana/logs show it). Use `scripts/convert.sh` (per-client CLI
shapes + memory limits + 60s backoff; committee count read from the genesis on
disk, `ACC=<SUBNETS>` only to override):
```bash
ssh "$SSH_USER@$h" "bash /tmp/convert.sh <CS_PORT> <N:client[:agg]>..."
```
It validates every spec before removing anything (a typo used to be discovered
after the node's container and data were already gone) and warns when the node it
is replacing was an aggregator and the new spec has no `:agg` — that silently
leaves a subnet with no aggregator.
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

**Scripts.** "operator" runs on your machine, "host" is scp'd and run on a server.

| Script | Where | Args / env | What |
|---|---|---|---|
| `make-genesis.sh` | operator | `OUTDIR NODES SUBNETS KEYS_DIR SRC_VCONFIG [GT_OFFSET]`; `VALIDATORS_PER_NODE` | Build one devnet's genesis dir: 127.0.0.1 ENRs, per-subnet aggregators, hardlinked keys, runs lean-quickstart `generate-genesis.sh` + subnet alignment |
| `merge-keyshards.py` | operator | `OUTDIR SHARD_DIR...` | Merge hash-sig key shards into one 0..N-1 dir + manifest (hash-sig-cli has no `--start-index`, so parallel keygen collides). Refuses to mix key formats, so a stale 52-byte `Dim46` shard can't poison a 32-byte `Dim42` genesis |
| `subnet-align-validators.py` | operator | `GENESIS_DIR NODES SUBNETS VPN` | Rewrite `annotated_validators.yaml` so each node's validators sit in ONE subnet. Called by `make-genesis.sh`; identity at `VPN=1` |
| `start-devnet.sh` | host | `NODES SUBNETS [N:client ...]`; `ETH_IMG`, `MEM`, `LOGOPT`, `EXTRA_ETH_FLAGS`, `ALLOW_STALE_DATA` | Launch a fresh devnet (all-ethlambda + canaries, per-subnet aggregators). Preflight: genesis/SUBNETS match, empty data dirs, known clients |
| `host-check.sh` | host | `[NODES]`; `LAG_THRESHOLD` | Per-node table (container status, restarts, head/justified/finalized, sync, aggregator, peers) read from `127.0.0.1` only — works when the central prom doesn't. Exit ≠0 = needs attention |
| `start-range.sh` | host | `START END SUBNETS [N:subnet ...]`; `ETH_IMG`, `MEM`, `LOGOPT`, `EXTRA_ETH_FLAGS`, `ALLOW_STALE_DATA` | Launch one host's SLICE of a chain that spans hosts (`start-devnet.sh` only does `0..NODES-1` with aggregator = index). Aggregator→subnet map is explicit; preflight also logs the genesis pubkey size so a 52B/32B image mismatch is caught before launch |
| `check-range.sh` | host | `START END` | Range-aware `host-check.sh` for a host owning `START..END` (status, head/justified/finalized, peers, aggregator, restarts). Exit ≠0 = needs attention |
| `teardown.sh` | host | `KEEP_GENESIS`, `STAGED` | Retire this host's slice in wipe-before-stamp order: clear `--restart` policy then remove containers, archive genesis to `genesis.bak-<ts>` (**keeps the retired chain's hash-sig keys**), promote a staged genesis, wipe `data/node_*` |
| `cs-restart.sh` | host | `CS_PORT[,PORT2] node...`; `IMAGE`, `AGG`, `SUBNETS` | Checkpoint-sync restart: 60s backoff, crash logs, aggregator role **preserved** by default (`AGG=auto\|<id>\|off` to set it, `IMAGE=` to canary a build) |
| `convert.sh` | host | `CS_PORT N:client[:agg]...`; `ACC` (default: from genesis) | Convert nodes to other clients. Validates specs first; warns on aggregator loss |
| `start-observability.sh` | host | `RECREATE`, `PROM_*`, `CADVISOR_*` | Create this host's prometheus + cadvisor containers (node_exporter is systemd, not here) |
| `start-promtail.sh` | host | `PROMTAIL_IMG` | (Re)launch the log shipper. Safe on a live devnet (not a gossip peer) |
| `prometheus-config.sh` | operator | `NETWORK NODES HOST_IP CENTRAL_WRITE_URL [N:client ...]` | Emit a per-devnet prometheus.yml (`network` label + per-node `client_type`) |
| `promtail-config.sh` | operator | `NETWORK HOST_IP LOKI_PUSH_URL [N:client ...]` | Emit a per-host promtail.yml (docker_sd → central Loki, labels mirror prometheus, backlog guard) |
| `sweep.sh` | operator | `CENTRAL_PROM_URL` | Cross-devnet audit: head/justified/finalized + client mix from the central Prometheus |
| `deploy-finality-alert.sh` | operator | `[WEBHOOK_FILE]`; `METRICS_HOST`, `GRAFANA_*`, `PROM_DS_UID`; `DRY_RUN` | Render + ship the "lost finality" Slack alert to the central Grafana |
| `devnet-env.sh` / `devnet.env.example` | operator | `$DEVNET_ENV`, `./devnet.env`, script dir | Load this deployment's hosts/urls/Grafana ids as defaults; exported vars win. Copy the example to `devnet.env` (gitignored) once |

**Grafana dashboards** (copy into the central Grafana's dashboards dir —
`GRAFANA_DASHBOARDS_DIR`, *not* the provisioning tree; they auto-load in ~30s and
pick their datasource through a template variable, so no editing):

| File | uid | Content |
|---|---|---|
| `client-dashboard.json` | `lean-ethereum-clients-dashboard` | The main per-node dashboard: Overview (start time, validators, committees, head/justified/finalized, slot + finality-delay graphs) plus 14 collapsed sections (config, sync, peers, req/resp + mesh, gossip, gossip arrival timing, PQ signatures, aggregation coverage, block production, proposal internals, fork choice, attestations, state transition, storage + tick health). Filters `network`/`job`/`instance` — `instance` is the **host**, not the node. The config section's **Image build** table answers "which commit is this node running" for **every** client, from the image's OCI `revision`/`ref.name` labels re-exported by cAdvisor as `container_label_*` (see `references/operations.md`) — ethlambda's own `lean_node_info{version}` already embeds its short SHA, partner clients' usually do not |
| `devnet-overview-dashboard.json` | `devnet-finality-overview` | head / justified / finalized per devnet, one series per `network` |
| `resources-dashboard.json` | `devnet-resources` | Per-node CPU cores + memory working set (+ limit + %-of-limit for OOM watch), OOM kills, restart events, current uptime, and the same **Image build** commit-per-node table as the client dashboard — all from cAdvisor, so read a fresh uptime next to an unchanged commit as "came back on the same build" |
| `logs-dashboard.json` | `devnet-logs` | Loki logs panel + log-volume-by-level, filtered `network`/`node`/`stream`/`search` |
| `grafana-finality-alert.yaml.template` | — | Unified-alerting provisioning for the per-devnet "lost finality" rule + Slack contact point; placeholders filled by the deploy script |

**One dashboard in that dir is NOT ours: `node-exporter-full.json` (uid `rYdddlPWk`).**
It is host-level CPU/RAM/disk/net for the systemd node_exporter on `<host>:9122`,
the counterpart to the container-level resources dashboard, and it comes from the
same repo the node_exporter itself does — `lambdaclass/monitoring-stack`, as
`ansible/files/infra-dashboard.json` (its `ansible/grafana.yml` installs it). That
repo in turn tracks the community **Node Exporter Full** dashboard, `gnetId: 1860`,
maintained at `github.com/rfmoz/grafana-dashboards`. Deliberately **not** vendored
here: it is ~460 KB of generated JSON we do not maintain, it would go stale against
its source, and this skill has no business owning it. Refresh it from the source
instead, which needs no edit (its `ds_prometheus` variable already ships with an
empty `current`, so it falls back to the default datasource):
```bash
gh repo clone lambdaclass/monitoring-stack /tmp/monitoring-stack -- --depth 1
cat /tmp/monitoring-stack/ansible/files/infra-dashboard.json \
  | ssh "$METRICS_HOST" "sudo tee $GRAFANA_DASHBOARDS_DIR/node-exporter-full.json >/dev/null"
```
So it is the one file the `md5sum` audit below must skip: every OTHER server
`.json` has a `scripts/` counterpart, this one has an upstream instead.

**References.** `node-health.md` — per-node "all is good" checklist (chain follow,
valid+useful attestations, non-empty proposals, aggregate+publish, on-time duties,
peers+mesh, votes-land-in-blocks) with a Prometheus query + log grep per item, and
why devnet-health is judged separately. `operations.md` — topology model, the
failure mode behind each golden rule, bootstrap-vs-stall diagnosis, detached-SSH /
pkill gotchas, prometheus + Loki wiring and their traps, host recovery.
`clients.md` — per-client images, CLI shapes, conversion principle, interop status.

Topology specifics and chain history for the operator's particular deployment
live in their project memory notes; verify versions/interop against the live
chain — status is version-specific.
