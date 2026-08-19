# Multi-Server Devnet Operations

Hard-won operational detail for lean-consensus devnets that run as detached
containers on remote hosts — **one independent single-host devnet per server**.
SKILL.md has the workflows; this file has the depth and the failure modes.

## Topology model

- Operator supplies SSH targets via `SERVERS` (any count, any names) and
  `SSH_USER`; `docker` runs under `sudo`. No host count, address, or spec is
  assumed.
- **Each server runs its own complete devnet** — its own genesis, GENESIS_TIME,
  fork choice, and finality. No cross-server peering: every ENR is pinned to
  `127.0.0.1`, so discovery never leaves the host even though all devnets share
  the dummy fork digest. Per-devnet validator count `NODES` and committee count
  `SUBNETS` can differ between servers.
- Three-layer naming, `0 ≤ n < NODES`, numbered from 0 **per devnet** (no
  cross-host BASE): **identity** `node_n` (node-id, `node_n.key`, data-dir,
  genesis validator name — client-agnostic); **container/display** `<client>_n`
  (docker `--name` → cAdvisor `name` + promtail `node`; `client_type` derived from
  this prefix); **index** `n` for ports gossip `9000+n`, api `5052+n`, metrics
  `9200+n`. Scripts locate a node's container by the `_n$` name suffix, so the
  client prefix can change without touching identity or data.
- One aggregator per subnet: nodes `0 .. SUBNETS-1`, node `k` aggregates subnet
  `k` (leanVM CPU isolation — one per subnet, no more). Node `n` attests on
  subnet `n % SUBNETS`.
- Containers: `docker run -d --restart unless-stopped --network host`. Genesis
  mounted `/opt/lean-quickstart/genesis:/config`, data
  `/opt/lean-quickstart/data/node_n:/data`.
- **Finality threshold is per devnet:** `ceil(2/3 · NODES)` for that server. One
  devnet stalling never affects another.
- A central Grafana/Prometheus stack runs on one chosen host; each server's
  per-host prometheus on `127.0.0.1:9090` remote-writes to it with a per-devnet
  `network` label. The central prom API (its host address, a distinct port like
  `:9099`) is the one cross-devnet metrics source that survives a server going
  dark, and what `sweep.sh` and Grafana read.

## Launching commands detached over SSH

A plain `ssh host 'setsid bash script & disown'` often hangs because the SSH
channel stays open. Use:

```bash
ssh "$SSH_USER@$host" "setsid bash /tmp/script.sh ARGS >/tmp/script.out 2>&1 </dev/null & disown; sleep 1; echo started; exit 0"
```

Then poll `/tmp/script.log` on the host. A foreground per-host loop with 60s
sleeps will exceed a 10-min command timeout once a host has more than ~8 nodes;
always launch detached and poll.

## Killing a host-side loop

`pkill -f script.sh` matches its OWN ssh command line (which contains the
string) and kills the session (exit 255). Use the bracket trick:
`pkill -f '[s]cript'` and check with `pgrep -f '[s]cript'`.

## The genesis_time landmine

Every restarted node reads `GENESIS_TIME` from `config.yaml` on disk. Each devnet
has its OWN `GENESIS_TIME` (they deliberately differ between servers — that's
part of what keeps the chains distinct). The landmine is *within* a devnet: if a
node's on-disk value disagrees with that server's running chain, it computes a
different slot clock and genesis block root, silently forks onto a private chain,
and never rejoins. Symptoms:

- checkpoint sync fails: `genesis time mismatch: expected X, got Y`.
- a "kept-DB" node shows `Finalized: slot 0` and a head far behind, not catching up.

Rule: never hand-edit `GENESIS_TIME` on a running devnet — regenerating genesis
means a NEW chain (wipe + restart all nodes). Restarting individual nodes must
reuse the on-disk value (the restart scripts mount the same `/config`, so they
do). To compare a server's value:
```bash
ssh "$SSH_USER@$h" 'sudo grep ^GENESIS_TIME /opt/lean-quickstart/genesis/config.yaml'
```

## The mandatory 60s gossip backoff

When a running container is removed, peers PRUNE it and set a ~60s gossipsub
backoff. A replacement that starts immediately has its GRAFT rejected for that
window and may stay out of the attestation-subnet meshes — it attests, but
aggregators never receive its votes. Observable as the vote count stuck below N
with exactly the freshly-restarted cohort missing.

Rule: after removing a *running* node, `sleep 60` before starting the
replacement. `cs-restart.sh` does this automatically (only for nodes that were
running; already-down nodes start immediately). Restart one node at a time per
host; hosts can run in parallel.

## Restarting must not change a node's role

`--is-aggregator` is not a preference, it is part of the devnet's topology: with
one aggregator per subnet, a node that comes back without the flag leaves its
subnet unaggregated. Nothing errors — attestations still verify and are logged as
processed — but no gossip signature is stored, so proposers build blocks with
`attestation_count=0` and finality stops while every other signal looks healthy.

`cs-restart.sh` therefore reads the topology flags (`--is-aggregator`,
`--aggregate-subnet-ids`, `--attestation-committee-count`) off the container it is
replacing (`docker inspect -f '{{join .Config.Cmd " "}}'`; the image's ENTRYPOINT
is the binary, so run args live in `.Config.Cmd`) and passes them through.
Experiment flags are deliberately NOT carried over — a restart is where an
experiment ends. When the container is already gone there is nothing to read, so
pass `SUBNETS=<n>` and the rule (nodes `0..SUBNETS-1`, node `k` → subnet `k`) is
re-derived. To SET the role instead of preserving it, the same script takes
`AGG=auto` (re-apply the topology rule — the repair for a node that lost its role),
`AGG=<id>` (promote), or `AGG=off` (deliberate demotion); `IMAGE=` swaps the image
in the same pass, so canarying a build on an aggregator keeps its role.

There is deliberately only ONE restart path: with a separate script per role, the
role handling silently drifts out of whichever one gets used every day.

Verify after any restart with `host-check.sh` — one `AGG=yes` per subnet.

## Diagnosing a finalization stall

A stall is rarely "a client crashed." Walk these in order (all scoped to the one
affected devnet):

0. **Bootstrap, not stall?** If the devnet is young and justified is still
   advancing (jumping square/pronic slots) with finalized=0, it's the bootstrap
   regime — leave it (see the young-devnet section above).
0b. **Per-node picture, from the host itself.** `host-check.sh [NODES]` on the
   affected server: which containers are down/restarting, which heads lag past the
   sync-gate threshold (those nodes stop attesting and proposing), and whether one
   `AGG=yes` still exists per subnet. It reads only `127.0.0.1`, so it works when
   remote_write or the central stack is the thing that is broken.
1. **Vote math.** Threshold is `ceil(2/3 · NODES)` for that devnet. Pull recent
   `Checkpoint justified ... vote_count=V threshold=T` from a stable node. If
   `V < T`, not enough aligned votes.
2. **Who's missing.** On the aggregator, list distinct validators heard:
   `sudo docker logs --tail 4000 ethlambda_<agg> | grep -oE "Received attestation from gossip slot=[0-9]+ validator=[0-9]+" | grep -oE "validator=[0-9]+" | sort -u`
   Compare to the full set. A missing contiguous cohort = a partitioned/overloaded
   host or a mesh-rejoin failure.
3. **Stale votes vs silence.** A node can keep attesting a frozen head/target
   (counts for nothing) without going silent. Group recent votes by
   `head_root|target_slot|source_slot`; fragmentation across many targets = nodes
   on divergent heads. `participants=1` aggregation sessions = aggregator isolated.
4. **Host resources.** Query the central prom (reachable even when a host's SSH
   is down):
   - MemAvailable history: `node_memory_MemAvailable_bytes{instance="<host-addr>"}` via `query_range`.
   - Per-container memory: `topk(8, container_memory_working_set_bytes{instance="<host-addr>",name!=""})` (cadvisor).
   A host starving on RAM/CPU freezes its nodes' fork choice → stale votes → stall.
5. **Not a fork.** Check the other clients aren't rejecting blocks
   (`grep -ciE "invalid|reject"` in zeam/qlean/ream logs). Zero rejections rules
   out interop divergence.

## The non-finality spiral

Once finality stops, the unfinalized tree grows on every node, per-slot
processing cost rises, nodes lag at different rates, heads scatter, votes
fragment further — self-reinforcing. Recovery requires getting a coherent
threshold-meeting set back to the tip fast (checkpoint sync), not waiting for
laggards to crawl through the swamp (forward sync through the unfinalized region
is slow, ~1.3 slots/s ≈ minutes per node). When deep in the spiral, a full reset
to fresh genesis is faster and cleaner than nursing it back.

## Resource guards (added after a host OOM)

Each host gets a 16 GiB swapfile (`/swapfile`, in `/etc/fstab`). Each container
defaults to `--memory 8g --memory-swap 16g --memory-reservation 2g` (raise further
for a client that legitimately needs it). Apply live with `docker update --memory
... <name>`; bake into any `docker run`. This converts a host-killing leak into a
single-container OOM-kill.
leanVM working set is normally ~4-5 GiB/node; a node sustained above that is
leaking.

## Prometheus / Grafana wiring

Each server runs its own per-host prometheus (`--web.listen-address=:9090`,
network-host) scraping that devnet's nodes (`172.17.0.1:9200+n`) with a
**`network=<devnet>` label** + per-node `client_type`, plus the host's
node_exporter (`<host>:9122`) and cadvisor (`172.17.0.1:9098`). It
`remote_write`s to the **central
prometheus**, which must run with `--web.enable-remote-write-receiver` and is
bound to a routable address + distinct port (e.g. `:9099`). Grafana reads the
central prometheus; the dashboards have a `network` template variable to pick a
devnet (`scripts/devnet-overview-dashboard.json` = head/justified/finalized;
`scripts/resources-dashboard.json` = per-node CPU + memory from cAdvisor). The
cAdvisor scrape job already exists in each host's prometheus.yml (target
`172.17.0.1:9098`, per-node `client_type` via `metric_relabel` on the container
`name`); the resources dashboard just consumes it. NOTE per-container **network/fs**
cAdvisor metrics are NOT meaningful under `--network host` (all containers report
the host namespace) — use node_exporter for host-level net/disk; cAdvisor is
trustworthy for per-container **CPU + memory** only. GOTCHA: cAdvisor scrapes EVERY
container (nodes + prometheus/cadvisor/promtail/grafana + the root cgroup), so the
resources dashboard's `name` template var MUST use `allValue: ethlambda_.*` (not
`.*`) — otherwise "All" pulls in infra containers, and since unlimited containers
report the HOST's total RAM as their `container_spec_memory_limit_bytes` (and 0 for
some → `inf%`), the memory limit line jumps to host-RAM and the %-of-limit panel
breaks. (For a multi-client devnet use `[a-z]+_[0-9]+` so canary containers like
`zeam_8`/`grandine_7` are included too.) SECOND GOTCHA: that `allValue` is spliced
VERBATIM into PromQL as `name=~"<allValue>"`, so it must be a PromQL-safe regex —
double-quoted PromQL strings reject `\d`/`\w` escapes (`parse error: unknown escape
sequence U+0064 'd'`), which 400s EVERY panel whenever "All" nodes is selected (the
default). Use POSIX classes (`[0-9]` not `\d`); the variable's `regex:` filter field
is JS and CAN keep `\d`, since only `allValue` reaches the query. (The Loki logs
dashboard can safely use `.*` because promtail only ships
`ethlambda_*` containers in the first place.) `scripts/prometheus-config.sh`
emits the per-host file; `scripts/start-observability.sh` creates the per-host
`prometheus` + `cadvisor` containers (it refuses to touch existing ones without
`RECREATE=1`, since a live scraper's flags may not be the ones it would use).

**cAdvisor also carries the image's OCI labels**, which is the only cross-client
way to see *which commit a node is actually running*: docker copies an image's
`LABEL`s onto every container created from it, and cAdvisor (default
`--store_container_labels=true`) re-exports them on every `container_*` series as
`container_label_<label_with_underscores>`. So
`container_label_org_opencontainers_image_revision` = the full 40-char SHA and
`..._ref_name` = the branch/tag — for partner clients too, whose own
`lean_node_info{version=…}` is often just a release string (`lantern` reports
`v0.0.5`) while ethlambda's already embeds the short SHA. It reflects the image
the container was **created** with, so it stays honest after a `docker pull` that
was not followed by a recreate — unlike the mutable tag in `image`. The client
dashboard's "Image build" table consumes it; if `Commit` is empty for a client,
that client's Dockerfile simply does not set the label (ethlambda's does, fed by
`GIT_COMMIT`/`GIT_BRANCH` build args from `docker_publish.yaml`). Two matcher
gotchas when writing such a panel: cAdvisor's `job` is `cadvisor` and its
`instance` is the **host**, so neither the `$job` nor the `$instance` filter of
the node panels applies — match the node through cAdvisor's `name` instead
(`name=~"$job"`, since the container name IS the node's job label), and AND a
`name=~".+_[0-9]+"` guard onto it so "All" (`.*`) does not drag the infra
containers in, per the gotcha above.
The **central** stack is a separate one-time deployment: a prometheus started with
`--web.enable-remote-write-receiver` on a routable address + distinct port (e.g.
`:9099`), a Loki with `allow_structured_metadata: true` + schema v13/tsdb and
`retention_enabled: true` (it is false by default and `retention_period` alone is
silently ignored), and a Grafana with provisioning dirs for datasources,
dashboards, and alerting. Two distinct dirs matter here: the **provisioning** tree
(`GRAFANA_PROV_DIR`, mounted at `/etc/grafana/provisioning`) holds the datasource,
dashboard-provider and alerting yamls; the **dashboard JSONs** live in a separate
host dir (`GRAFANA_DASHBOARDS_DIR`) bind-mounted read-only at the provider's
`options.path` (`/var/lib/grafana/dashboards`). `deploy-finality-alert.sh` writes
to the first; dashboards go to the second. A JSON dropped in
`GRAFANA_PROV_DIR/dashboards` is silently ignored.

**node_exporter is a systemd service, not a container.** It's installed from
`github.com/lambdaclass/monitoring-stack` (ansible: `make inventory TARGET=...`
then `make node_exporter`), binds `<tailscale_ip>:9122`, and `Requires=
tailscaled.service`. The per-host prometheus scrapes it at `<host>:9122` (the
host's tailscale IP — reachable from the bridge container, same path as the
remote_write target). A "Node Exporter Full" Grafana dashboard (uid `rYdddlPWk`)
sits in the central grafana dashboards dir as `node-exporter-full.json`. It is NOT
vendored into this skill: it belongs to the same monitoring-stack repo the
node_exporter comes from (`ansible/files/infra-dashboard.json`, installed by that
repo's `ansible/grafana.yml`), which itself tracks the community dashboard
`gnetId: 1860` from `github.com/rfmoz/grafana-dashboards`. Copy it from there when
it needs refreshing — the source needs no edit, since its `ds_prometheus` variable
ships with an empty `current` and so resolves to the default datasource. It is the
one dashboard in that dir with no `scripts/` counterpart.
The monitoring-stack can also deploy grafana/prometheus/loki/promtail/alloy/
pyroscope, but those would collide with this docker-based stack — install ONLY
node_exporter from it.

After a client **conversion**, relabel BOTH `job_name:` and `client_type:` in
that host's `prometheus.yml` (Grafana groups by job name; converted-but-not-
relabeled nodes still show as ethlambda) — regenerate with `prometheus-config.sh`
passing the canary `N:client` specs.

**Reload gotcha (single-file bind-mount inode trap):** `prometheus.yml` is
bind-mounted as a SINGLE FILE. `sed -i` (and most editors) write a new inode and
rename over the old one, but the bind mount is pinned to the original inode — so
the container keeps reading the OLD content. `docker kill -s HUP prometheus`
reloads the stale inode, and even `promtool check config` validates the stale
file, masking it. **Do `sudo docker restart prometheus`** after editing (rebinds
to the current inode), OR overwrite in place preserving the inode (`... | sudo
tee file`, not `sed -i`/`mv`). Verify with `curl 127.0.0.1:9090/api/v1/targets`
(job/client_type per scrapeUrl). All clients export standardized `lean_*`
metrics so shared panels work; client-native metrics (e.g. `zeam_*`) need
separate panels. After a host reboot, the per-host `prometheus`/`promtail`
containers may need `docker start`.

## Logs: Loki + promtail

Log shipping mirrors the metrics path. A per-host **promtail** container
(`--network host --user root`, docker-socket mounted) discovers the devnet's node
containers via the **Docker daemon API** (`docker_sd_configs`) and ships their
stdout/stderr to the **central Loki** (`grafana/loki`, filesystem store, 7d
retention, published on `<central_ip>:3100`). Grafana reads it via a provisioned
datasource (`url: http://loki:3100`, same docker network as grafana). Reading via
the daemon API — not the json files — makes promtail immune to `--log-opt`
rotation: it consumes the live stream. `promtail-config.sh` emits the per-host
file; `start-promtail.sh` launches it. promtail is NOT a gossip peer, so deploying
it needs no 60s backoff and never touches the devnet — only the socket.

**Pipeline (in `promtail-config.sh`), in order:** (1) `drop older_than 1h` (backlog
guard, below); (2) `replace` to strip ANSI colour escapes (`\x1b\[[0-9;]*m`) from
the client pretty-logger output — without this every line is full of escape codes
and Loki's level auto-detect fails; (3) `multiline` to merge multi-line events
(fork-choice tree dumps, panics) — `firstline` is a leading ISO timestamp, so any
line that does NOT start with one is folded into the previous entry. State is
per-stream (node label). Without it, every tree-dump line is a separate level-less
entry (a large `<none>` series ≈ nodes × dumps/min × lines, plus clutter); with it
the dump is one entry that inherits its firstline's level. NOTE the order matters —
strip ANSI BEFORE multiline so `firstline` can anchor on the bare `^\d{4}-…`
timestamp (verified: putting it after, or matching ANSI-prefixed lines, was the
difference between dumps merging and not). (4) `regex`+`labels` to lift the tracing
level into a low-card **indexed label** `level` (also drives Grafana's level
colouring); (5) a `match |= "="` wrapping `logfmt`+`structured_metadata` that attaches
high-cardinality fields (`slot`, `validator`, `proposer`, `block_root`, target/
source slot+root, `attestation_count`, `peer_id`) as **structured metadata** —
queryable (`{…} | slot="123"`) and visible in Grafana log-details, but NOT indexed
as stream labels, so stream cardinality stays bounded. Indexed labels stay low-card:
`network` (SAME value as prometheus), `node` (`<client>_N`, e.g. `zeam_8`), `client_type`,
`instance`, `stream`, `level`. **Rule of thumb:** low-cardinality → label; high-
cardinality → structured metadata (or a query-time `unwrap` metric / promtail
`metrics` stage), NEVER a label. The `match |= "="` gate keeps `logfmt` off lines
with no fields (e.g. multi-line tree dumps) so the per-line CPU cost stays low.
Requires Loki `allow_structured_metadata: true` + schema v13/tsdb (both already set).

**First-start backlog is the one trap.** docker_sd has no `since`, so with an empty
`positions.yaml` promtail replays each container's ENTIRE retained history. With
large json-file caps (e.g. the old 600m×10 = 6 GiB) that is days of logs:
- Loki rejects everything older than its 7d retention (`400 ... timestamp too old`)
  and rate-limits the firehose (`429 ... ingestion rate limit`, default 4 MB/s).
- promtail burns 1.7–2.5 cores per host *just reading* the backlog — which
  competes with latency-sensitive leanVM block-building and can disturb the devnet.

`promtail-config.sh` bakes in a `drop older_than: 1h` pipeline stage so only recent
lines are *shipped* (no Loki flood, no too-old/429 spam), but promtail still *reads*
the whole backlog to advance its position. So on a host with large logs, **seed the
positions to "now" after first launch** to skip the read entirely:
```bash
POS=/opt/lean-quickstart/observability/promtail-data/positions.yaml
sudo docker stop promtail; N=$(date +%s)
sudo sed -i -E "s/: \"[0-9]+\"/: \"$((N-300))\"/" "$POS"; sudo docker start promtail
```
The positions format is `cursor-<full-container-id>: "<unix-seconds>"` — the value
is the last-read Docker log timestamp, so overwriting it with `now-300` makes
promtail resume ~5 min ago and tail forward. Positions live in the mounted
`promtail-data/` dir (NOT a single-file bind-mount, so `sed -i` is safe here), so the
seed is a one-time per-host fixup; subsequent restarts resume cleanly. CPU drops to
~0.1% once caught up; steady-state shipping of warn/info devnet logs is well under
the 4 MB/s Loki limit. Verify ingestion:
`curl -s <central_ip>:3100/loki/api/v1/label/network/values` (all devnets present)
and a `query_range` on `{network="..."}`. promtail's own `:9080/metrics`
(`promtail_sent_entries_total`, `promtail_request_duration_seconds_count` by
`status_code`, `promtail_dropped_entries_total`) is the definitive "is it shipping?"
check — a 204 status with rising sent-entries means logs are landing even if a
narrow query window shows none yet (verbose hosts lag a few seconds under load).

Reducing the json-file caps (`start-devnet.sh` LOGOPT, now 200m×5 = 1 GiB) also
shrinks the first-start backlog, but the caps only change on container recreate —
they do NOT apply to already-running nodes, so a live fleet keeps its old (possibly
6 GiB) logs until the next cs-restart/convert/fresh-genesis. Until then, seed
positions rather than letting promtail chew through the old backlog.

## Recovering an unreachable host

If a host drops off the network (e.g. OOM starved sshd), it may only be
recoverable via a provider console reboot — there may be no alternate route.
After reboot its old containers auto-start (`--restart unless-stopped`) on the
stale chain. Since each server is an independent devnet, the other devnets are
unaffected and keep finalizing. For the recovered server, either `cs-restart.sh`
its nodes (if the chain is still healthy and you only need them to rejoin) or, if
the chain is dead, stop the stale containers (`docker rm -f`) and start fresh
(`make-genesis.sh` → ship → `start-devnet.sh`). The central
Grafana/Prometheus, if it lives on a different host, keeps showing every other
devnet throughout.
