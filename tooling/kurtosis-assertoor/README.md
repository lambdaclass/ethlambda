# Kurtosis + assertoor battery

Starts a mainnet-preset devnet in kurtosis and runs [assertoor](https://github.com/ethpandaops/assertoor)
checks against every client pair, ethlambda included.

```
participant 1  lighthouse + geth                       lighthouse validator   (bootnode)
participant 2  lighthouse + geth                       ethlambda validator
participant 3  ethlambda beacon + geth                 ethlambda validator
```

| Check | Playbook | What passing shows |
|---|---|---|
| Stability | `stable/stability-check` | Finality, participation, no reorg or fork churn, all nodes synced |
| Block proposals | `stable/block-proposal-check` | Every client pair that holds validators proposed a block |
| Sync | `dev/synchronized-check` | Every CL and EL, `cl-3-ethlambda-geth` included, reports synced |

The devnet comes from `lambdaclass/ethereum-package`, a fork of ethpandaops'
package that adds `cl_type: ethlambda` and `vc_type: ethlambda`. It is pinned to a
commit in `.github/workflows/kurtosis_assertoor.yml` (`ETHEREUM_PACKAGE_REF`).
Assertoor's image and the three playbook URLs are pinned to one assertoor commit
in `network_params.yaml`; bump them together.

## Run it locally

Needs Docker and the kurtosis CLI (CI uses 1.20.0). From the repository root:

```bash
git clone https://github.com/lambdaclass/ethereum-package.git /tmp/ethereum-package
git -C /tmp/ethereum-package checkout 67cb0e02dc0bd49ec9461cbf2ef7ac4a3232755f

kurtosis run /tmp/ethereum-package --enclave ethlambda-assertoor \
  --args-file tooling/kurtosis-assertoor/network_params.yaml

url=$(kurtosis port print ethlambda-assertoor assertoor http)
tooling/kurtosis-assertoor/scripts/wait-assertoor.sh "$url" 3
open "$url"                                   # assertoor web UI

kurtosis enclave rm -f ethlambda-assertoor
```

It runs from a clone because kurtosis refuses a remote package whose
`kurtosis.yml` names another repository, and the fork's still says
`ethpandaops/ethereum-package`. To test a local build, set the ethlambda entries'
`cl_image` and `vc_image` in `network_params.yaml` (default `ghcr.io/lambdaclass/ethlambda:unstable`).
Expect about an hour: the stability check waits for finality at 12 s slots.

## In CI

`.github/workflows/kurtosis_assertoor.yml`:

| Trigger | Image under test |
|---|---|
| push to `main` | `ghcr.io/lambdaclass/ethlambda:sha-<7>`, waited for up to 75 min until `docker_publish.yaml` pushes it |
| pull request touching this directory or the workflow | `ghcr.io/lambdaclass/ethlambda:unstable` |
| manual dispatch | the `image` input, else `unstable` |

The workflow rewrites the ethlambda images with `yq`, runs the battery, and always
uploads the enclave dump and assertoor results (`enclave-dump-<run id>`) before
removing the enclave. A failure on `main` posts the commit, the failed tests and
the run URL to Slack.

## Known failure

Until ethlambda's `/eth/v1/config/spec` reports `GLOAS_FORK_EPOCH`, every test
fails after its 5-minute client health check. Assertoor compares each CL's spec
field by field and marks a node whose spec differs offline (`invalid node
specs: spec mismatch: GloasForkEpoch`); lighthouse reports the far-future
value and ethlambda omits the key. The chain itself is healthy (all nodes share
a head and finalize), so this is a spec-endpoint gap, not a harness problem.

## Commit-Boost check

Starts the same three participants with `mev_type: commit-boost`
(`commit_boost_params.yaml`): a flashbots mev-boost-relay, a reth-rbuilder
builder with its own lighthouse beacon node, and one
[Commit-Boost](https://github.com/Commit-Boost/commit-boost-client) PBS module
per participant, which stands in for MEV-Boost. The package gives the ethlambda
beacon node `--builder <pbs url>` and the ethlambda validator client
`--builder-proposals`. There is no assertoor: the base battery's checks fail on
the spec-endpoint gap above, so `scripts/check-builder-blocks.sh` polls the
ethlambda services' Prometheus metrics instead, for up to the timeout it is given.

| Service | Metric | Shows |
|---|---|---|
| `cl-3-ethlambda-geth` | `lean_beacon_builder_registrations_total{outcome="forwarded"}` >= 1 | Registrations reach the builder through the beacon node |
| `cl-3-ethlambda-geth` | `lean_beacon_builder_payload_source_total{source="builder"}` >= 1 | The beacon node's own `produceBlockV3` took a builder bid |
| `vc-3-geth-ethlambda` | `ethlambda_validator_builder_registrations_sent_total` >= 1 | The validator client registers its validators |
| `vc-3-geth-ethlambda` | `ethlambda_validator_blinded_blocks_proposed_total` >= 1 | It signs and publishes blinded blocks through ethlambda's beacon node |
| `vc-2-geth-lighthouse-ethlambda` | `ethlambda_validator_blinded_blocks_proposed_total` >= 1 | It does the same through a third-party beacon node (lighthouse) |

Passing therefore covers the registration path, a builder block from ethlambda's
own beacon node, and ethlambda's validator client proposing blinded blocks
through lighthouse. The script writes every `lean_beacon_builder_*` and
`ethlambda_validator_*` blinded or registration series of the three services to
`<output-dir>/<service>.prom`, pass or fail, and the unmet conditions to
`failed.txt`.

The relay, builder and PBS images are pinned by digest in
`commit_boost_params.yaml` (the package's defaults are floating tags).

### Run it locally

The image needs the builder support, so build one from the builder PR stack
(#694 to #705) and set it as the `cl_image` and `vc_image` of the ethlambda
entries in `commit_boost_params.yaml`. From the repository root:

```bash
git clone https://github.com/lambdaclass/ethereum-package.git /tmp/ethereum-package
git -C /tmp/ethereum-package checkout 37fe57ea309b954361c0f33ac6efc570313ffaf6

kurtosis run /tmp/ethereum-package --enclave ethlambda-commit-boost \
  --args-file tooling/kurtosis-assertoor/commit_boost_params.yaml

tooling/kurtosis-assertoor/scripts/check-builder-blocks.sh \
  ethlambda-commit-boost 40 /tmp/builder-results

kurtosis enclave rm -f ethlambda-commit-boost
```

### In CI

The `commit-boost` job of `.github/workflows/kurtosis_assertoor.yml` runs on
manual dispatch only. Pick `battery: commit-boost` (or `both`) and give `image`
the tag of an image built from the builder PR stack; the default `assertoor`
runs only the base battery, as before. Its pin is `COMMIT_BOOST_PACKAGE_REF`,
separate from `ETHEREUM_PACKAGE_REF`, and it uploads `commit-boost-enclave-dump-<run id>`.

It is dispatch-only because the image that pushes and pull requests test
(`sha-<7>` of `main`, or `unstable`) does not have `--builder` or
`--builder-proposals` until the builder PR stack is on `main`, so the check
would fail there. Once it lands, drop the event condition on the job to run it
on push and on pull requests.

### The fork pin

`COMMIT_BOOST_PACKAGE_REF` is `37fe57ea309b954361c0f33ac6efc570313ffaf6`, the
commit on the `lambdaclass/ethereum-package` branch `feat/ethlambda-builder-flags`
that adds ethlambda to `apply_external_builder_flags` (`--builder=<url>` for the
beacon node, `--builder-proposals` for the validator client). That branch has
to be pushed before the job can fetch the commit. If the fork PR is
squash-merged, the commit is no longer reachable from the fork's default branch
and may be garbage collected, so re-pin to the squash commit.
