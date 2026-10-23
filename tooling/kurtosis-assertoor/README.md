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
