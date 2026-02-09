# Releasing ethlambda

This document describes how we publish and distribute ethlambda. We currently
release via Docker images, published by manually triggering the
["Publish Docker Image" workflow](.github/workflows/docker_publish.yaml).
We don't use GitHub Releases yet.

## Docker images

Images are published to GitHub Container Registry (GHCR) under
`ghcr.io/lambdaclass/ethlambda`. Each publish builds for both `amd64` and
`arm64`, then creates a multi-arch manifest so `docker pull` automatically
fetches the right image for your machine.

## Docker image tags

Every publish automatically creates a `sha-<7chars>` tag (e.g. `sha-12f8377`)
from the commit hash. This makes it easy to trace a running image back to the
exact commit it was built from.

On top of that, the workflow accepts a comma-separated list of custom tags as a
parameter (e.g. `latest,devnet2`). We use the following tagging convention:

- `latest` - the latest image built from the `main` branch
- `devnet2` - the latest image built with `devnet2` support
- `devnet1` - *(deprecated)* `devnet1` support

Future devnets will introduce new tags, with previous ones left without updates.

### Pulling an image

```bash
docker pull ghcr.io/lambdaclass/ethlambda:latest        # latest from main
docker pull ghcr.io/lambdaclass/ethlambda:devnet2        # devnet2-compatible
docker pull ghcr.io/lambdaclass/ethlambda:sha-12f8377    # pinned to a specific commit
```

## Publishing a Docker image

Make sure CI is passing on the branch you want to publish before triggering the
workflow.

To publish a Docker image, follow these steps:

1. Go to the **Actions** tab in GitHub and select the **"Publish Docker Image"** workflow.
2. Click **"Run workflow"**, select the branch (prefer `main`), and enter the tags (e.g. `latest,devnet2`).

The workflow will then:

1. Build `amd64` and `arm64` images in parallel.
2. Push arch-specific images (e.g. `latest-amd64`, `latest-arm64`).
3. Create a multi-arch manifest for each tag.
4. Create an additional `sha-<7chars>` manifest for commit traceability.

## Building locally

You can build a Docker image locally for testing before publishing. The Makefile
provides a shortcut:

```bash
make docker-build                              # Builds with tag "local"
make docker-build DOCKER_TAG=my-test           # Custom tag
```

The Dockerfile accepts build arguments for customizing the build:

| Argument | Default | Description |
|----------|---------|-------------|
| `BUILD_PROFILE` | `release` | Cargo build profile |
| `FEATURES` | `""` | Extra Cargo features (e.g. `skip-signature-verification`) |
| `RUSTFLAGS` | `""` | Extra Rust compiler flags |

Example with custom args:

```bash
docker build --build-arg FEATURES=skip-signature-verification -t ethlambda:test .
```

`GIT_COMMIT` and `GIT_BRANCH` are also available but set automatically by CI.
When building locally, `vergen-git2` extracts them from the local Git repo at
build time.
