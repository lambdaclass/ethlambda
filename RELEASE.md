# Releasing ethlambda

This document describes how we publish and distribute ethlambda: Docker images on
GitHub Container Registry (`ghcr.io/lambdaclass/ethlambda`) and binaries attached
to [GitHub Releases](https://github.com/lambdaclass/ethlambda/releases).

A release is cut as a **release candidate** (`vX.Y.Z-rc.N`), tested, and then
**promoted** to the final version (`vX.Y.Z`). Promotion re-publishes the tested
candidate's images rather than rebuilding them, so what ships is what was tested.

Three workflows do the publishing:

| Workflow | Trigger | Publishes |
|----------|---------|-----------|
| [Release](.github/workflows/release.yaml) | push to `main` | `unstable`, `sha-<7>` (and `-shadow` twins). It also builds the binaries and the changelog, publishing neither, so a broken release path fails on the commit that broke it |
| | push of a `vX.Y.Z-rc.N` tag | `X.Y.Z-rc.N` image, binaries, GitHub pre-release |
| | manual run, given a `vX.Y.Z-rc.N` tag | nothing: a dry run of pushing that tag on the chosen ref. It shows the pre-release it would create and keeps its assets as a workflow artifact |
| [Release promotion](.github/workflows/release_promote.yaml) | a pre-release edited into a final release, or manual run | `X.Y.Z`, `latest` |
| [Publish Docker Image](.github/workflows/docker_publish.yaml) | manual run | devnet and other ad-hoc tags, plus `sha-<7>` (and `-shadow` twins) |

## Docker image tags

| Tag | Moves? | Source |
|-----|--------|--------|
| `latest` | yes | the latest promoted release |
| `X.Y.Z` | no | a promoted release |
| `X.Y.Z-rc.N` | no | a release candidate |
| `unstable` | yes | the latest commit on `main` |
| `sha-<7chars>` | no | a specific commit (e.g. `sha-12f8377`) |
| `devnetX` | yes | the latest image built with `devnetX` support, published by hand |

Images are multi-arch (`amd64` and `arm64`), so `docker pull` fetches the right
one for your machine. Images from `main` and from the manual workflow also come
as a Shadow-simulator build, tagged with a `-shadow` suffix (e.g.
`unstable-shadow`). Release images do not.

```bash
docker pull ghcr.io/lambdaclass/ethlambda:latest        # latest release
docker pull ghcr.io/lambdaclass/ethlambda:unstable      # latest from main
docker pull ghcr.io/lambdaclass/ethlambda:devnet5       # devnet5-compatible
docker pull ghcr.io/lambdaclass/ethlambda:sha-12f8377   # pinned to a specific commit
```

## Release binaries

Every release candidate attaches these binaries, plus a `SHA256SUMS` file:

| Asset | Platform |
|-------|----------|
| `ethlambda-linux-x86_64` | Linux x86_64, glibc 2.35+ (built on Ubuntu 22.04). Targets x86-64-v3, so it needs AVX2 (Haswell or later) |
| `ethlambda-linux-aarch64` | Linux aarch64, glibc 2.35+ |
| `ethlambda-macos-aarch64` | macOS on Apple silicon |

Every asset, `SHA256SUMS` included, comes with a minisign signature
(`<asset>.minisig`).

## Verifying a release

Releases are verifiable two independent ways:

- **minisign signatures**, made with the project's key. Its public key is
  committed at [`.github/minisign.pub`](.github/minisign.pub); take it from the
  repository rather than from a release, since whoever could replace a release's
  assets could replace a key shipped beside them.
- **GitHub build provenance attestations** (Sigstore), which tie the binaries
  and the images to the workflow run and commit that built them. Final images
  are re-stamped at promotion, so they are attested by the promotion run.

```bash
# minisign: the trusted comment names the asset, the tag and the commit
minisign -Vm ethlambda-linux-x86_64 -p minisign.pub

# attestations, for a binary and for an image
gh attestation verify ethlambda-linux-x86_64 --repo lambdaclass/ethlambda
gh attestation verify oci://ghcr.io/lambdaclass/ethlambda:X.Y.Z --repo lambdaclass/ethlambda
```

## Version string

`ethlambda --version` reports a channel between the version and the commit:

```
ethlambda/v0.2.0-rc.1-<sha>/x86_64-unknown-linux-gnu/rustc-v1.97.1    # candidate
ethlambda/v0.2.0-stable-<sha>/x86_64-unknown-linux-gnu/rustc-v1.97.1  # promoted image
ethlambda/v0.2.0-main-<sha>/x86_64-unknown-linux-gnu/rustc-v1.97.1    # built from main
```

The channel is baked in at build time (the git branch, or the `rc.N` suffix of a
candidate tag), and the `ETHLAMBDA_CHANNEL` environment variable overrides it at
runtime. Promotion sets `ETHLAMBDA_CHANNEL=stable` on the image config, which is
how the promoted image reports `stable` while running the candidate's binary.
The release binaries are the candidate's, so they keep reporting `rc.N`.

## Signing key

The Release workflow signs with the minisign key in the `MINISIGN_SECRET_KEY` and
`MINISIGN_PASSWORD` repository secrets. It refuses to publish from this
repository when the key is missing, or when it does not match
`.github/minisign.pub`. Attestations need no setup.

To create the key (once), or to rotate it:

```bash
minisign -G -p .github/minisign.pub -s minisign.key   # prompts for a password
gh secret set MINISIGN_SECRET_KEY --repo lambdaclass/ethlambda < minisign.key
gh secret set MINISIGN_PASSWORD --repo lambdaclass/ethlambda   # prompts for it
```

Then commit `.github/minisign.pub` through a PR, and keep `minisign.key` and its
password in the team's password manager. A rotation takes effect when both the
secret and the committed key have changed; until then every release run fails
on the mismatch, which is the point.

## Cutting a release

### 1. Create the release branch

```bash
git switch -c release/vX.Y.Z origin/main
```

### 2. Bump the version

Set `version` under `[workspace.package]` in the root `Cargo.toml` to `X.Y.Z`.
Every workspace crate inherits it, so this is the only place to change. Then
refresh the lockfile, which should only touch the `ethlambda-*` entries:

```bash
cargo update --workspace
```

Commit and push the branch. The Release workflow refuses a tag whose `X.Y.Z`
differs from this version, since the binary reports the Cargo version, not the
tag.

> [!TIP]
> Dry-run the tag before pushing it: **Actions → Release → Run workflow** on
> `release/vX.Y.Z`, with `rc_tag` set to `vX.Y.Z-rc.1`. It runs everything a push
> of that tag would, including the version check, and publishes nothing. The run
> summary shows the pre-release it would create, and the assets are kept as the
> `dry-run-release-assets` artifact.

### 3. Tag a release candidate

```bash
git tag vX.Y.Z-rc.1
git push origin vX.Y.Z-rc.1
```

The Release workflow then:

1. Builds the `amd64` and `arm64` images, publishes them as `X.Y.Z-rc.1`, and
   attests the image.
2. Builds the binaries listed above.
3. Signs the binaries and `SHA256SUMS` with minisign, and attests the binaries.
4. Creates a GitHub pre-release named after the tag, with the binaries,
   `SHA256SUMS` and the signatures attached and a changelog in its notes.

The changelog lists the [Conventional Commits](https://www.conventionalcommits.org/)
of type `feat`, `fix`, `perf`, `refactor` and `revert` since the previous final
release (never since a previous candidate). A PR title becomes its squashed
commit's subject, so a PR whose title does not follow that format is left out.
The first release has no changelog, as there is nothing to compare against.

### 4. Test the candidate

#### Testing checklist

- [ ] TODO: list the checks every candidate must pass, with the devnets or
  hosts to run them on and the commands to upgrade each one.

Until that list exists, run `ghcr.io/lambdaclass/ethlambda:X.Y.Z-rc.N` on the current devnet and confirm
it keeps finalizing alongside the other clients, and that `--version` reports
`vX.Y.Z-rc.N`. If the release changes what is stored on disk, check what it does
with an existing data directory.

If a fix is needed, commit it to `release/vX.Y.Z`, push, and tag the next
candidate (`vX.Y.Z-rc.2`). The final tag must point at the commit that was tested.

### 5. Promote the candidate

Go to the [releases page](https://github.com/lambdaclass/ethlambda/releases),
click **Edit** on the tested pre-release, and in **one** edit:

1. Change the tag to `vX.Y.Z`, choosing **Create new tag on publish**, and set its
   **Target** to `release/vX.Y.Z` (not `main`).
2. Change the title to `ethlambda vX.Y.Z`.
3. Write the release notes above the generated changelog (see below).
4. Untick **Set as a pre-release** and tick **Set as the latest release**.
5. Click **Update release**.

> [!IMPORTANT]
> The tag rename and the pre-release untick must be saved **in the same edit**.
> The promotion fires on the edit that carries both; split across two saves,
> neither edit does, and `latest` does not move. The `Assert release was
> promoted to latest` job then fails; see [Troubleshooting](#troubleshooting).

The tag only exists once the release is saved. Check it landed on the tested
commit; the two SHAs must be identical:

```bash
git ls-remote origin refs/tags/vX.Y.Z refs/tags/vX.Y.Z-rc.N
```

If they differ, move the final tag onto the candidate's commit:
`git tag -f vX.Y.Z <rc-commit> && git push origin vX.Y.Z --force`.

The Release promotion workflow then publishes `X.Y.Z` and `latest` from the
candidate's images and attests them. It checks that `latest` resolves to
`X.Y.Z`, that the promoted image reports `vX.Y.Z-stable`, and that its
attestation verifies.

#### Release notes

Operators read the notes to decide whether and how to upgrade. Use
[GitHub alerts](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#alerts),
in this order, and drop the boxes that do not apply:

- `> [!IMPORTANT]`: only for critical security or correctness fixes. One line
  saying upgrading is strongly recommended.
- `> [!WARNING]`: only when the upgrade cannot be cleanly undone or breaks
  something the operator must act on: an incompatible database (a resync from
  checkpoint), removed or renamed CLI flags, changed defaults, breaking API
  changes, or a new devnet.
- `> [!NOTE]`: always. A **What's new** list of the highlights, and whether a
  resync is needed.

```markdown
> [!WARNING]
> This release changes the database format; existing data directories cannot be reused. Resync with `--checkpoint-sync-url`.

> [!NOTE]
> **What's new**
> - <highlight>
> - <highlight>
```

### 6. Merge the release branch

Open a PR from `release/vX.Y.Z` into `main` and merge it, so the version bump and
any candidate fixes land on `main`.

## Distribution channels

Releases are published to GitHub Releases and GHCR only. Not covered yet:

- **crates.io**: not possible while the workspace depends on `leanvm` from git,
  since crates.io rejects crates with git dependencies.
- **apt and Homebrew**: future work. Either would be fed from the promoted
  release's binaries, after the release is promoted.

## Troubleshooting

**`latest` did not move after promotion.** Usually the tag rename and the
pre-release untick were saved as two edits. Go to **Actions → Release promotion →
Run workflow** and set `rc_tag` to the tested candidate (e.g. `v0.2.0-rc.1`) and
`version` to the final version (e.g. `v0.2.0`). Its `Verify promotion` job
confirms the result.

**The release run failed after the tag was pushed.** Fix the cause and re-run the
failed jobs. If the pre-release already exists, `Create GitHub pre-release`
replaces its assets instead of failing. If the fix needs a code change, tag the
next candidate instead.

**The tag names the wrong version.** Delete it (`git push origin :refs/tags/vX.Y.Z-rc.N`),
fix the version on the release branch, and tag again.

**`Sign the assets` failed.** The error names the cause. `MINISIGN_SECRET_KEY is
not set` and `could not derive a public key` mean the secrets are missing or the
password is wrong. `does not match .github/minisign.pub` means the key was rotated
in one place only. Fix the secret or the committed key (see
[Signing key](#signing-key)) and re-run the failed jobs. A committed key only
takes effect on a new tag, since the run checks out the tagged commit.

## Publishing devnet images

Devnet tags (`devnetX`) and other ad-hoc tags are published by hand:

1. Make sure CI is passing on the branch you want to publish.
2. Go to **Actions → Publish Docker Image → Run workflow**.
3. Select the branch (prefer `main`) and enter the tags, comma-separated (e.g.
   `devnet5`).

The workflow builds `amd64` and `arm64` images, regular and `-shadow`, and
publishes a multi-arch manifest for each tag plus a `sha-<7chars>` one for the
commit. It refuses `latest`, `unstable`, `sha-*` and version tags, which belong
to the release workflows.

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
| `FEATURES` | `""` | Extra Cargo features |
| `NO_DEFAULT_FEATURES` | `""` | Set to `--no-default-features` to drop default features |
| `LOCKED` | `--locked` | Set empty to build without `--locked` |
| `SHADOW` | `""` | Set to `1` to inject the Shadow simulator's Cargo patch |

Example with custom args:

```bash
docker build --build-arg BUILD_PROFILE=debug -t ethlambda:debug .
```

`GIT_COMMIT`, `GIT_BRANCH` and `VERSION` are set by CI. When building locally,
`vergen-git2` reads the branch and commit from the local Git repo at build time;
a non-empty `GIT_BRANCH` overrides the branch it reports.
