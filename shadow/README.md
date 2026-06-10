# Shadow simulator integration

Build support for running ethlambda under the [Shadow] network simulator,
used by the [lean-shadow-fuzzer]. Everything here is **opt-in**: a normal
`cargo build` / `make docker-build` is completely unaffected, and the committed
`Cargo.toml` / `Cargo.lock` are identical to a Shadow-free checkout.

## Why Shadow needs special handling

Shadow runs the real binary but emulates time, threads, and the network. Three
things in a stock ethlambda build need to change for Shadow:

| Area | Stock build | Under Shadow | Why |
|------|-------------|--------------|-----|
| Allocator | jemalloc with `unprefixed_malloc` (interposes the global C `malloc`) | system allocator (drop jemalloc) | Self-deadlocks at startup ([shadow#3763]) |
| QUIC UDP I/O | `quinn-udp` uses GSO/GRO batch syscalls (`sendmmsg`, segmentation offload) | fall back to `send_to`/`recv_from` | Shadow's UDP emulation doesn't support those batch syscalls. |
| Tokio runtime | multi-threaded | `current_thread` | Shadow single-steps execution, so worker threads add only scheduling noise. |

The allocator change (dropping jemalloc) and the runtime flavor are gated behind
the `shadow-integration` Cargo feature (jemalloc is dropped via
`--no-default-features`). The quinn-udp change is a Cargo `[patch]`, which
**cannot** be feature-gated, so it is injected into the manifest only at build
time (see below). Of the three, only the allocator and quinn-udp changes are
correctness requirements; the single-threaded runtime is purely a performance
choice.

## Contents

| Path | Purpose |
|------|---------|
| `quinn-udp-patch/` | Drop-in `quinn-udp` replacement (package name stays `quinn-udp`) routing every send/receive through plain `send_to`/`recv_from`, batch size 1 |
| `cargo-patch.toml` | The `[patch.crates-io]` snippet appended to the workspace `Cargo.toml` for Shadow builds |
| `build.sh` | Runs a cargo command with the patch temporarily injected, then restores `Cargo.toml` + `Cargo.lock` |

## Building

```bash
# Local binary (release, single-threaded, no jemalloc, quinn-udp fallback)
make shadow-build

# Docker image, tagged ...:<DOCKER_TAG>-shadow
make shadow-docker-build
```

`make shadow-build` is a thin wrapper around:

```bash
./shadow/build.sh cargo build --release \
    --no-default-features --features shadow-integration --bin ethlambda
```

`shadow/build.sh` can run any cargo command against the patched workspace, e.g.:

```bash
./shadow/build.sh cargo check  --no-default-features --features shadow-integration
./shadow/build.sh cargo clippy --no-default-features --features shadow-integration
```

It backs up `Cargo.toml` and `Cargo.lock`, appends `cargo-patch.toml`, runs the
command, and restores both files on exit (even on failure), so the working tree
is left pristine.

> [!NOTE]
> `--no-default-features` is required, not optional: Cargo features are additive,
> so the `shadow-integration` feature cannot *remove* the default `jemalloc`
> dependency on its own. A `compile_error!` in `bin/ethlambda/src/main.rs` fires
> if `shadow-integration` is built with jemalloc still enabled.

## Docker

`make shadow-docker-build` passes these build args to the standard `Dockerfile`:

| Arg | Value | Effect |
|-----|-------|--------|
| `SHADOW` | `1` | Appends `shadow/cargo-patch.toml` to `Cargo.toml` before the build |
| `FEATURES` | `shadow-integration` | Enables the feature |
| `NO_DEFAULT_FEATURES` | `--no-default-features` | Drops jemalloc |
| `LOCKED` | (empty) | Builds unlocked, since the injected patch is absent from the committed lockfile |

[Shadow]: https://shadow.github.io/
[lean-shadow-fuzzer]: https://github.com/kamilsa/lean-shadow-fuzzer
[shadow#3763]: https://github.com/shadow/shadow/issues/3763
