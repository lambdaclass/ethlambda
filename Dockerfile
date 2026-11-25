# syntax=docker.io/docker/dockerfile:1.7-labs

FROM rust:1.97-bookworm AS chef
WORKDIR /app

# Install cargo-chef and system dependencies
RUN cargo install cargo-chef
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

# Builds a cargo-chef plan
FROM chef AS planner
COPY --exclude=.git --exclude=target . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Include .cargo/ so [target.*.rustflags] (e.g. -Ctarget-cpu=x86-64-v3) applies to
# cargo-chef's dep build as well as the final cargo build. Without this the
# cached deps are compiled with default flags and cargo reuses them.
COPY .cargo/ .cargo/

# leanVM's PQ prover is compiled once more per CPU tier (AVX-512, GFNI and
# VPCLMULQDQ on x86-64, SHA3 on arm64), and picks the fastest one the host has
# at run time: one image for every host, as the other clients' leanVM builds
# are. A tier only gets its instructions when rustc is wrapped by leanVM's own
# `scripts/tier-rustc`, which adds a tier's target features to that tier's
# crates and leaves every other crate as asked, so the node itself keeps the
# portable baseline in `.cargo/config.toml`. Fetched at the pinned revision
# (`leanvm-revision`, which a test holds equal to the workspace's `rev`), so
# the wrapper is the one the prover's sources were written against. Set before
# `cargo chef cook`, which is what compiles the tiers. A build without the
# `leanvm-cpu-tiers` feature has no tier crates, and the wrapper changes
# nothing in it.
COPY leanvm-revision leanvm-revision
RUN rev="$(tr -d '[:space:]' < leanvm-revision)" \
    && test -n "$rev" \
    && curl -fsSL "https://raw.githubusercontent.com/leanEthereum/leanVM/${rev}/scripts/tier-rustc" \
        -o /usr/local/bin/leanvm-tier-rustc \
    && chmod +x /usr/local/bin/leanvm-tier-rustc
ENV RUSTC_WRAPPER=/usr/local/bin/leanvm-tier-rustc

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Cargo features. `leanvm-cpu-tiers` by default: see the wrapper above.
ARG FEATURES="leanvm-cpu-tiers"
ENV FEATURES=$FEATURES

# Disable default features (e.g. for `shadow-integration`, which must drop the
# default jemalloc allocator). Set to "--no-default-features" to enable.
ARG NO_DEFAULT_FEATURES=""
ENV NO_DEFAULT_FEATURES=$NO_DEFAULT_FEATURES

# Cargo --locked by default. The Shadow build injects a [patch] (see below) that
# is absent from the committed lockfile, so it must build unlocked: set LOCKED= .
ARG LOCKED="--locked"
ENV LOCKED=$LOCKED

RUN cargo chef cook --profile $BUILD_PROFILE $NO_DEFAULT_FEATURES --features "$FEATURES" $LOCKED --recipe-path recipe.json

# Build application
# Include .git so vergen-git2 can extract version info (branch, commit SHA)
COPY --exclude=target . .

# Shadow builds inject the quinn-udp [patch] into the workspace manifest, since a
# Cargo patch cannot be feature-gated and is therefore not committed. Set SHADOW=1.
ARG SHADOW=""
RUN if [ -n "$SHADOW" ]; then cat shadow/cargo-patch.toml >> Cargo.toml; fi

# Channel reported in the client version. vergen reads the branch from .git, but a
# release-candidate tag is checked out detached (it would report "HEAD"), so CI
# passes the tag's `rc.N` suffix here. Left empty, vergen reads .git as before.
ARG GIT_BRANCH=""

RUN if [ -n "$GIT_BRANCH" ]; then export VERGEN_GIT_BRANCH="$GIT_BRANCH"; fi; \
    cargo build --profile $BUILD_PROFILE $NO_DEFAULT_FEATURES --features "$FEATURES" $LOCKED --bin ethlambda

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/ethlambda /app/ethlambda

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/lambdaclass/ethlambda
LABEL org.opencontainers.image.description="A minimalist and fast Beacon Chain and Lean Chain client written in Rust by LambdaClass"
LABEL org.opencontainers.image.licenses="MIT"

ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG VERSION=dev

LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.ref.name=$GIT_BRANCH
LABEL org.opencontainers.image.version=$VERSION

# Copy ethlambda over from the build stage
COPY --from=builder /app/ethlambda /usr/local/bin
# pq-devnet-0's launcher name, `ethlambda-pq beacon <flags>`, kept for
# launchers that still use it. leanVM bindings v0.17.0 proves in the node, so
# there is no sidecar to start: the script only runs `ethlambda`. The leanVM
# revision the node proves with is the one in `leanvm-revision`.
COPY --chmod=755 bin/ethlambda/pq/ethlambda-pq /usr/local/bin/ethlambda-pq
COPY leanvm-revision /usr/local/share/ethlambda/leanvm-revision

# Copy licenses
COPY LICENSE ./

# 9000/tcp, 9000/udp - P2P networking (discv5: always on for beacon, --discovery.enable for node; --discovery.port)
# 9001/udp - libp2p QUIC connections
# 9001/tcp - libp2p TCP (noise + yamux) connections, the fallback transport
# 5052 - API RPC
# 5054 - Prometheus metrics
#
# The swarm binds both protocols on 9001 and the ENR advertises both, so a `tcp`
# entry with no mapping behind it is worse than none: every peer racing the
# address list burns a connect timeout on a black-holed port.
EXPOSE 9000/tcp 9000/udp 9001/udp 9001/tcp 5052 5054
ENTRYPOINT ["/usr/local/bin/ethlambda"]
