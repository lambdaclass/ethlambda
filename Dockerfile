# syntax=docker.io/docker/dockerfile:1.7-labs

FROM rust:1.92-bookworm AS chef
WORKDIR /app

# Install cargo-chef and system dependencies
RUN cargo install cargo-chef
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config protobuf-compiler

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

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Disable default features (e.g. for `shadow-integration`, which must drop the
# default jemalloc allocator). Set to "--no-default-features" to enable.
ARG NO_DEFAULT_FEATURES=""
ENV NO_DEFAULT_FEATURES=$NO_DEFAULT_FEATURES

# Cargo --locked by default. The Shadow build injects a [patch] (see below) that
# is absent from the committed lockfile, so it must build unlocked: set LOCKED= .
ARG LOCKED="--locked"
ENV LOCKED=$LOCKED

# Local-only: the vendored ethp2p-rs is an out-of-workspace path dep, so
# cargo-chef cook needs its manifests present to resolve. Copying it here
# (before cook) keeps it in the cached dependency layer.
COPY ethp2p-rs ethp2p-rs

RUN cargo chef cook --profile $BUILD_PROFILE $NO_DEFAULT_FEATURES --features "$FEATURES" --recipe-path recipe.json

# Build application
# Include .git so vergen-git2 can extract version info (branch, commit SHA)
COPY --exclude=target . .

# Shadow builds inject the quinn-udp [patch] into the workspace manifest, since a
# Cargo patch cannot be feature-gated and is therefore not committed. Set SHADOW=1.
ARG SHADOW=""
RUN if [ -n "$SHADOW" ]; then cat shadow/cargo-patch.toml >> Cargo.toml; fi

RUN cargo build --profile $BUILD_PROFILE $NO_DEFAULT_FEATURES --features "$FEATURES" $LOCKED --bin ethlambda

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/ethlambda /app/ethlambda

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/lambdaclass/ethlambda
LABEL org.opencontainers.image.description="A minimalist and fast Lean Consensus client written in Rust by LambdaClass"
LABEL org.opencontainers.image.licenses="MIT"

ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown

LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.ref.name=$GIT_BRANCH

# Copy ethlambda over from the build stage
COPY --from=builder /app/ethlambda /usr/local/bin

# Copy licenses
COPY LICENSE ./

# 9000/tcp, 9000/udp - P2P networking
# 9001/udp - QUIC connections
# 5052 - API RPC
# 5054 - Prometheus metrics
EXPOSE 9000/tcp 9000/udp 9001/udp 5052 5054
ENTRYPOINT ["/usr/local/bin/ethlambda"]
