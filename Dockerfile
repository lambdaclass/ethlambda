# syntax=docker.io/docker/dockerfile:1.7-labs

FROM rust:1.92-bookworm AS chef
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

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS="$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Build dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build application
# Include .git so vergen-git2 can extract version info (branch, commit SHA)
COPY --exclude=target . .
RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin ethlambda

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

# Lighthouse-compatible default ports:
# 9000/tcp, 9000/udp - P2P networking
# 9001/udp - QUIC connections
# 5052 - HTTP API
# 5054 - Prometheus metrics
EXPOSE 9000/tcp 9000/udp 9001/udp 5052 5054
ENTRYPOINT ["/usr/local/bin/ethlambda"]
