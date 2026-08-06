#!/usr/bin/env bash
# Builds each fuzz target's seed corpus from the real fixture tree.
#
# Usage: ./seed_corpus.sh [target ...]
#   ./seed_corpus.sh                              # seed all three targets
#   ./seed_corpus.sh ssz_roundtrip                 # seed just one
#
# This is a thin wrapper: all the actual work is in
# examples/seed_corpus.rs, which is a normal Rust program (no `cargo-fuzz`
# or nightly toolchain needed to run it) so that decompressing the fixtures'
# `.ssz_snappy` files can reuse the `snap` crate instead of re-implementing
# raw snappy decompression in shell.
#
# Requires the consensus-spec-tests fixtures to already be on disk; run
# `make consensus-spec-tests` from the repository root first if they are not.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

cargo run --example seed_corpus --release -- "$@"
