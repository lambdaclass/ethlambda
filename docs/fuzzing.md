# Fuzzing

Coverage-guided fuzzing of the code a remote peer drives: every parser a
gossip message or a req/resp stream goes through, and the req/resp codec
that runs them, before the node decides anything about it. The targets live in `fuzz/`, a `cargo-fuzz` (libFuzzer)
crate at the repo root, and run on demand; there is no scheduled job yet.

## Running

Once:

```bash
cargo install cargo-fuzz --locked
```

`fuzz/rust-toolchain.toml` pins the nightly `cargo fuzz` needs (the same date
the dependency cooldown check installs), so nothing else changes toolchain.

```bash
make fuzz-list                              # the targets
make fuzz FUZZ_TARGET=beacon_gossip_decode  # one target, until Ctrl-C
make fuzz-smoke                             # every target, 60 s each
make fuzz-smoke FUZZ_SECONDS=600            # ... 10 minutes each
```

`FUZZ_ARGS` goes to libFuzzer; the default is `-timeout=10 -rss_limit_mb=2048`,
because a decoder that needs ten seconds or two gigabytes on one input is a
finding, not a flake. Any libFuzzer flag can be added, for example
`FUZZ_ARGS="-timeout=10 -max_len=65536"` to grow inputs past the default 4 KiB.

A run that finds something stops and writes the input to
`fuzz/artifacts/<target>/crash-<hash>` (or `timeout-<hash>`,
`oom-<hash>`), and prints the panic and the stack. Reproduce it with

```bash
cd fuzz && cargo fuzz run <target> artifacts/<target>/crash-<hash>
```

and shrink it to the smallest input that still fails with

```bash
cd fuzz && cargo fuzz tmin <target> artifacts/<target>/crash-<hash>
```

The corpus a run grows is kept in `fuzz/corpus/<target>/` (git-ignored) and
reused by the next run of the same target, so coverage accumulates across
runs on one machine.

## What is fuzzed

Each target is one binary with one property, documented at the top of its
file in `fuzz/fuzz_targets/`. A target that covers a family of decoders
takes its first input byte as a selector, so libFuzzer mutates the choice
along with the payload (`ethlambda_fuzz::split`).

| Target | Entry point | Property |
|---|---|---|
| `snappy_raw` | `decompress_message`, `compress_message` | never panics, output under `MAX_PAYLOAD_SIZE`, compress then decompress is the identity |
| `topic_strings` | lean `topic_kind`; beacon `topics::*` | never panics on any string |
| `enr_parse` | `parse_enrs` | never panics, fed raw, `enr:`-prefixed and base64url-encoded so the RLP decoder is reached |
| `lean_gossip_ssz` | `SignedBlock`, `SignedAttestation`, `SignedAggregatedAttestation` | never panics; a decoded value re-encodes to bytes that decode |
| `lean_req_resp_ssz` | `lean::encoding::decode_request`, `decode_status_response` | never panics; an unknown protocol id decodes nothing |
| `beacon_gossip_decode` | `beacon::decode::decode_gossip` under `Config::mainnet()` | never panics; an unsubscribed kind is `UnknownTopic` |
| `beacon_slot_readers` | `block_slot`, `aggregate_slot`, `attester_slashing_slot` | never panic; agree with the full decode's slot |
| `beacon_status_metadata` | `beacon::encoding::decode_status`, `decode_metadata` | never panics for every protocol version; unknown id refused |
| `beacon_container_ssz` | `SignedBeaconBlock::from_ssz`, `DataColumnSidecar`, `Attestation` per fork; the gloas and sync committee decoders | never panics for every `ForkName::ALL` entry |
| `xmss_decode` | `ValidatorSignature`, `ValidatorPublicKey`, `MultiMessageAggregate` `from_bytes` | never panics (decode only, no verification) |
| `varint` | `decode_varint`, `encode_varint` | never panics; decode consumes input; every `u32` round-trips |
| `snappy_framed` | `decode_payload`, `write_payload` | never panics, output under `MAX_PAYLOAD_SIZE`, compressed size within what was read, write then decode is the identity |
| `chunked_response` | `read_chunked_response` under every `ChunkLimits` | never panics; context width as promised; never more chunks than the limit |
| `codec_lean` | `Codec::lean()` `read_request`/`read_response` per lean protocol | never panics; a beacon protocol is refused; what was read writes and reads back the same |
| `codec_beacon` | `Codec::beacon(..)` under `Config::mainnet()` per beacon protocol | as `codec_lean`, plus context bytes against the fork digest and per-protocol chunk limits |
| `message_id` | the gossipsub message id | always 20 bytes, deterministic, sensitive to the topic |

Generic SSZ decoding is not fuzzed here: `lambdaclass/libssz` runs its own
targets for that, differential against lighthouse's `ethereum_ssz`.

## Design

- **A separate workspace.** `fuzz/Cargo.toml` declares its own `[workspace]`,
  so `libfuzzer-sys`, `arbitrary` and the nightly toolchain never enter the
  production lockfile or build. Its lockfile is covered by
  `make cooldown-check` like the other two.
- **`fuzzing` feature on `ethlambda-p2p`.** The gossip codec helpers, the
  lean topic parser, the req/resp framing functions and a wrapper over the
  message-id function are crate-private; the feature re-exports them for the
  fuzz crate without widening the production API. The next layer (validation
  rules with an in-memory store, discovery admission) will use the same
  feature.
- **The codec over a cursor.** `Codec` is async over libp2p's `AsyncRead`, so
  the targets drive it from `futures::io::Cursor` with `block_on`: the whole
  inbound path as libp2p runs it, with no socket and no runtime. The fuzz
  crate depends on the same libp2p fork and rev as the P2P crate, so the
  `StreamProtocol` and `gossipsub::Message` it builds are the codec's own
  types.
- **libssz pinned to the workspace's rev.** The fuzz crate names the same git
  rev the root `Cargo.toml` does, so it cannot fuzz a different decoder than
  the one the node ships.
- **Layering.** The first ten targets are layer 0, the wire parsers; the
  six from `varint` on are layer 1, the framing and the codec as libp2p
  drives them. The plan is bottom-up: next are the validation rules with an
  in-memory store, then the live actor under a hostile peer. A bug in a lower
  layer hides everything above it.

## When a target fails

1. Reproduce from the artifact (above) and minimise it with `tmin`.
2. Add the minimised bytes as a `#[test]` in the crate that owns the parser,
   asserting the error it should return.
3. Fix the parser in its own PR, linking the artifact. The fuzz target stays.

## References

- cargo-fuzz and libFuzzer flags: <https://rust-fuzz.github.io/book/>
- libssz's fuzz crate, the layout this one copies: <https://github.com/lambdaclass/libssz/tree/main/fuzz>
- The beacon wire these parsers implement: [beacon_wire.md](./beacon_wire.md)
