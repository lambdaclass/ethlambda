# Validator Key Generation

`ethlambda keygen` writes the validator XMSS key set and manifest that
`--hash-sig-keys-dir` reads, in the layout `hash-sig-cli generate` produces.

```bash
# One validator's attester and proposer pair
ethlambda keygen --output-dir keys

# A genesis for a three-node devnet
ethlambda keygen --num-validators 3 --output-dir local-devnet/genesis/hash-sig-keys
```

`--output-dir` is the only required flag.

## Why the client generates its own keys

An XMSS key file is only usable by a client built against the same signature
scheme, and the scheme lives in leanVM, which ethlambda pins to one revision.

The trap is that nothing in the file layout changes when the scheme does.
leanVM's move from Poseidon over KoalaBear to BLAKE2s over binary fields kept
the public key at 32 SSZ bytes and the secret key in postcard, so a key set from
the wrong revision satisfies every check a genesis generator makes: the file
names match, the sizes match, and the manifest parses. It fails only later, when
a signature is verified, and then it looks like a consensus bug rather than a
provisioning one.

Generating here removes the second pin. These keys come from the same
`ethlambda-crypto` types the node loads them with, so the generator and the
loader cannot disagree about the format.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--num-validators <N>` | `1` | Validators to generate a key pair for |
| `--log-num-active-epochs <N>` | `18` | Log2 of the slots each key can sign at, from slot 0 |
| `--output-dir <DIR>` | required | Where to write; created if absent |
| `--create-manifest <bool>` | `true` | Write `validator-keys-manifest.yaml` |
| `--distributed` | off | Name validators by public key rather than by index |
| `--force` | off | Replace key files already in `--output-dir` |

Each validator gets **two** independent keys, an attester and a proposer, so it
can sign an attestation and a block in the same slot without spending one slot's
one-time leaf twice.

`--log-num-active-epochs` is the network's lifetime, not a tuning knob: a key
cannot sign past its range, and the range is fixed at generation. At the default
cadence 2^18 slots is about 12 days, after which every validator holding such a
key stops signing.

`--force` is off by default because a key is one-time-use material. Replacing a
set that validators are still signing with makes each of them sign twice at the
same slot, under a key someone else now holds.

## Output

```
hash-sig-keys/
├── validator_0_attester_key_pk.ssz   32 bytes, SSZ
├── validator_0_attester_key_sk.ssz   postcard
├── validator_0_proposer_key_pk.ssz
├── validator_0_proposer_key_sk.ssz
├── validator_1_...
└── validator-keys-manifest.yaml
```

The `.ssz` extension on a secret key is a misnomer kept for the tooling's sake:
SSZ has no encoding for one, so it is postcard.

`hash-sig-cli` had an `--export-format both` that additionally dumped each key as
serde JSON. Its own help called that legacy and nothing reads it, so this writes
only the form above and takes no format flag. A caller carrying
`--export-format ssz` from the old invocation has to drop it.

## The manifest

```yaml
key_scheme: XmssTargetSumLifetime32Dim42Base8
hash_function: BLAKE2s
encoding: TargetSum
pubkey_bytes: 32
lifetime: 4294967296
leanvm_rev: 5a4f55c1138759f43f78483a7b70fde973e4a1ee
log_num_active_epochs: 18
num_active_epochs: 262144
num_validators: 3

validators:
  - index: 0
    proposer_key_pubkey_hex: 0x...
    proposer_key_privkey_file: validator_0_proposer_key_sk.ssz
    attester_key_pubkey_hex: 0x...
    attester_key_privkey_file: validator_0_attester_key_sk.ssz
```

`leanvm_rev` is ethlambda's addition, and it is the field to trust. Read against
the scheme parameters alone, two key sets from either side of the BLAKE2s rewrite
are indistinguishable: `key_scheme` is built from the lifetime, `V` and
`CHAIN_LENGTH`, and all three came through that change unaltered. `hash_function`
does separate them but is a hardcoded label, since leanVM's facade exports no
name for its hash. The revision is resolved from `Cargo.lock` at build time and
cannot drift from what the binary actually links.

`generate-genesis.sh` reads `key_scheme` and cross-checks `pubkey_bytes` against
the pubkeys the manifest holds; the rest is informational.

## Cost

Key generation is `O(sqrt(range))` in memory and fans out over the bottom Merkle
subtrees, so a large range is cheaper than it looks: about 3 seconds per
validator at 2^18 epochs on an M4 Max, generated serially. A 1024-validator
genesis is therefore tens of minutes, and worth doing once and keeping.

Building on aarch64 without the crypto extensions makes this, and every other
leanVM operation, far slower. See the aarch64 entry in `.cargo/config.toml`.
