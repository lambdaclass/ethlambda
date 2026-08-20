#!/usr/bin/env python3
"""Merge hash-sig key shards into one canonical, sequentially-indexed key dir.

hash-sig-cli always emits validator_0..validator_{N-1}, so generating a key set
across several machines produces colliding indices. This reindexes each shard
into a single 0..TOTAL-1 namespace (shards concatenated in argument order) and
regenerates the manifest that lean-quickstart's generate-genesis.sh reads
positionally.

Refuses to merge shards whose scheme/pubkey width differ: that mismatch is
exactly how stale 52-byte (Dim46) keys would silently poison a 32-byte
(Dim42) leanVM-main genesis.

Usage: merge-keyshards.py OUTDIR SHARD_DIR [SHARD_DIR ...]
"""
import re
import shutil
import sys
from pathlib import Path

import yaml

ROLES = ("attester", "proposer")
PARTS = ("pk", "sk")


class HexSafeLoader(yaml.SafeLoader):
    """SafeLoader that does not coerce `0x...` scalars to int.

    The manifest stores pubkeys as unquoted `0x<hex>`. PyYAML follows YAML 1.1,
    whose int resolver matches `0x[0-9a-fA-F]+`, so a plain safe_load turns a
    pubkey into a Python int and round-tripping it writes a DECIMAL -- which yq
    (YAML 1.2, keeps it a string) then rejects downstream, and which would also
    silently drop any leading zero byte. Dropping the int resolver keeps every
    scalar a str; callers int() the few numeric fields they actually use.
    """


HexSafeLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers
          if tag != "tag:yaml.org,2002:int"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
# Header fields that must agree across every shard (they define the key format).
CRITICAL = ("key_scheme", "hash_function", "encoding", "pubkey_bytes",
            "lifetime", "log_num_active_epochs", "num_active_epochs")


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    outdir = Path(sys.argv[1])
    shards = [Path(p) for p in sys.argv[2:]]

    header: dict | None = None
    merged: list[dict] = []
    # (src_shard, src_index) per destination index, for the file copy pass.
    provenance: list[tuple[Path, int]] = []

    for shard in shards:
        manifest_path = shard / "validator-keys-manifest.yaml"
        man = yaml.load(manifest_path.read_text(), Loader=HexSafeLoader)
        fields = {k: man.get(k) for k in CRITICAL}
        if header is None:
            header = fields
        elif fields != header:
            diff = {k: (header[k], fields[k]) for k in CRITICAL
                    if header[k] != fields[k]}
            print(f"ERROR: {shard} key format differs from first shard: {diff}")
            return 1

        entries = man["validators"]
        # Pubkeys must survive as literal 0x-hex of the declared width: a non-str
        # here means the int-resolver crept back in, and a short one means a
        # leading zero byte was lost.
        want_width = 2 * int(header["pubkey_bytes"])
        for entry in entries:
            for role in ROLES:
                pk = entry[f"{role}_key_pubkey_hex"]
                if not isinstance(pk, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", pk):
                    print(f"ERROR: {shard} validator {entry['index']} {role} "
                          f"pubkey is not a 0x-hex string: {pk!r}")
                    return 1
                if len(pk) - 2 != want_width:
                    print(f"ERROR: {shard} validator {entry['index']} {role} pubkey "
                          f"is {len(pk) - 2} hex chars, expected {want_width}")
                    return 1
        # Trust the manifest's own ordering, but key the copy off its recorded
        # index rather than list position so a sparse shard can't silently shift.
        for entry in entries:
            src_index = int(entry["index"])
            dst_index = len(merged)
            merged.append({
                "index": dst_index,
                "proposer_key_pubkey_hex": entry["proposer_key_pubkey_hex"],
                "proposer_key_privkey_file":
                    f"validator_{dst_index}_proposer_key_sk.ssz",
                "attester_key_pubkey_hex": entry["attester_key_pubkey_hex"],
                "attester_key_privkey_file":
                    f"validator_{dst_index}_attester_key_sk.ssz",
            })
            provenance.append((shard, src_index))
        print(f"  {shard.name}: {len(entries)} validators")

    outdir.mkdir(parents=True, exist_ok=True)
    for dst_index, (shard, src_index) in enumerate(provenance):
        for role in ROLES:
            for part in PARTS:
                src = shard / f"validator_{src_index}_{role}_key_{part}.ssz"
                dst = outdir / f"validator_{dst_index}_{role}_key_{part}.ssz"
                if not src.exists():
                    print(f"ERROR: missing {src}")
                    return 1
                shutil.copy2(src, dst)

    assert header is not None
    out_manifest = dict(header)
    out_manifest["num_validators"] = len(merged)
    # Emit in the same field order hash-sig-cli uses, then the validator list.
    lines = [
        "# Hash-Signature Validator Keys Manifest",
        "# Generated by hash-sig-cli, reindexed by merge-keyshards.py",
        f"# Shards merged in order: {', '.join(s.name for s in shards)}",
        "",
    ]
    for key in CRITICAL:
        lines.append(f"{key}: {out_manifest[key]}")
    lines.append(f"num_validators: {len(merged)}")
    lines.append("")
    lines.append("validators:")
    for entry in merged:
        lines.append(f"  - index: {entry['index']}")
        lines.append(
            f"    proposer_key_pubkey_hex: {entry['proposer_key_pubkey_hex']}")
        lines.append(
            f"    proposer_key_privkey_file: {entry['proposer_key_privkey_file']}")
        lines.append(
            f"    attester_key_pubkey_hex: {entry['attester_key_pubkey_hex']}")
        lines.append(
            f"    attester_key_privkey_file: {entry['attester_key_privkey_file']}")
        lines.append("")
    (outdir / "validator-keys-manifest.yaml").write_text("\n".join(lines))

    # Re-read through yaml to prove generate-genesis.sh's yq will parse it, and
    # that pubkeys survived the reindex unchanged.
    check = yaml.load((outdir / "validator-keys-manifest.yaml").read_text(),
                      Loader=HexSafeLoader)
    assert int(check["num_validators"]) == len(merged)
    assert [int(v["index"]) for v in check["validators"]] == list(range(len(merged)))
    # The regression this guards: pubkeys must remain 0x-hex TEXT on the way out,
    # not decimals produced by an int-coercing round-trip.
    for v in check["validators"]:
        for role in ROLES:
            pk = v[f"{role}_key_pubkey_hex"]
            assert isinstance(pk, str) and pk.startswith("0x"), \
                f"validator {v['index']} {role} pubkey not 0x-hex text: {pk!r}"
    dupes = len({v["attester_key_pubkey_hex"] for v in merged}) != len(merged)
    print(f"\nmerged {len(merged)} validators -> {outdir}")
    print(f"  key_scheme={header['key_scheme']} "
          f"pubkey_bytes={header['pubkey_bytes']}")
    print(f"  duplicate attester pubkeys: {dupes}")
    return 1 if dupes else 0


if __name__ == "__main__":
    sys.exit(main())
