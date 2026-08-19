#!/usr/bin/env python3
"""Rewrite annotated_validators.yaml so each node's validators share one subnet.

WHY: the client derives a validator's attestation subnet from its own global
index (`vid % ACC`, see p2p::attestation_subscription_subnets) -- the `subnet`
field in validator-config.yaml is not consulted. lean-quickstart's
generate-genesis.sh hands node i the CONTIGUOUS block [i*vpn, (i+1)*vpn), so at
vpn == ACC every node ends up owning exactly one validator in every subnet and
therefore subscribes to all of them. Permuting the key files cannot fix that:
the subnet is a property of the index, not of the key sitting at it.

So we reassign which indices each node owns:

    s = i % S                      subnet of node i (round-robin, so the
                                   aggregators 0..S-1 stay one-per-subnet)
    g = i // S                     which block of nodes within that subnet
    indices = [s + S*(g*vpn + k) for k in range(vpn)]

Every index in that set is congruent to s mod S, so the node holds validators
from subnet s only and subscribes to exactly that one subnet. The map is a
bijection onto 0..N*vpn-1 (index = s + S*m with m = g*vpn + k covering 0..N*vpn/S-1
once per s), and it degenerates to the identity when vpn == 1.

Rebuilt from the key manifest rather than by permuting the existing file, then
cross-checked against config.yaml's GENESIS_VALIDATORS so an index/pubkey skew
fails loudly instead of producing a chain whose signatures never verify.

Usage: subnet-align-validators.py GENESIS_DIR NODES SUBNETS VALIDATORS_PER_NODE
"""
import sys
from collections import defaultdict
from pathlib import Path

import yaml


class HexSafeLoader(yaml.SafeLoader):
    """SafeLoader that does not coerce `0x...` scalars to int.

    The key manifest stores pubkeys as unquoted `0x<hex>`, and PyYAML's YAML 1.1
    int resolver matches that -- turning a pubkey into an int and breaking the
    comparison against config.yaml's quoted string form. yq (YAML 1.2, used by
    generate-genesis.sh) keeps it a string, so this loader matches yq.
    """


HexSafeLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers
          if tag != "tag:yaml.org,2002:int"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__)
        return 2
    gdir = Path(sys.argv[1])
    nodes, subnets, vpn = (int(x) for x in sys.argv[2:5])
    total = nodes * vpn

    if nodes % subnets:
        print(f"ERROR: NODES ({nodes}) must be divisible by SUBNETS ({subnets}) "
              "for an equal-sized, subnet-homogeneous split")
        return 1

    manifest = yaml.load(
        (gdir / "hash-sig-keys" / "validator-keys-manifest.yaml").read_text(),
        Loader=HexSafeLoader)
    entries = {int(v["index"]): v for v in manifest["validators"]}
    if len(entries) < total:
        print(f"ERROR: manifest has {len(entries)} validators, need {total}")
        return 1

    # --- assignment ---------------------------------------------------------
    assignment: dict[str, list[int]] = {}
    for i in range(nodes):
        s, g = i % subnets, i // subnets
        assignment[f"node_{i}"] = [s + subnets * (g * vpn + k) for k in range(vpn)]

    # bijection + homogeneity checks
    flat = [idx for idxs in assignment.values() for idx in idxs]
    if sorted(flat) != list(range(total)):
        print("ERROR: assignment is not a bijection onto 0..%d" % (total - 1))
        return 1
    for name, idxs in assignment.items():
        if len({idx % subnets for idx in idxs}) != 1:
            print(f"ERROR: {name} spans multiple subnets: {idxs}")
            return 1

    # --- cross-check index -> pubkey against config.yaml --------------------
    cfg = yaml.safe_load((gdir / "config.yaml").read_text())
    gvs = cfg["GENESIS_VALIDATORS"]
    if len(gvs) != total:
        print(f"ERROR: config.yaml has {len(gvs)} GENESIS_VALIDATORS, need {total}")
        return 1
    for idx in range(total):
        want_att = entries[idx]["attester_key_pubkey_hex"].removeprefix("0x").lower()
        want_pro = entries[idx]["proposer_key_pubkey_hex"].removeprefix("0x").lower()
        got_att = str(gvs[idx]["attestation_pubkey"]).removeprefix("0x").lower()
        got_pro = str(gvs[idx]["proposal_pubkey"]).removeprefix("0x").lower()
        if (want_att, want_pro) != (got_att, got_pro):
            print(f"ERROR: index {idx} pubkey mismatch between manifest and "
                  f"config.yaml\n  manifest att={want_att}\n  config   att={got_att}")
            return 1

    # --- emit ---------------------------------------------------------------
    per_subnet: dict[int, list[str]] = defaultdict(list)
    lines = [
        "# node -> validator assignment, SUBNET-HOMOGENEOUS.",
        f"# {nodes} nodes x {vpn} validators = {total} validators over {subnets} subnets.",
        "# Node i owns only validators of subnet i % "
        f"{subnets} (indices s + {subnets}*(g*{vpn}+k)), so it subscribes to that",
        "# one subnet instead of all of them. Generated by subnet-align-validators.py;",
        "# do not hand-edit -- regenerate.",
        "",
    ]
    for i in range(nodes):
        name = f"node_{i}"
        idxs = assignment[name]
        per_subnet[i % subnets].append(name)
        lines.append(f"{name}:   # subnet {i % subnets}, validators {idxs}")
        for idx in idxs:
            e = entries[idx]
            for role in ("attester", "proposer"):
                pk = e[f"{role}_key_pubkey_hex"].removeprefix("0x")
                lines.append(f"  - index: {idx}")
                lines.append(f"    pubkey_hex: {pk}")
                lines.append(f"    privkey_file: {e[f'{role}_key_privkey_file']}")
        lines.append("")
    out = gdir / "annotated_validators.yaml"
    out.write_text("\n".join(lines))

    # Re-parse to prove the client's serde_yaml_ng will accept the shape.
    back = yaml.safe_load(out.read_text())
    assert len(back) == nodes, f"{len(back)} nodes in output, expected {nodes}"
    for name, idxs in assignment.items():
        got = back[name]
        assert len(got) == 2 * vpn, f"{name}: {len(got)} entries, want {2 * vpn}"
        assert sorted({e["index"] for e in got}) == sorted(idxs)
        atts = [e for e in got if "attester" in e["privkey_file"]]
        pros = [e for e in got if "proposer" in e["privkey_file"]]
        assert len(atts) == len(pros) == vpn, f"{name}: role split wrong"

    print(f"annotated_validators.yaml rewritten: {nodes} nodes x {vpn} validators")
    for s in sorted(per_subnet):
        members = per_subnet[s]
        print(f"  subnet {s}: {len(members)} nodes ({members[0]}..{members[-1]}), "
              f"{len(members) * vpn} validators")
    print(f"  node_0 -> {assignment['node_0']}    node_1 -> {assignment['node_1']}")
    print(f"  node_{nodes - 1} -> {assignment[f'node_{nodes - 1}']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
