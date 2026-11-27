"""ethlambda's `block_events` stage names, before and after the rename.

ethlambda renamed its stages to `<section>_start`/`<section>_end`
(lambdaclass/ethlambda#917). Rows written before keep the old names, and
Silver's rows always carry them, so every stage predicate on ethlambda's
ClickHouse matches both: `stage = 'received'` becomes
`stage IN ('received', 'import_start')`, and an `IN` list gains the new name of
each old one it holds. Applied to the finished dashboard, so the SQL builders
keep writing the old names and a re-run gives the same output.
"""
import re

# Old name -> new name. Each pair marks the same instant.
RENAMED = {
    "received": "import_start",
    "el_sent": "el_start",
    "el_verdict": "el_end",
    "stf_spec_start": "cl_start",
    "stf_spec_end": "cl_end",
    "stf_start": "store_start",
    "stf_done": "store_end",
    "attestable": "fc_head_end",
    # Old rows wrote `da_available` only for a block that needed columns and
    # `da_check_end` for the rest; new rows write `da_check_end` for both.
    "da_available": "da_check_end",
    "column_recv": "column_start",
    "column_validated": "column_end",
}

# The ClickHouse datasource holding ethlambda's rows.
ETHLAMBDA_CH = "ethlambda-ch"


def _equals(match):
    old = match.group(1)
    new = RENAMED.get(old)
    return f"stage IN ('{old}', '{new}')" if new else match.group(0)


def _in_list(match):
    names = re.findall(r"'(\w+)'", match.group(1))
    extra = [RENAMED[n] for n in names if n in RENAMED and RENAMED[n] not in names]
    if not extra:
        return match.group(0)
    return "stage IN (" + ", ".join(f"'{n}'" for n in names + extra) + ")"


def both_names(sql):
    """`sql` with every stage predicate matching the old and the new name."""
    sql = re.sub(r"stage = '(\w+)'", _equals, sql)
    return re.sub(r"stage IN \(([^)]*)\)", _in_list, sql)


def _panels(panels):
    for panel in panels:
        yield panel
        yield from _panels(panel.get("panels", []))


def apply(dashboard):
    """Rewrites, in place, every SQL target that reads ethlambda's ClickHouse.

    Targets on another ClickHouse (Silver's own) are left alone: only ethlambda
    renamed anything. Returns the dashboard.
    """
    for panel in _panels(dashboard["panels"]):
        for target in panel.get("targets", []):
            if "rawSql" not in target:
                continue
            datasource = target.get("datasource") or panel.get("datasource") or {}
            if datasource.get("uid") == ETHLAMBDA_CH:
                target["rawSql"] = both_names(target["rawSql"])
    return dashboard


if __name__ == "__main__":
    # Rewrites dashboard JSON files in place: `python3 stage_names.py a.json ...`.
    import json
    import sys

    for path in sys.argv[1:]:
        with open(path) as f:
            dashboard = json.load(f)
        with open(path, "w") as f:
            json.dump(apply(dashboard), f, indent=2)
            f.write("\n")
