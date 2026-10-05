# A devnet from ethpandaops/ethereum-package, plus `ethlambda validator`.
#
# ethereum-package has no ethlambda client type, so this wraps it: run the
# devnet exactly as the package would, then add the ethlambda validator client
# as one more service in the same enclave, pointed at the first participant's
# beacon node over the enclave network.
#
# # Whose keys the ethlambda validator signs with
#
# Keys that are in genesis but that no validator client in the devnet holds.
# `network_params.preregistered_validator_count` is set above the participants'
# total, so the genesis state registers the extra keys while ethereum-package
# generates keystores only for the participants' ranges. This package derives
# the tail range itself, from the same mnemonic, with the same tool.
#
# That exclusivity is not optional. The ethlambda validator client keeps no
# slashing-protection record, so a key held by it and by any other client would
# be signed twice every slot.
#
# # Which beacon node it talks to
#
# By default, the first participant's. With `ethlambda_beacon.enabled`, the
# package also runs `ethlambda beacon`, paired with a geth of its own over the
# Engine API, and hands the validator client both nodes, ethlambda's first: the
# client fails over per call, so everything ethlambda beacon serves goes through
# it. With `ethlambda_beacon.fallback: false` the participant's node is left
# out of the list entirely, and ethlambda beacon serves every duty alone.
#
# # Which validator client
#
# `ethlambda validator` by default. With `ethlambda_validator.client:
# lighthouse`, Lighthouse's validator client signs for the same keys instead,
# against the same beacon node list: that is how the Beacon API ethlambda
# beacon serves is checked against a client other than its own.
# `ethlambda_validator.doppelganger: true` turns on Lighthouse's doppelganger
# protection, which calls `/eth/v1/validator/liveness`.

ethereum_package = import_module("github.com/ethpandaops/ethereum-package/main.star")

# ethereum-package's own default, so the derived keys match its genesis unless
# the args override the mnemonic.
DEFAULT_MNEMONIC = "giant issue aisle success illegal bike spike question tent bar rely arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky have athlete"

KEYS_ARTIFACT = "ethlambda-validator-keys"
KEYS_MOUNT = "/keys"
METRICS_PORT = 5064

# What ethereum-package names the genesis files and the Engine API secret, and
# where its own clients mount them.
GENESIS_ARTIFACT = "el_cl_genesis_data"
GENESIS_MOUNT = "/network-configs"
JWT_ARTIFACT = "jwt_file"
JWT_MOUNT = "/jwt"

BEACON_API_PORT = 5052
BEACON_METRICS_PORT = 5054
BEACON_P2P_PORT = 9001
BEACON_DISCOVERY_PORT = 9000
ENGINE_PORT = 8551


def run(plan, args={}):
    vc = args.get("ethlambda_validator", {})
    devnet_args = {
        k: v for k, v in args.items() if k not in ("ethlambda_validator", "ethlambda_beacon")
    }

    network_params = devnet_args.get("network_params", {})
    # One entry per participant ethereum-package will start, in its order:
    # `count` expands one config entry into several identical participants.
    keys_per_participant = []
    for participant in devnet_args.get("participants", []):
        keys = participant.get(
            "validator_count", network_params.get("num_validator_keys_per_node", 128)
        )
        keys_per_participant += [keys] * participant.get("count", 1)
    participants_total = 0
    for keys in keys_per_participant:
        participants_total += keys
    genesis_total = network_params.get("preregistered_validator_count", 0)
    if genesis_total <= participants_total:
        fail(
            (
                "network_params.preregistered_validator_count ({}) must exceed the "
                + "participants' validators ({}), or there are no keys left for the "
                + "ethlambda validator that another client does not already hold"
            ).format(genesis_total, participants_total)
        )

    first = vc.get("first_index", participants_total)
    last = vc.get("last_index", genesis_total)  # exclusive
    if first < participants_total or last > genesis_total or first >= last:
        fail(
            "ethlambda_validator keys [{}, {}) must lie within the unassigned range [{}, {})".format(
                first, last, participants_total, genesis_total
            )
        )

    output = ethereum_package.run(plan, devnet_args)
    beacon_nodes = [output.all_participants[0].cl_context.beacon_http_url]

    beacon = args.get("ethlambda_beacon", {})
    if beacon.get("enabled", False):
        ethlambda_url = launch_ethlambda_beacon(
            plan,
            beacon,
            output.all_participants[0].cl_context.enr,
            ",".join([p.el_context.enode for p in output.all_participants]),
            vc.get("image", "ghcr.io/lambdaclass/ethlambda:validator-local"),
        )
        # With `fallback: false` the client talks to ethlambda beacon alone, so
        # every duty, proposals included, has to go through it.
        if beacon.get("fallback", True):
            beacon_nodes = [ethlambda_url] + beacon_nodes
        else:
            beacon_nodes = [ethlambda_url]
    name = vc.get("name", "ethlambda-vc")
    if "dora" in devnet_args.get("additional_services", []):
        label_in_dora(plan, first, last, name)

    mnemonic = network_params.get("preregistered_validator_keys_mnemonic", DEFAULT_MNEMONIC)
    derive_keys(plan, mnemonic, first, last)

    if vc.get("client", "ethlambda") == "lighthouse":
        launch_lighthouse_vc(plan, vc, beacon_nodes, name)
        plan.print(
            "Lighthouse's validator client signs for validators [{}, {}) via {}".format(
                first, last, ", ".join(beacon_nodes)
            )
        )
        return output

    cmd = [
        "validator",
        "--beacon-nodes",
        ",".join(beacon_nodes),
        "--validators-dir",
        KEYS_MOUNT + "/validators",
        "--secrets-dir",
        KEYS_MOUNT + "/raw/secrets",
        "--http-address",
        "0.0.0.0",
        "--metrics-port",
        str(METRICS_PORT),
        "--graffiti",
        vc.get("graffiti", name),
    ]
    fee_recipient = vc.get("suggested_fee_recipient", "")
    if fee_recipient:
        cmd += ["--suggested-fee-recipient", fee_recipient]

    plan.add_service(
        name="vc-ethlambda",
        config=ServiceConfig(
            image=vc.get("image", "ghcr.io/lambdaclass/ethlambda:validator-local"),
            cmd=cmd,
            files={KEYS_MOUNT: KEYS_ARTIFACT},
            ports={
                "metrics": PortSpec(
                    number=METRICS_PORT, transport_protocol="TCP", application_protocol="http"
                ),
            },
        ),
    )

    plan.print(
        "ethlambda validator signs for validators [{}, {}) via {}".format(
            first, last, ", ".join(beacon_nodes)
        )
    )
    return output


def launch_lighthouse_vc(plan, vc, beacon_nodes, name):
    """Run Lighthouse's validator client on the derived keys.

    eth2-val-tools writes keys in Lighthouse's own layout
    (`keys/<pubkey>/voting-keystore.json` and `secrets/<pubkey>`), and with no
    `validator_definitions.yml` in the validators directory Lighthouse
    discovers them and writes one. It writes that file into the directory, so
    the keys are copied out of the artifact first rather than used in place.
    No `--datadir`: Lighthouse refuses it alongside `--validators-dir`, and
    keeps its slashing-protection database in the validators directory, which
    is the writable copy. `--init-slashing-protection` because that database
    starts empty.
    """
    flags = [
        "--testnet-dir={}".format(GENESIS_MOUNT),
        "--beacon-nodes={}".format(",".join(beacon_nodes)),
        "--validators-dir=/data/raw/keys",
        "--secrets-dir=/data/raw/secrets",
        "--init-slashing-protection",
        "--graffiti={}".format(vc.get("graffiti", name)),
        "--metrics",
        "--metrics-address=0.0.0.0",
        "--metrics-port={}".format(METRICS_PORT),
    ]
    fee_recipient = vc.get("suggested_fee_recipient", "")
    if fee_recipient:
        flags.append("--suggested-fee-recipient={}".format(fee_recipient))
    if vc.get("doppelganger", False):
        flags.append("--enable-doppelganger-protection")
    flags += vc.get("lighthouse_extra_params", [])

    plan.add_service(
        name="vc-lighthouse",
        config=ServiceConfig(
            image=vc.get("lighthouse_image", "sigp/lighthouse:latest"),
            entrypoint=["sh", "-c"],
            cmd=[
                "mkdir -p /data && cp -r {}/raw /data/ && lighthouse vc {}".format(
                    KEYS_MOUNT, " ".join(flags)
                )
            ],
            files={KEYS_MOUNT: KEYS_ARTIFACT, GENESIS_MOUNT: GENESIS_ARTIFACT},
            ports={
                "metrics": PortSpec(
                    number=METRICS_PORT, transport_protocol="TCP", application_protocol="http"
                ),
            },
        ),
    )


def derive_keys(plan, mnemonic, first, last):
    """Derive keystores for [first, last) and the definitions file the client reads.

    The same tool and flags ethereum-package uses for its own participants, so
    these are the keys its genesis registered at those indices. `--insecure`
    picks a cheap KDF, which matters on startup: the real one takes seconds per
    key.
    """
    # One line, with the commands chained by `&&`. Kurtosis passes the script
    # through in a way that breaks a multi-line `for ... do ... done` loop (a
    # launch failed with `Syntax error: ";" unexpected`), so nothing here may
    # depend on a newline surviving. The printf format is single-quoted so its
    # `\n` reaches printf rather than the shell.
    definition = (
        "printf -- '- enabled: true\\n  voting_public_key: \"%s\"\\n"
        + "  voting_keystore_path: {m}/raw/keys/%s/voting-keystore.json\\n"
        + "  voting_keystore_password_path: {m}/raw/secrets/%s\\n'"
        + ' "$pubkey" "$pubkey" "$pubkey" >> /out/validators/validator_definitions.yml'
    ).format(m=KEYS_MOUNT)
    script = " && ".join(
        [
            (
                "/app/eth2-val-tools keystores --insecure --prysm-pass unused --out-loc /out/raw"
                + ' --source-mnemonic "{}" --source-min {} --source-max {}'
            ).format(mnemonic, first, last),
            "mkdir -p /out/validators",
            'for dir in /out/raw/keys/*; do pubkey=$(basename "$dir"); ' + definition + "; done",
            'echo "derived $(ls /out/raw/keys | wc -l) keys"',
        ]
    )

    plan.run_sh(
        name="ethlambda-validator-key-derivation",
        description="Deriving the ethlambda validator's keys [{}, {})".format(first, last),
        image="protolambda/eth2-val-tools:latest",
        run=script,
        store=[StoreSpec(src="/out", name=KEYS_ARTIFACT)],
    )


def label_in_dora(plan, first, last, name):
    """Name the ethlambda validator's range in Dora.

    Dora labels validators from one file ethereum-package writes, listing only
    its own participants, so without this our range shows as bare indices and
    nothing on screen says ethlambda signed those blocks. Dora reads the file at
    startup, so it is appended to and Dora restarted; a container restart keeps
    its filesystem, so the edit survives.
    """
    plan.exec(
        service_name="dora",
        description="Naming validators [{}, {}) {} in Dora".format(first, last, name),
        recipe=ExecRecipe(
            command=[
                "sh",
                "-c",
                "echo '{}-{}: {}' >> /validator-ranges/validator-ranges.yaml".format(
                    first, last - 1, name
                ),
            ]
        ),
    )
    plan.stop_service(name="dora", description="Restarting Dora to load the new name")
    plan.start_service(name="dora", description="Restarting Dora to load the new name")


def launch_ethlambda_beacon(plan, beacon, bootnode_enr, el_enodes, default_image):
    """Run `ethlambda beacon` with a geth of its own, and return its API URL.

    The geth starts from the same genesis as the devnet's. It still syncs
    every block from ethlambda beacon, which hands it every payload in order
    over the Engine API, so each one extends a parent geth already has. That
    makes geth answer VALID rather than SYNCING, which keeps the node out of
    optimistic mode, and the validator client refuses to sign against an
    optimistic node. It peers with every participant's execution client (not
    just the first) so transactions (spamoor's included) reach its mempool;
    spamoor may submit to any of them, and a transaction that reaches only some
    of them is not reliably relayed. Without that, the blocks this node
    builds, the only blocks on this devnet, would always be empty.

    geth is started first because the Engine API client does not retry a block
    once its attempts are spent.
    """
    geth = plan.add_service(
        name="el-ethlambda",
        config=ServiceConfig(
            image=beacon.get("geth_image", "ethereum/client-go:latest"),
            entrypoint=["sh", "-c"],
            cmd=[
                " ".join(
                    [
                        "geth",
                        "--override.genesis={}/genesis.json".format(GENESIS_MOUNT),
                        "--datadir=/data/geth",
                        "--syncmode=full",
                        "--authrpc.addr=0.0.0.0",
                        "--authrpc.port={}".format(ENGINE_PORT),
                        "--authrpc.vhosts=*",
                        "--authrpc.jwtsecret={}/jwtsecret".format(JWT_MOUNT),
                        # The other ELs run discv5 only, so match them or the
                        # bootnode is never contacted.
                        "--discovery.v4=false",
                        "--discovery.v5=true",
                        "--bootnodes={}".format(el_enodes),
                    ]
                )
            ],
            files={GENESIS_MOUNT: GENESIS_ARTIFACT, JWT_MOUNT: JWT_ARTIFACT},
            ports={
                "engine": PortSpec(number=ENGINE_PORT, transport_protocol="TCP"),
            },
        ),
    )

    bootnodes = plan.render_templates(
        name="ethlambda-beacon-bootnodes",
        config={"bootnodes.txt": struct(template="{{.enr}}\n", data={"enr": bootnode_enr})},
    )

    service = plan.add_service(
        name="cl-ethlambda",
        config=ServiceConfig(
            image=beacon.get("image", default_image),
            cmd=[
                "beacon",
                "--network",
                GENESIS_MOUNT,
                "--execution-endpoint",
                "http://{}:{}".format(geth.ip_address, ENGINE_PORT),
                "--execution-jwt-secret",
                "{}/jwtsecret".format(JWT_MOUNT),
                "--bootnodes",
                "/bootnodes/bootnodes.txt",
                "--data-dir",
                "/data",
                "--http-address",
                "0.0.0.0",
                "--api-port",
                str(BEACON_API_PORT),
                "--metrics-port",
                str(BEACON_METRICS_PORT),
                "--gossipsub-port",
                str(BEACON_P2P_PORT),
                "--discovery.port",
                str(BEACON_DISCOVERY_PORT),
            ],
            files={
                GENESIS_MOUNT: GENESIS_ARTIFACT,
                JWT_MOUNT: JWT_ARTIFACT,
                "/bootnodes": bootnodes,
            },
            ports={
                "http": PortSpec(
                    number=BEACON_API_PORT, transport_protocol="TCP", application_protocol="http"
                ),
                "metrics": PortSpec(
                    number=BEACON_METRICS_PORT, transport_protocol="TCP", application_protocol="http"
                ),
            },
        ),
    )
    return "http://{}:{}".format(service.ip_address, BEACON_API_PORT)
