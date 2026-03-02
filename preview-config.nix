# NixOS configuration for ethlambda preview containers (4-node devnet)
# Used by tekton's preview.sh to build a NixOS container for PR previews.
# Built by: tekton's preview.sh using nix build --impure --expr
#
# system.build.previewMeta  -- read by tekton before container start (routing, services, DB)
# environment.etc."preview-meta.json"  -- same JSON available inside the running container
#
# Deploys a 4-node ethlambda devnet using lean-quickstart genesis tooling.
# Each node runs as a separate systemd service with its own QUIC port, metrics
# endpoint, and RocksDB data directory.
#
# The ethlambda binary is built from the PR branch at Nix eval time via builtins.getFlake,
# so the container image always contains the exact binary from the branch under review.
# PREVIEW_BRANCH is available at runtime via /etc/preview.env (injected by tekton).
#
# Ports:
#   QUIC (P2P):    9001-9004 (UDP)
#   Metrics/RPC:   8081-8084 (TCP)  -- serves /lean/v0/* API and /metrics
#
# Prerequisites:
#   - Podman (rootless, with dockerCompat) for genesis generation tools:
#     hash-sig-cli (XMSS key generation) and eth-beacon-genesis (genesis state)
#   - Podman rootless uses user namespaces instead of cgroup BPF, so it works
#     inside systemd-nspawn containers where Docker's cgroup device access fails.
{ config, lib, pkgs, ... }:

let
  meta = {
    # Oneshot service that generates genesis state for the devnet.
    setupService = "setup-devnet";

    # Long-running ethlambda node services started after setup completes.
    appServices = [ "ethlambda-0" "ethlambda-1" "ethlambda-2" "ethlambda-3" ];

    # "container": no external DB needed; each node uses its own RocksDB.
    database = "container";

    # Caddy routing: most-specific path wins; "/" must be last.
    # /node/N/ routes to each node's RPC/metrics port (prefix stripped).
    # / routes to node 0 for quick health checks.
    #
    # Useful endpoints on each node:
    #   /lean/v0/health            -- health check
    #   /lean/v0/states/head       -- current head state
    #   /lean/v0/checkpoints/finalized -- finalized checkpoint
    #   /metrics                   -- Prometheus metrics
    routes = [
      { path = "/node/0/"; port = 8081; stripPrefix = true; }
      { path = "/node/1/"; port = 8082; stripPrefix = true; }
      { path = "/node/2/"; port = 8083; stripPrefix = true; }
      { path = "/node/3/"; port = 8084; stripPrefix = true; }
      { path = "/"; port = 8081; }
    ];

    # No third-party API keys required.
    hostSecrets = [];

    extraHosts = [];
  };

  # Build ethlambda from the current repo at eval time (requires --impure).
  # tekton evaluates preview-config.nix from the cloned PR branch, so path:.
  # resolves to the branch under review — the container always runs that branch's binary.
  ethlambdaPkg = (builtins.getFlake "path:.").packages.x86_64-linux.ethlambda;

  # Paths used throughout the config
  quickstartDir = "/home/preview/lean-quickstart";
  genesisDir   = "/home/preview/devnet/genesis";
  dataDir      = "/home/preview/devnet/data";

  binaryPath = "${ethlambdaPkg}/bin/ethlambda";

  # Helper: create a systemd service for ethlambda node N.
  # Node 0 runs with --is-aggregator so the devnet can finalize blocks:
  # without at least one aggregator, attestations are never packed into
  # blocks and justified_slot/finalized_slot stay at 0 forever.
  mkNodeService = idx:
    let
      name = "ethlambda_${toString idx}";
      gossipPort = 9001 + idx;
      metricsPort = 8081 + idx;
      aggregatorArgs = lib.optionals (idx == 0) [ "--is-aggregator" ];
    in
    {
      description = "ethlambda node ${toString idx} (gossip=${toString gossipPort}, rpc=${toString metricsPort})";
      after = [ "setup-devnet.service" ];
      requires = [ "setup-devnet.service" ];
      path = with pkgs; [ bash coreutils ];
      serviceConfig = {
        Type = "simple";
        User = "preview";
        WorkingDirectory = "${dataDir}/${name}";
        ExecStart = builtins.concatStringsSep " " ([
          binaryPath
          "--custom-network-config-dir" genesisDir
          "--gossipsub-port" (toString gossipPort)
          "--node-id" name
          "--node-key" "${genesisDir}/${name}.key"
          "--metrics-address" "0.0.0.0"
          "--metrics-port" (toString metricsPort)
        ] ++ aggregatorArgs);
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

  nodeServices = builtins.listToAttrs (map (idx: {
    name = "ethlambda-${toString idx}";
    value = mkNodeService idx;
  }) [ 0 1 2 3 ]);

in
{
  boot.isContainer = true;

  # Networking: static IP is set by nixos-container, disable DHCP
  networking.useDHCP = false;
  networking.useHostResolvConf = false;
  # systemd-resolved handles DNS; FallbackDNS is used when the container's
  # upstream resolver is unavailable. Don't set networking.nameservers here:
  # with resolved enabled, NixOS routes DNS through 127.0.0.53, and setting
  # nameservers directly would bypass resolved and produce conflicting config.
  services.resolved = {
    enable = true;
    settings.Resolve.FallbackDNS = [ "8.8.8.8" "1.1.1.1" ];
  };

  # Open ports: 4 RPC/metrics (TCP) + 4 QUIC P2P (UDP)
  networking.firewall.allowedTCPPorts = [ 8081 8082 8083 8084 ];
  networking.firewall.allowedUDPPorts = [ 9001 9002 9003 9004 ];

  # Podman (rootless) for genesis generation (hash-sig-cli, eth-beacon-genesis).
  # dockerCompat provides a `docker` CLI alias so generate-genesis.sh works unmodified.
  virtualisation.podman = {
    enable = true;
    dockerCompat = true;
  };

  environment.etc."containers/containers.conf".text = lib.mkForce ''
    [engine]
    cgroup_manager = "cgroupfs"
    [containers]
    cgroups = "disabled"
  '';

  # ── Setup service ─────────────────────────────────────────────────────
  # Clones lean-quickstart, generates genesis for the 4-node devnet, and creates
  # per-node data directories. The ethlambda binary is already in the container
  # image (built from path:. via builtins.getFlake at eval time).
  systemd.services = {
    setup-devnet = {
      description = "Setup ethlambda 4-node devnet (genesis)";
      after = [ "systemd-resolved.service" "network-online.target" ];
      wants = [ "systemd-resolved.service" "network-online.target" ];
      before = map (idx: "ethlambda-${toString idx}.service") [ 0 1 2 3 ];
      path = with pkgs; [
        bash coreutils git
        # Genesis generation (generate-genesis.sh needs these)
        yq-go podman
        gawk gnugrep gnused which shadow
        (writeShellScriptBin "docker" ''exec podman "$@"'')
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        WorkingDirectory = "/home/preview";
        TimeoutStartSec = "300"; # genesis generation (podman image pull + XMSS key gen)
      };
      script = ''
        set -euo pipefail

        # ── Load preview environment ──
        if [ ! -f /etc/preview.env ]; then
          echo "ERROR: /etc/preview.env not found"
          exit 1
        fi
        set -a
        source /etc/preview.env
        set +a

        # On container restart, skip setup if genesis already exists.
        # Touch /tmp/force-rebuild to force re-genesis on 'preview update'.
        # (The ethlambda binary is baked into the container image at eval time —
        # no runtime build needed.)
        if [ -d "${genesisDir}/hash-sig-keys" ] \
           && [ -f "${genesisDir}/config.yaml" ] \
           && [ ! -f /tmp/force-rebuild ]; then
          echo "Devnet already set up, skipping (container restart)."
          exit 0
        fi
        rm -f /tmp/force-rebuild
        # Clear both genesis and RocksDB data dirs: new genesis produces new XMSS keys
        # and a new genesis state, so any existing chain state is incompatible.
        rm -rf "${genesisDir}" "${dataDir}"

        # ── 1. Clone lean-quickstart (for genesis generation scripts) ──
        if [ ! -d "${quickstartDir}/.git" ]; then
          echo "Cloning lean-quickstart..."
          git clone --depth 1 --single-branch \
            https://github.com/blockblaz/lean-quickstart.git "${quickstartDir}"
        fi

        # ── 2. Write 4-node ethlambda-only validator config ──
        # Four ethlambda nodes, each with 1 validator, on localhost with
        # unique QUIC and metrics ports. The privkeys below are secp256k1
        # P2P identity keys reused from the standard devnet config — they are
        # publicly known and are NOT secrets. Validator signing uses XMSS keys
        # generated fresh by hash-sig-cli during genesis.
        mkdir -p "${genesisDir}"

        cat > "${genesisDir}/validator-config.yaml" << 'VCEOF'
shuffle: roundrobin
deployment_mode: local
config:
  activeEpoch: 18
  keyType: "hash-sig"
validators:
  - name: "ethlambda_0"
    privkey: "4fd22cf461fbeae4947a3fdaef8d533fc7fd1ef1ce4cd98e993210c18234df3f"
    enrFields:
      ip: "127.0.0.1"
      quic: 9001
    metricsPort: 8081
    count: 1

  - name: "ethlambda_1"
    privkey: "64a7f5ab53907966374ca23af36392910af682eec82c12e3abbb6c2ccdf39a72"
    enrFields:
      ip: "127.0.0.1"
      quic: 9002
    metricsPort: 8082
    count: 1

  - name: "ethlambda_2"
    privkey: "299550529a79bc2dce003747c52fb0639465c893e00b0440ac66144d625e066a"
    enrFields:
      ip: "127.0.0.1"
      quic: 9003
    metricsPort: 8083
    count: 1

  - name: "ethlambda_3"
    privkey: "bdf953adc161873ba026330c56450453f582e3c4ee6cb713644794bcfdd85fe5"
    enrFields:
      ip: "127.0.0.1"
      quic: 9004
    metricsPort: 8084
    count: 1
VCEOF

        # ── 3. Generate genesis ──
        # Runs lean-quickstart's genesis generator which uses container images to:
        #   1. Generate XMSS key pairs (hash-sig-cli)
        #   2. Generate genesis state (eth-beacon-genesis)
        # Output: config.yaml, validators.yaml, nodes.yaml, genesis.json,
        #         genesis.ssz, annotated_validators.yaml, *.key files,
        #         hash-sig-keys/ directory
        echo "Generating genesis for 4-node devnet..."
        cd "${quickstartDir}"
        bash generate-genesis.sh "${genesisDir}" --mode local

        # Verify critical output files
        for f in config.yaml validators.yaml nodes.yaml genesis.json annotated_validators.yaml; do
          if [ ! -f "${genesisDir}/$f" ]; then
            echo "ERROR: Genesis generation did not produce $f"
            exit 1
          fi
        done

        # ── 4. Create per-node data directories ──
        for i in 0 1 2 3; do
          mkdir -p "${dataDir}/ethlambda_$i"
        done

        chown -R preview:preview /home/preview/devnet /home/preview/lean-quickstart

        echo "Devnet setup complete. 4 ethlambda nodes ready to start."
      '';
    };
  } // nodeServices;

  # Preview user (non-root): all build and node processes run as this user
  users.users.preview = {
    isNormalUser = true;
    home = "/home/preview";
    group = "preview";
    shell = pkgs.bash;
    extraGroups = [];
    subUidRanges = [{ startUid = 100000; count = 65536; }];
    subGidRanges = [{ startGid = 100000; count = 65536; }];
  };

  users.groups.preview = {};

  # SSH access for debugging (key-only, no passwords)
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
    };
  };

  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEYfIsBaa3Jr/0Ij7QOwWcLp1I1fnNp86yW0Bzsg4Ylg"
  ];

  # Required: expose meta to tekton before container boot, and inside the container.
  system.build.previewMeta = pkgs.writeText "preview-meta.json" (builtins.toJSON meta);
  environment.etc."preview-meta.json".text = builtins.toJSON meta;

  environment.systemPackages = with pkgs; [
    curl
    jq
    yq-go
    htop    # Useful for debugging resource usage
    podman  # For genesis tool access via SSH
  ];

  system.stateVersion = "24.11";
}
