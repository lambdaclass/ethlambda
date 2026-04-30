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
# The setup service clones the PR branch and builds ethlambda at container start,
# so previews always run the exact binary from the branch under review.
# PREVIEW_BRANCH is available at runtime via /etc/preview.env (injected by tekton).
#
# Ports:
#   QUIC (P2P):    9001-9004 (UDP)
#   API RPC:       8081-8084 (TCP)  -- serves /lean/v0/* API endpoints
#   Metrics:       8085-8088 (TCP)  -- serves /metrics and /debug/pprof/*
#
# Prerequisites:
#   - Podman (rootless, with dockerCompat) for genesis generation tools:
#     hash-sig-cli (XMSS key generation) and eth-beacon-genesis (genesis state)
#   - Podman rootless uses user namespaces instead of cgroup BPF, so it works
#     inside systemd-nspawn containers where Docker's cgroup device access fails.
{ config, lib, pkgs, ... }:

let
  meta = {
    # Oneshot service that clones, builds, and generates genesis.
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

  # Paths used throughout the config
  appDir       = "/home/preview/app";
  quickstartDir = "/home/preview/lean-quickstart";
  genesisDir   = "/home/preview/devnet/genesis";
  dataDir      = "/home/preview/devnet/data";

  binaryPath = "${appDir}/target/release/ethlambda";

  # Helper: create a systemd service for ethlambda node N.
  # Node 0 runs with --is-aggregator so the devnet can finalize blocks:
  # without at least one aggregator, attestations are never packed into
  # blocks and justified_slot/finalized_slot stay at 0 forever.
  mkNodeService = idx:
    let
      name = "ethlambda_${toString idx}";
      gossipPort = 9001 + idx;
      apiPort = 8081 + idx;
      metricsPort = 8085 + idx;
      aggregatorArgs = lib.optionals (idx == 0) [ "--is-aggregator" ];
    in
    {
      description = "ethlambda node ${toString idx} (gossip=${toString gossipPort}, api=${toString apiPort}, metrics=${toString metricsPort})";
      after = [ "setup-devnet.service" ];
      requires = [ "setup-devnet.service" ];
      path = with pkgs; [ bash coreutils ];
      serviceConfig = {
        Type = "simple";
        User = "preview";
        WorkingDirectory = "${dataDir}/${name}";
        ExecStart = builtins.concatStringsSep " " ([
          binaryPath
          "--genesis" "${genesisDir}/config.yaml"
          "--validators" "${genesisDir}/annotated_validators.yaml"
          "--bootnodes" "${genesisDir}/nodes.yaml"
          "--validator-config" "${genesisDir}/validator-config.yaml"
          "--hash-sig-keys-dir" "${genesisDir}/hash-sig-keys"
          "--gossipsub-port" (toString gossipPort)
          "--node-id" name
          "--node-key" "${genesisDir}/${name}.key"
          "--http-address" "0.0.0.0"
          "--api-port" (toString apiPort)
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
  # Clones the PR branch, builds ethlambda via nix build, clones lean-quickstart,
  # generates genesis for the 4-node devnet, and creates per-node data directories.
  systemd.services = {
    setup-devnet = {
      description = "Setup ethlambda 4-node devnet (clone, build, genesis)";
      after = [ "systemd-resolved.service" "network-online.target" ];
      wants = [ "systemd-resolved.service" "network-online.target" ];
      before = map (idx: "ethlambda-${toString idx}.service") [ 0 1 2 3 ];
      path = with pkgs; [
        bash coreutils git rustup pkg-config llvmPackages.libclang llvmPackages.clang
        # Genesis generation (generate-genesis.sh needs these)
        yq-go podman
        gawk gnugrep gnused which shadow
        (writeShellScriptBin "docker" ''exec podman "$@"'')
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        WorkingDirectory = "/home/preview";
        TimeoutStartSec = "900"; # rustup toolchain install + cargo build --release
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

        export RUST_LOG=info

        # On container restart, skip setup if the binary and genesis already exist.
        # Touch /tmp/force-rebuild to force a full rebuild on 'preview update'.
        if [ -f "${binaryPath}" ] \
           && [ -d "${genesisDir}/hash-sig-keys" ] \
           && [ -f "${genesisDir}/config.yaml" ] \
           && [ ! -f /tmp/force-rebuild ]; then
          echo "Devnet already set up, skipping (container restart)."
          exit 0
        fi
        rm -f /tmp/force-rebuild
        # Clear both genesis and RocksDB data dirs: new genesis produces new XMSS keys
        # and a new genesis state, so any existing chain state is incompatible.
        rm -rf "${genesisDir}" "${dataDir}"

        # ── 1. Clone ethlambda ──
        PREVIEW_TOKEN=$(cat /etc/preview-token 2>/dev/null || echo "")
        AUTHED_URL=$(echo "$PREVIEW_REPO_URL" | sed "s|https://|https://x-access-token:$PREVIEW_TOKEN@|")

        if [ -d "${appDir}/.git" ]; then
          echo "Updating ethlambda repo (branch: $PREVIEW_BRANCH)..."
          git -C "${appDir}" remote set-url origin "$AUTHED_URL"
          git -C "${appDir}" fetch origin
          git -C "${appDir}" reset --hard "origin/$PREVIEW_BRANCH"
        else
          echo "Cloning ethlambda (branch: $PREVIEW_BRANCH)..."
          git clone --depth 1 --branch "$PREVIEW_BRANCH" --single-branch "$AUTHED_URL" "${appDir}"
        fi

        # ── 2. Build ethlambda ──
        # cargo build instead of nix build: the flake has no binary cache, so nix
        # build would recompile from scratch on every preview start (10-15 min).
        # rustup reads rust-toolchain.toml automatically and installs the pinned version.
        export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
        export RUSTUP_HOME=/home/preview/.rustup
        export CARGO_HOME=/home/preview/.cargo
        cd "${appDir}"
        rustup toolchain install  # installs from rust-toolchain.toml
        cargo build --release --bin ethlambda

        if [ ! -f "${appDir}/target/release/ethlambda" ]; then
          echo "ERROR: Binary not found after cargo build"
          exit 1
        fi
        echo "Build complete: ${appDir}/target/release/ethlambda"

        # ── 3. Clone lean-quickstart (for genesis generation scripts) ──
        if [ ! -d "${quickstartDir}/.git" ]; then
          echo "Cloning lean-quickstart..."
          git clone --depth 1 --single-branch \
            https://github.com/blockblaz/lean-quickstart.git "${quickstartDir}"
        fi

        # ── 4. Write 4-node ethlambda-only validator config ──
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

        # ── 5. Generate genesis ──
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

        # ── 6. Create per-node data directories ──
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
    rustup  # For inspecting/rebuilding ethlambda over SSH
  ];

  system.stateVersion = "24.11";
}
