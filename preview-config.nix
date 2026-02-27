# NixOS configuration for ethlambda preview containers (4-node devnet)
# Copy this file to the root of your repo as preview-config.nix and adapt it.
# Built by: tekton's preview.sh using nix build --impure --expr
#
# system.build.previewMeta  -- read by tekton before container start (routing, services, DB)
# environment.etc."preview-meta.json"  -- same JSON available inside the running container
#
# Deploys a 4-node ethlambda devnet using lean-quickstart genesis tooling.
# Each node runs as a separate systemd service with its own QUIC port, metrics
# endpoint, and RocksDB data directory.
#
# Ports:
#   QUIC (P2P):    9001-9004 (UDP)
#   Metrics/RPC:   8081-8084 (TCP)  -- serves /lean/v0/* API and /metrics
#
# Prerequisites:
#   - Docker (or podman with dockerCompat) for genesis generation tools:
#     hash-sig-cli (XMSS key generation) and eth-beacon-genesis (genesis state)
#   - If Docker is unavailable in the container, replace virtualisation.docker
#     with: virtualisation.podman = { enable = true; dockerCompat = true; };
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
  appDir = "/home/preview/app";
  quickstartDir = "/home/preview/lean-quickstart";
  genesisDir = "/home/preview/devnet/genesis";
  dataDir = "/home/preview/devnet/data";

  # nix build produces result/bin/ethlambda via the repo's flake.nix
  binaryPath = "${appDir}/result/bin/ethlambda";

  # Helper: create a systemd service for ethlambda node N
  mkNodeService = idx:
    let
      name = "ethlambda_${toString idx}";
      gossipPort = 9001 + idx;
      metricsPort = 8081 + idx;
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
        ExecStart = builtins.concatStringsSep " " [
          binaryPath
          "--custom-network-config-dir" genesisDir
          "--gossipsub-port" (toString gossipPort)
          "--node-id" name
          "--node-key" "${genesisDir}/${name}.key"
          "--metrics-address" "0.0.0.0"
          "--metrics-port" (toString metricsPort)
        ];
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
  services.resolved = {
    enable = true;
    settings.Resolve.FallbackDNS = [ "8.8.8.8" "1.1.1.1" ];
  };
  networking.nameservers = [ "8.8.8.8" "1.1.1.1" ];

  # Open ports: 4 RPC/metrics (TCP) + 4 QUIC P2P (UDP)
  networking.firewall.allowedTCPPorts = [ 8081 8082 8083 8084 ];
  networking.firewall.allowedUDPPorts = [ 9001 9002 9003 9004 ];

  # Docker for genesis generation (hash-sig-cli, eth-beacon-genesis).
  # Requires cgroup delegation from the host for systemd-nspawn containers.
  # Alternative: virtualisation.podman = { enable = true; dockerCompat = true; };
  virtualisation.docker.enable = true;

  # Nix: enable flakes for 'nix build' from the repo's flake.nix
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # ── Setup service ─────────────────────────────────────────────────────
  # Clones the repo, builds ethlambda via nix build (using the repo's
  # flake.nix for exact Rust version and reproducible builds), generates
  # genesis for a 4-node ethlambda-only devnet, and creates per-node
  # data directories.
  systemd.services = {
    setup-devnet = {
      description = "Setup ethlambda 4-node devnet (clone, build, genesis)";
      after = [ "systemd-resolved.service" "docker.service" ];
      wants = [ "systemd-resolved.service" "docker.service" ];
      before = map (idx: "ethlambda-${toString idx}.service") [ 0 1 2 3 ];
      path = with pkgs; [
        bash coreutils git nix
        # Genesis generation
        yq-go docker
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        User = "preview";
        Group = "preview";
        WorkingDirectory = "/home/preview";
        TimeoutStartSec = "900"; # nix build fetches deps + compiles Rust
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

        SECRETS_FILE="/home/preview/.devnet-secrets.env"

        # Generate stable per-preview secrets on first run.
        if [ ! -f "$SECRETS_FILE" ]; then
          echo "Generating preview secrets..."
          {
            echo "RUST_LOG=info"
          } > "$SECRETS_FILE"
          chmod 600 "$SECRETS_FILE"
        fi

        set -a
        source "$SECRETS_FILE"
        source /etc/preview.env
        set +a

        # On container restart, skip setup if already built and genesis exists.
        # Touch /tmp/force-rebuild to force a full rebuild on 'preview update'.
        if [ -f "${binaryPath}" ] \
           && [ -d "${genesisDir}/hash-sig-keys" ] \
           && [ -f "${genesisDir}/config.yaml" ] \
           && [ ! -f /tmp/force-rebuild ]; then
          echo "Devnet already set up, skipping (container restart)."
          exit 0
        fi
        rm -f /tmp/force-rebuild

        # ── 1. Clone ethlambda ──
        PREVIEW_TOKEN=$(cat /etc/preview-token 2>/dev/null || echo "")
        AUTHED_URL=$(echo "$PREVIEW_REPO_URL" | sed "s|https://|https://x-access-token:$PREVIEW_TOKEN@|")

        if [ -d "${appDir}/.git" ]; then
          echo "Updating ethlambda repo..."
          ${pkgs.git}/bin/git -C "${appDir}" remote set-url origin "$AUTHED_URL"
          ${pkgs.git}/bin/git -C "${appDir}" fetch origin
          ${pkgs.git}/bin/git -C "${appDir}" reset --hard "origin/$PREVIEW_BRANCH"
        else
          echo "Cloning ethlambda (branch: $PREVIEW_BRANCH)..."
          ${pkgs.git}/bin/git clone --depth 1 --branch "$PREVIEW_BRANCH" --single-branch "$AUTHED_URL" "${appDir}"
        fi

        # ── 2. Build ethlambda ──
        # Uses the repo's flake.nix which pins the exact Rust version (1.92.0)
        # and handles all build dependencies via crane + rust-overlay.
        echo "Building ethlambda with nix build..."
        cd "${appDir}"
        nix build 2>&1

        if [ ! -f "${binaryPath}" ]; then
          echo "ERROR: Binary not found at ${binaryPath} after build"
          exit 1
        fi
        echo "Build complete: $(readlink -f ${appDir}/result)"

        # ── 3. Clone lean-quickstart (for genesis generation scripts) ──
        if [ ! -d "${quickstartDir}/.git" ]; then
          echo "Cloning lean-quickstart..."
          ${pkgs.git}/bin/git clone --depth 1 --single-branch \
            https://github.com/blockblaz/lean-quickstart.git "${quickstartDir}"
        fi

        # ── 4. Write 4-node ethlambda-only validator config ──
        # Four ethlambda nodes, each with 1 validator, on localhost with
        # unique QUIC and metrics ports. Private keys are secp256k1 keys
        # for P2P identity (reused from the standard devnet config).
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
        # Runs lean-quickstart's genesis generator which uses Docker to:
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

        echo "Devnet setup complete. 4 ethlambda nodes ready to start."
      '';
    };
  } // nodeServices;

  # Preview user (non-root): all build and node processes run as this user
  users.users.preview = {
    isNormalUser = true;
    home = "/home/preview";
    shell = pkgs.bash;
    extraGroups = [ "docker" ]; # Needed for genesis generation via Docker
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
    git
    curl
    jq
    yq-go
    htop     # Useful for debugging resource usage
    docker   # For genesis tool access via SSH
  ];

  system.stateVersion = "24.11";
}
