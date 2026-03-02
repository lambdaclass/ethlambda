{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      mkPkgs = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      rustToolchain = pkgs: pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      mkCraneLib = pkgs: (crane.mkLib pkgs).overrideToolchain (rustToolchain pkgs);
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = mkPkgs system;
          craneLib = mkCraneLib pkgs;

          commonArgs = {
            pname = "ethlambda";
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                (craneLib.filterCargoSources path type) || (builtins.match ".*\\.html$" path != null);
            };
            strictDeps = true;

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            buildInputs = with pkgs; [
              llvmPackages.libclang
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin (with pkgs; [
              libiconv
              apple-sdk_15
            ]);

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

            # vergen-git2 falls back to env vars when .git is absent
            VERGEN_GIT_SHA = self.shortRev or self.dirtyShortRev or "unknown";
            VERGEN_GIT_BRANCH = "nix";
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          ethlambda = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            # Only install the main binary
            cargoExtraArgs = "--bin ethlambda";
          });
        in
        {
          default = ethlambda;
          inherit ethlambda;
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = mkPkgs system;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              (rustToolchain pkgs)
              pkg-config
              cargo-watch
            ];

            buildInputs = with pkgs; [
              llvmPackages.libclang
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin (with pkgs; [
              libiconv
              apple-sdk_15
            ]);

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          };
        }
      );
    };
}
