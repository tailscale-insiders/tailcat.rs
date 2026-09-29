{
  description = "tailcat.rs: a Rust re-implementation of tailcat (netcat over Tailscale's data plane, without its control plane)";

  # nixpkgs is the only input: the Rust toolchain, the build helpers, and
  # the upstream Go tailcat used by the interop check all come from it.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Only what cargo needs: manifests, the lock file, Rust sources,
      # and the README that the CLI embeds with include_str!.
      src = lib.cleanSourceWith {
        src = ./.;
        filter = path: type:
          let base = baseNameOf path; in
          type == "directory"
          || lib.hasSuffix ".rs" base
          || base == "Cargo.toml"
          || base == "Cargo.lock"
          || base == "README.md";
      };

      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
      version = cargoToml.workspace.package.version;

      mkWorkspace = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "tailcat-rs";
        inherit version src;
        cargoLock.lockFile = ./Cargo.lock;
        # Unit and loopback integration tests; tests that need the
        # public internet or root skip themselves when this is set.
        env.TAILCAT_TEST_OFFLINE = "1";
        cargoTestFlags = [ "--workspace" ];
        # The netstack and relay tests bind loopback sockets.
        __darwinAllowLocalNetworking = true;
        meta = {
          description = "netcat over Tailscale's data plane, without its control plane (Rust)";
          homepage = "https://github.com/tailscale-insiders/tailcat.rs";
          license = lib.licenses.bsd3;
          mainProgram = "tailcat";
          platforms = systems;
        };
      };

      # A cargo invocation over the vendored dependencies, for lint checks.
      mkCargoCheck = pkgs: name: nativeBuildInputs: command:
        pkgs.stdenv.mkDerivation {
          name = "tailcat-rs-${name}";
          inherit src;
          cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
          nativeBuildInputs = [ pkgs.rustPlatform.cargoSetupHook pkgs.cargo pkgs.rustc ] ++ nativeBuildInputs;
          buildPhase = ''
            runHook preBuild
            ${command}
            runHook postBuild
          '';
          installPhase = "touch $out";
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        tailcat = mkWorkspace pkgs;
        default = tailcat;
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.tailcat}/bin/tailcat";
        };
      });

      checks = forAllSystems (pkgs:
        let tailcat = self.packages.${pkgs.system}.tailcat; in
        {
          inherit tailcat;

          clippy = mkCargoCheck pkgs "clippy" [ pkgs.clippy ]
            "cargo clippy --offline --workspace --all-targets -- --deny warnings";

          fmt = mkCargoCheck pkgs "fmt" [ pkgs.rustfmt ] "cargo fmt --all -- --check";

          # Rust <-> Go interop over a loopback DERP relay, run inside the
          # build sandbox against nixpkgs' build of upstream tailcat.
          interop = pkgs.runCommand "tailcat-rs-interop"
            {
              nativeBuildInputs = [ tailcat pkgs.tailcat pkgs.coreutils pkgs.bash pkgs.gnugrep ];
              __darwinAllowLocalNetworking = true;
            } ''
            export HOME=$TMPDIR/home
            mkdir -p "$HOME"
            bash ${./tests/interop.sh} ${tailcat}/bin/tailcat ${pkgs.tailcat}/bin/tailcat
            touch $out
          '';
        });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
            # The upstream Go implementation, for manual interop testing.
            pkgs.tailcat
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixpkgs-fmt);
    };
}
