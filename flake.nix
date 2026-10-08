{
  description = "MCP server for the CrowdStrike Falcon API";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      overlays.default = import ./overlay.nix;

      nixosModules = {
        falcon-mcp =
          { pkgs, ... }:
          {
            imports = [ ./modules/falcon-mcp.nix ];
            services.falcon-mcp.package =
              lib.mkDefault
                self.packages.${pkgs.stdenv.hostPlatform.system}.falcon-mcp;
          };
        default = self.nixosModules.falcon-mcp;
      };

      packages = forAllSystems (system: rec {
        falcon-mcp = (pkgsFor system).callPackage ./pkgs/falcon-mcp.nix { };
        default = falcon-mcp;
      });

      checks = forAllSystems (
        system:
        {
          # Runs the Go test suite in checkPhase.
          package = self.packages.${system}.falcon-mcp;
        }
        // import ./tests/eval.nix {
          inherit self lib;
          pkgs = pkgsFor system;
        }
        // {
          # Boots a VM with a stub Falcon; about a minute with KVM.
          vm = import ./tests/vm.nix {
            inherit self;
            pkgs = pkgsFor system;
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.gotools
              pkgs.nixfmt
              pkgs.jq
            ];
            env.CGO_ENABLED = "0";
            # /tmp is a small tmpfs on the dev machines; keep Go's build
            # scratch and cache off it.
            shellHook = ''
              export GOCACHE="$HOME/.cache/go-build"
              export GOTMPDIR="$PWD/.gotmp"
              mkdir -p "$GOTMPDIR"
            '';
          };
        }
      );
    };
}
