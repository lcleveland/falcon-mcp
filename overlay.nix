# nixpkgs.overlays = [ falcon-mcp.overlays.default ]; gives pkgs.falcon-mcp.
# Not needed for the NixOS module, which defaults to this flake's build.
final: _prev: {
  falcon-mcp = final.callPackage ./pkgs/falcon-mcp.nix { };
}
