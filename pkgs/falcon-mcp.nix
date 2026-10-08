# Static Go binary. Refresh vendorHash whenever go.mod/go.sum change:
#   nix build .#falcon-mcp 2>&1 | grep 'got:'
{
  lib,
  buildGoModule,
  versionCheckHook,
}:

buildGoModule (finalAttrs: {
  pname = "falcon-mcp";
  version = "0.1.0";

  # Only the Go tree, so editing docs or Nix does not rebuild the binary.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
      ../guides
    ];
  };

  vendorHash = "sha256-NbuvbsmNbz3aKdjyyfpkbi52yRhXl473j3LvAUDn3L8=";

  subPackages = [ "cmd/falcon-mcp" ];
  env.CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X"
    "github.com/lcleveland/falcon-mcp/internal/version.Version=${finalAttrs.version}"
  ];

  # subPackages also narrows what checkPhase tests; unset it so the whole
  # ./internal suite runs (all hermetic, httptest on loopback).
  preCheck = ''
    unset subPackages
  '';

  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";
  doInstallCheck = true;

  meta = {
    description = "MCP server for the CrowdStrike Falcon API";
    homepage = "https://github.com/lcleveland/falcon-mcp";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "falcon-mcp";
  };
})
