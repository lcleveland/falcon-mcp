# Module evaluation checks: no VM, just the generated unit.
{
  pkgs,
  self,
  lib,
}:
let
  evalModule =
    module:
    (lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        self.nixosModules.falcon-mcp
        {
          services.falcon-mcp.package = lib.mkForce (pkgs.writeShellScriptBin "falcon-mcp" "exit 0");
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = lib.trivial.release;
        }
        module
      ];
    });

  failed = config: map (a: a.message) (builtins.filter (a: !a.assertion) config.assertions);

  base = extra: {
    services.falcon-mcp = lib.recursiveUpdate {
      enable = true;
      http.enable = true;
      clientId = "client-id-123";
      clientSecretFile = "/persist/secrets/falcon-client-secret";
    } extra;
  };

  # Evaluates cleanly and the generated unit passes the grep checks.
  unitCheck =
    name: extra: checks:
    let
      config = (evalModule (base extra)).config;
      broken = failed config;
      svc = config.systemd.services.falcon-mcp;
    in
    assert broken == [ ] || throw "${name}: ${lib.concatStringsSep "; " broken}";
    pkgs.runCommand "falcon-mcp-${name}" { } ''
      cat > cmd <<'EOF'
      ${svc.serviceConfig.ExecStart}
      EOF
      cat > env <<'EOF'
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "${k}=${v}") svc.environment)}
      EOF
      cat > creds <<'EOF'
      ${lib.concatStringsSep "\n" svc.serviceConfig.LoadCredential}
      EOF
      cat > bind <<'EOF'
      ${svc.serviceConfig.SocketBindAllow}
      EOF
      check() { grep -qF -- "$1" "$2" || { echo "missing from $2: $1"; cat "$2"; exit 1; }; }
      refute() { if grep -qF -- "$1" "$2"; then echo "unexpected in $2: $1"; cat "$2"; exit 1; fi; }
      ${checks}
      touch $out
    '';

  # Evaluation must trip an assertion containing `want`.
  mustFail =
    name: extra: want:
    let
      broken = failed (evalModule (base extra)).config;
    in
    assert
      lib.any (lib.hasInfix want) broken
      || throw "${name}: expected assertion '${want}', got: ${toString broken}";
    pkgs.runCommand "falcon-mcp-${name}" { } "touch $out";

  warns =
    name: extra: want:
    let
      config = (evalModule (base extra)).config;
    in
    assert lib.any (lib.hasInfix want) config.warnings || throw "${name}: no warning '${want}'";
    pkgs.runCommand "falcon-mcp-${name}" { } "touch $out";

  opts = (evalModule { }).config.services.falcon-mcp;
  clouds =
    (evalModule { }).options.services.falcon-mcp.cloud.type.nestedTypes.elemType.functor.payload.values;
in
{
  module-eval = unitCheck "module-eval" { } ''
    check "--http" cmd
    check "--addr 127.0.0.1:8235" cmd
    check "--path /mcp" cmd
    check "--client-id client-id-123" cmd
    check "--tool-groups core,respond,hosts,prevent,intel,siem,exposure,identity,ai" cmd
    check "--max-bulk 1000" cmd
    check "--log-level info" cmd
    check "client-secret:/persist/secrets/falcon-client-secret" creds
    check "tcp:8235" bind
    refute "/persist/secrets/falcon-client-secret" cmd
    refute "falcon-client-secret" env
    refute "--cloud" cmd
    refute "--base-url" cmd
    refute "--allow-" cmd
    refute "--no-probe" cmd
  '';

  module-full =
    unitCheck "module-full"
      {
        baseUrl = "https://api.example.test";
        clientId = null;
        clientIdFile = "/run/secrets/client-id";
        allow = {
          triage = true;
          host-tags = true;
          rtr-read = true;
        };
        toolGroups = [ "hosts" ];
        maxBulk = 10;
        noProbe = true;
        logLevel = "debug";
        http = {
          addr = "[::]:9000";
          path = "/falcon";
          authTokenFile = "/run/secrets/bearer";
        };
        extraArgs = [ "--request-timeout=1m" ];
      }
      ''
        check "--base-url https://api.example.test" cmd
        refute "--cloud" cmd
        refute "--client-id" cmd
        check "client-id:/run/secrets/client-id" creds
        check "--allow-triage" cmd
        check "--allow-host-tags" cmd
        check "--allow-rtr-read" cmd
        refute "--allow-rtr-respond" cmd
        refute "--allow-destructive" cmd
        check "--tool-groups hosts" cmd
        check "--max-bulk 10" cmd
        check "--no-probe" cmd
        check "--log-level debug" cmd
        check "--addr '[::]:9000'" cmd
        check "--path /falcon" cmd
        check "--request-timeout=1m" cmd
        check "http-auth-token:/run/secrets/bearer" creds
        refute "/run/secrets/bearer" cmd
        check "tcp:9000" bind
      '';

  module-cloud = unitCheck "module-cloud" { cloud = "us-2"; } ''
    check "--cloud us-2" cmd
    refute "--base-url" cmd
  '';

  # enable alone puts the CLI on PATH for stdio clients and runs no unit.
  module-cli-only =
    let
      config =
        (evalModule {
          services.falcon-mcp.enable = true;
        }).config;
    in
    assert failed config == [ ] || throw "cli-only: ${toString (failed config)}";
    assert !(config.systemd.services ? falcon-mcp) || throw "cli-only: unit defined";
    assert
      lib.any (p: (p.name or "") == "falcon-mcp") config.environment.systemPackages
      || throw "cli-only: package not installed";
    pkgs.runCommand "falcon-mcp-cli-only" { } "touch $out";

  # The module's capabilities and groups must match the binary's flags.
  module-flags-sync = pkgs.runCommand "falcon-mcp-flags-sync" { } ''
    help=$(${
      lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.falcon-mcp
    } --help 2>&1 || true)
    got=$(echo "$help" | grep -o -- '-allow-[a-z-]*' | sed 's/^-allow-//' | sort | tr '\n' ' ')
    want="${lib.concatStringsSep " " (lib.sort lib.lessThan (lib.attrNames opts.allow))} "
    [ "$got" = "$want" ] || { echo "capabilities: binary '$got', module '$want'"; exit 1; }
    echo "$help" | grep -qF -- "${lib.concatStringsSep "," opts.toolGroups}" \
      || { echo "tool groups differ from the binary's:"; echo "$help"; exit 1; }
    echo "$help" | grep -qF -- "${lib.concatStringsSep "|" (lib.sort lib.lessThan clouds)};" \
      || { echo "clouds differ from the binary's:"; echo "$help"; exit 1; }
    touch $out
  '';

  module-destructive-warn = warns "destructive-warn" {
    allow.destructive = true;
  } "allow.destructive is true";
  module-rtr-respond-warn = warns "rtr-respond-warn" {
    allow.rtr-respond = true;
  } "allow.rtr-respond is true";

  module-no-secret = mustFail "no-secret" { clientSecretFile = null; } "clientSecretFile";
  module-secret-in-store = mustFail "secret-in-store" {
    clientSecretFile = "${builtins.storeDir}/abc-secret";
  } "world-readable";
  module-open-listener = mustFail "open-listener" {
    http.addr = "0.0.0.0:8235";
  } "without http.authTokenFile";
  module-open-listener-any = mustFail "open-listener-any" {
    http.addr = ":8235";
  } "without http.authTokenFile";
  module-cloud-and-url = mustFail "cloud-and-url" {
    cloud = "us-1";
    baseUrl = "https://api.example.test";
  } "at most one of cloud and baseUrl";
  module-two-ids = mustFail "two-ids" {
    clientIdFile = "/run/secrets/client-id";
  } "exactly one of clientId and clientIdFile";
  module-bad-addr = mustFail "bad-addr" { http.addr = "localhost"; } "host:port";
  module-bare-v6-addr = mustFail "bare-v6-addr" { http.addr = "::1:8235"; } "host:port";
  module-port-zero = mustFail "port-zero" { http.addr = "127.0.0.1:0"; } "host:port";
  module-loopback-lookalike = mustFail "loopback-lookalike" {
    http.addr = "127.example.test:8235";
  } "without http.authTokenFile";
  module-token-in-store = mustFail "token-in-store" {
    http.addr = "[::]:8235";
    http.authTokenFile = "${builtins.storeDir}/abc-token";
  } "world-readable";
  module-relative-secret = mustFail "relative-secret" {
    clientSecretFile = "secrets/falcon";
  } "clientSecretFile must be an absolute";
  module-relative-id-file = mustFail "relative-id-file" {
    clientId = null;
    clientIdFile = "client-id";
  } "clientIdFile must be an absolute";
  module-relative-token = mustFail "relative-token" {
    http.authTokenFile = "bearer";
  } "authTokenFile must be an absolute";
  module-bad-path = mustFail "bad-path" { http.path = "mcp"; } "must begin with a slash";
}
