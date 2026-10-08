{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    optional
    literalExpression
    ;
  cfg = config.services.falcon-mcp;
  # Keep in step with config.Groups and config.Capabilities; the
  # module-flags-sync check compares them with the binary's --help.
  groups = [
    "core"
    "respond"
    "hosts"
    "prevent"
    "intel"
    "siem"
    "exposure"
    "identity"
    "ai"
  ];
  # See docs/adr/0002.
  capabilities = [
    "triage"
    "host-tags"
    "containment"
    "detection-add"
    "detection-remove"
    "fleet-config"
    "rtr-read"
    "rtr-respond"
    "destructive"
    "workflows"
  ];
  # "host:port" or "[v6]:port" -> [ host port ], as Go's net.SplitHostPort.
  v6 = builtins.match "\\[([^]]+)]:([0-9]+)" cfg.http.addr;
  addrParts = if v6 != null then v6 else builtins.match "([^]:[]*):([0-9]+)" cfg.http.addr;
  host = lib.elemAt addrParts 0;
  port = lib.elemAt addrParts 1;
  validAddr = addrParts != null && lib.toInt port >= 1 && lib.toInt port <= 65535;
  # Go's ip.IsLoopback(), minus IPv4-mapped forms.
  isLoopback =
    host == "localhost"
    || host == "::1"
    || builtins.match "127\\.[0-9]+\\.[0-9]+\\.[0-9]+" host != null;
  inStore = p: p != null && lib.hasPrefix builtins.storeDir p;

  args = [
    "--http"
    "--addr"
    cfg.http.addr
    "--path"
    cfg.http.path
    "--tool-groups"
    (lib.concatStringsSep "," cfg.toolGroups)
    "--max-bulk"
    (toString cfg.maxBulk)
    "--log-level"
    cfg.logLevel
  ]
  ++ lib.optionals (cfg.cloud != null) [
    "--cloud"
    cfg.cloud
  ]
  ++ lib.optionals (cfg.baseUrl != null) [
    "--base-url"
    cfg.baseUrl
  ]
  ++ lib.optionals (cfg.clientId != null) [
    "--client-id"
    cfg.clientId
  ]
  ++ optional cfg.noProbe "--no-probe"
  ++ lib.concatMap (c: optional cfg.allow.${c} "--allow-${c}") capabilities
  ++ cfg.extraArgs;
in
{
  options.services.falcon-mcp = {
    enable = mkEnableOption ''
      the Falcon MCP server: puts falcon-mcp on the system PATH for MCP clients
      that spawn it over stdio. Set http.enable as well to run it as a service;
      every other option configures only that service'';

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../pkgs/falcon-mcp.nix { };
      defaultText = literalExpression "pkgs.falcon-mcp";
      description = "The falcon-mcp package.";
    };

    cloud = mkOption {
      type = types.nullOr (
        types.enum [
          "us-1"
          "us-2"
          "us-3"
          "eu-1"
          "us-gov-1"
          "us-gov-2"
        ]
      );
      default = null;
      example = "us-1";
      description = "Falcon cloud. Leave this and baseUrl unset to autodiscover; gov clouds must be set.";
    };
    baseUrl = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "https://api.example.test";
      description = "Falcon API base URL, instead of cloud. Must be https unless the host is loopback.";
    };

    clientId = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Falcon API client ID. Not secret. Set exactly one of clientId and clientIdFile.";
    };
    clientIdFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/persist/secrets/falcon-client-id";
      description = "Runtime path to a file holding the client ID, instead of clientId. Passed via systemd `LoadCredential`.";
    };
    clientSecretFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/persist/secrets/falcon-client-secret";
      description = ''
        Runtime path to a file holding the API client secret. Passed via systemd
        `LoadCredential`, so it never enters the Nix store, argv or the
        environment. Use sops-nix, agenix or a root-owned 0400 file.
      '';
    };

    allow = lib.genAttrs capabilities (
      c:
      mkOption {
        type = types.bool;
        default = false;
        description = "Enable the `${c}` write capability (`--allow-${c}`); see docs/adr/0002.";
      }
    );
    toolGroups = mkOption {
      type = types.nonEmptyListOf (types.enum groups);
      default = groups;
      description = "Tool groups to register. `core` is always on; `[ \"core\" ]` for core alone.";
    };
    maxBulk = mkOption {
      type = types.ints.positive;
      default = 1000;
      description = "Most records one write may touch.";
    };
    noProbe = mkOption {
      type = types.bool;
      default = false;
      description = "Skip the startup scope probe and show every action.";
    };

    http = {
      enable = mkEnableOption "the streamable HTTP server as a hardened systemd service";
      addr = mkOption {
        type = types.str;
        default = "127.0.0.1:8235";
        example = "[::]:8235";
        description = "Listen address as host:port. A non-loopback host requires authTokenFile.";
      };
      path = mkOption {
        type = types.str;
        default = "/mcp";
        description = "URL path of the MCP endpoint.";
      };
      authTokenFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/run/secrets/falcon-mcp-bearer";
        description = ''
          Runtime path to a shared secret HTTP clients must send as
          `Authorization: Bearer <token>`. Required for a non-loopback listener.
          `/healthz` stays open.
        '';
      };
    };

    logLevel = mkOption {
      type = types.enum [
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "Log verbosity. Writes are always audit-logged at info.";
    };
    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra command-line arguments. Never put a secret here.";
    };
  };

  config = lib.mkMerge [
    (mkIf cfg.enable { environment.systemPackages = [ cfg.package ]; })

    (mkIf (cfg.enable && cfg.http.enable) {
      assertions = [
        {
          assertion = cfg.cloud == null || cfg.baseUrl == null;
          message = "services.falcon-mcp: set at most one of cloud and baseUrl.";
        }
        {
          assertion = (cfg.clientId == null) != (cfg.clientIdFile == null);
          message = "services.falcon-mcp: set exactly one of clientId and clientIdFile.";
        }
        {
          assertion = cfg.clientIdFile == null || lib.hasPrefix "/" cfg.clientIdFile;
          message = "services.falcon-mcp.clientIdFile must be an absolute path.";
        }
        {
          assertion = cfg.clientSecretFile != null && lib.hasPrefix "/" cfg.clientSecretFile;
          message = "services.falcon-mcp.clientSecretFile must be an absolute runtime path to the API client secret.";
        }
        {
          assertion = !(inStore cfg.clientSecretFile) && !(inStore cfg.http.authTokenFile);
          message = "services.falcon-mcp: secret files must not live in ${builtins.storeDir}, which is world-readable. Use sops-nix, agenix or a root-owned 0400 file.";
        }
        {
          assertion = validAddr;
          message = "services.falcon-mcp.http.addr must be host:port or [v6]:port with a port from 1 to 65535, got ${cfg.http.addr}.";
        }
        {
          assertion = !validAddr || isLoopback || cfg.http.authTokenFile != null;
          message = "services.falcon-mcp.http.addr is ${cfg.http.addr} (not loopback) without http.authTokenFile; the server refuses to start unauthenticated on a network address.";
        }
        {
          assertion = cfg.http.authTokenFile == null || lib.hasPrefix "/" cfg.http.authTokenFile;
          message = "services.falcon-mcp.http.authTokenFile must be an absolute path.";
        }
        {
          assertion = lib.hasPrefix "/" cfg.http.path;
          message = "services.falcon-mcp.http.path must begin with a slash.";
        }
      ];

      warnings =
        optional cfg.allow.destructive "services.falcon-mcp.allow.destructive is true: a model can make irreversible bulk changes to the tenant."
        ++ optional cfg.allow.rtr-respond "services.falcon-mcp.allow.rtr-respond is true: a model can kill processes and delete or place files on hosts.";

      systemd.services.falcon-mcp = {
        description = "CrowdStrike Falcon MCP server";
        documentation = [ "https://github.com/lcleveland/falcon-mcp" ];
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          Type = "exec";
          ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs args}";
          Restart = "on-failure";
          RestartSec = 5;
          LoadCredential = [
            "client-secret:${cfg.clientSecretFile}"
          ]
          ++ optional (cfg.clientIdFile != null) "client-id:${cfg.clientIdFile}"
          ++ optional (cfg.http.authTokenFile != null) "http-auth-token:${cfg.http.authTokenFile}";

          DynamicUser = true;
          AmbientCapabilities = [ "" ];
          CapabilityBoundingSet = [ "" ];
          DevicePolicy = "closed";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          # AF_NETLINK: Go's pure resolver reads interface addresses.
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
          ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "~@resources"
          ];
          UMask = "0077";
          SocketBindDeny = "any";
          SocketBindAllow = mkIf validAddr "tcp:${port}";
        };
      };
    })
  ];
}
