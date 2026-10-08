# falcon-mcp

An MCP server for the [CrowdStrike Falcon](https://www.crowdstrike.com/) REST API, written in Go. It serves over stdio or streamable HTTP and is packaged as a Nix flake with a NixOS module.

The server is read-only by default. Writes are turned on per **capability** (triage, containment, RTR, ...), every write needs a reason that goes to the audit log, and some operations are never exposed at all: RTR admin commands and runscript, permanent host deletion, revealing uninstall tokens or turning off uninstall protection, and user, API-client and installation-token administration.

## Tools

| Group | Tools |
|---|---|
| core (always on) | `falcon_status` (auth, cloud, rate-limit headroom, the startup probe, and `action=guide`), `falcon_api` (any Falcon operation, capability-gated) |
| respond | `falcon_alert`, `falcon_case`, `falcon_rtr` (Real Time Response), `falcon_quarantine` |
| hosts | `falcon_host`, `falcon_host_group`, `falcon_discover` (applications, managed and unmanaged assets), `falcon_zta` (Zero Trust Assessment), `falcon_sensor_usage` |
| prevent | `falcon_policy` (by `policy_type`: prevention, sensor_update, firewall, device_control, response, content_update), `falcon_exclusion` (by `exclusion_type`: ioa, ml, sensor_visibility, certificate), `falcon_firewall`, `falcon_custom_ioa`, `falcon_ioc` |
| intel | `falcon_intel` (actors, indicators, reports, MITRE reports), `falcon_recon` (Falcon Intelligence Recon) |
| siem | `falcon_ngsiem` (CQL search), `falcon_correlation_rule`, `falcon_workflow` (Fusion SOAR), `falcon_report` (scheduled reports and searches) |
| exposure | `falcon_vulnerability` (Spotlight and serverless), `falcon_cloud` (Cloud Security), `falcon_shield` (SaaS Security), `falcon_data_protection` |
| identity | `falcon_identity` (Identity Protection GraphQL, queries only) |
| ai | `falcon_guardian` (AIDR: AI agents seen on hosts), `falcon_agentworks` (Charlotte AI AgentWorks) |

Every tool takes an `action`; each tool's description lists its actions and what they take. The read actions are:

| Tool | Read actions |
|---|---|
| `falcon_alert` | search, get, aggregate |
| `falcon_case` | search, get, list_templates, aggregate_slas, aggregate_templates, aggregate_access_tags, aggregate_notification_groups, aggregate_file_details |
| `falcon_rtr` | search_sessions, search_audit_sessions, aggregate_sessions, get_session |
| `falcon_quarantine` | search, get, preview_actions |
| `falcon_host` | search, get |
| `falcon_host_group` | search, search_members |
| `falcon_discover` | search_applications, search_unmanaged_assets, search_managed_assets |
| `falcon_zta` | search, get, get_audit |
| `falcon_sensor_usage` | search_weekly |
| `falcon_policy` | search, get, search_members |
| `falcon_exclusion` | search, get, get_certificate_details |
| `falcon_firewall` | search_rules, search_rule_groups, search_policy_rules, get_rules, get_rule_groups |
| `falcon_custom_ioa` | search_rule_groups, get_platforms, get_rule_types, get_rule_type |
| `falcon_ioc` | search, get |
| `falcon_intel` | search_actors, search_indicators, search_reports, get_mitre_report |
| `falcon_recon` | search_notifications, get_notifications, search_rules, get_rules, search_exposed_data_records, get_exposed_data_records, aggregate_notifications, aggregate_exposed_data_records, preview_rule |
| `falcon_ngsiem` | search |
| `falcon_correlation_rule` | search |
| `falcon_workflow` | search_definitions, search_executions, get_execution_results |
| `falcon_report` | search, get, search_executions, get_executions, download_execution |
| `falcon_vulnerability` | search, search_serverless |
| `falcon_cloud` | search_cspm_assets, search_kubernetes_containers, count_kubernetes_containers, search_images_vulnerabilities, search_insights, get_asset_insights, list_insight_definitions, search_iom_findings, search_suppression_rules, search_risks, search_groups, get_groups |
| `falcon_shield` | search_checks, get_check_affected_entities, get_posture_metrics, get_check_compliance, search_alerts, get_activity_monitor, search_users, search_devices, search_apps, get_app_users, search_data_shares, get_integrations, get_system_users, get_supported_saas, get_system_logs |
| `falcon_data_protection` | search_classifications, search_policies, search_content_patterns |
| `falcon_identity` | investigate_entity |
| `falcon_guardian` | search_, get_ and aggregate_ actions over agents, sessions, tools, skills, OS users, MCP servers, installs, models, executions, tool and skill usage, prompts and detections, plus get_session_activity, get_process_tree, get_network_events, get_file_events, get_classified_file_access |
| `falcon_agentworks` | search_agents, get_agents, search_agent_versions, get_agent_versions, search_spans, get_spans, get_invocation |

Searches:
- take an FQL `filter` and `sort`, and return a brief field set unless you pass `fields`;
- cap results at 200 items and 60 KiB, adding a `_truncation` note when they have to cut;
- return `next_cursor` when there is more. Pass it back as `cursor`. It hides Falcon's offset and `after` paging.

Gets take up to 200 `ids`. Timestamps come back as RFC 3339 UTC. Reads are retried once on a 429 or 5xx, honouring `X-RateLimit-RetryAfter`.

`falcon_api` calls any operation in the generated table by its FalconPy operation ID, or by `method` and `path`. A write that a typed tool sends is refused there, with a pointer to that tool, so the typed tool's rails apply. The few writes no typed tool sends each belong to a capability or to "never" (a test enforces this). GETs outside the table are allowed; other methods outside it are refused.

## Write capabilities

All are off by default. A disabled capability's actions are removed from the tool schemas and also refused by the handler. Why capabilities rather than Falcon's scopes: `Hosts:write` alone covers tagging, containment, hiding a host and permanent deletion. See [ADR 0002](docs/adr/0002-capability-flags-over-falcon-scopes.md).

| Flag | Unlocks |
|---|---|
| `--allow-triage` | `falcon_alert` update (status, assignee, comments, tags); `falcon_case` create, update, add evidence, add/remove tags |
| `--allow-host-tags` | `falcon_host` add_tags, remove_tags |
| `--allow-containment` | `falcon_host` contain, lift_containment |
| `--allow-detection-add` | custom IOA rule and rule-group create and enable; IOC create and update; through `falcon_api`, correlation-rule create and Cloud Security suppression-rule delete |
| `--allow-detection-remove` | exclusions of every type (create, update, delete); custom IOA disable and delete; allow-listing and deleting IOCs; quarantine release/unrelease; `falcon_host` suppress_detections, unsuppress_detections; through `falcon_api`, correlation-rule update/delete, suppression-rule create and SaaS Security check dismissal |
| `--allow-fleet-config` | policies of every type (create, update, delete, perform, set_precedence); host groups (create, update, delete, add/remove hosts); firewall rule groups |
| `--allow-rtr-read` | `falcon_rtr` sessions, batch sessions, listing session files, and read-only commands on live hosts: `cat`, `cd`, `env`, `eventlog list`/`view`, `filehash`, `getsid`, `history`, `ipconfig`, `ls`, `netstat`, `ps`, `pwd`, `reg query`, `users` |
| `--allow-rtr-respond` | `falcon_rtr` run_responder_command on one host: `cp`, `get`, `kill`, `memdump`, `mkdir`, `mv`, `put`, `reg` delete/load/set/unload, `rm`, `umount`, `xmemdump`, `zip` |
| `--allow-destructive` | `falcon_host` hide_host, unhide_host; `falcon_quarantine` delete |
| `--allow-workflows` | `falcon_workflow` execute, `falcon_report` launch; through `falcon_api`, invoking an AgentWorks agent |

**Write safety:**
- Every write requires `reason`. It goes to the audit log (with the tool, action, capability, target ids and Falcon's trace ID) before the call is sent and again with the outcome. Where Falcon has a comment or note field, the reason goes there too: alert comments, the note on containment and detection suppression, and the comment on quarantine, custom IOA, IOC and exclusion writes. RTR has no comment field, so there it is audit-logged only.
- A write touches at most `--max-bulk` records (1000), or Falcon's own per-call limit when that is lower.
- Writes that act on records take `ids`, or a `filter`. A filter is first resolved to ids with reads only; if it matches nothing, or more than the limit, nothing is sent. Otherwise the reply says how many records it matches, and the write runs only when repeated with `confirm` equal to that count.
- Host actions (contain, lift containment, suppress detections, hide and unhide, RTR responder commands) take exactly one device id and need `confirm` equal to that host's hostname. A mismatch fails before anything is sent.
- Writes are never retried automatically. Falcon takes no idempotency keys, so a retried write could happen twice.

## Probe

At startup the server makes one cheap read (`limit=1`) per read scope, concurrently, within 10 seconds. A 403 that is not a token error means "missing scope or not licensed", and that scope's actions are hidden. A write is shown only when its family's read scope passed, and a tool left with no actions is not listed. Anything uncertain (a timeout, a 5xx) fails open and shows the actions.

`falcon_status` reports the cloud and base URL, whether the token works and when it expires, the rate-limit headroom from one read, the probe result for each scope, the enabled tool groups and capabilities, each visible tool's actions, and the guides. Call it first when another tool fails. The probe runs once, so restart the server after granting a scope.

`--no-probe` skips the probe and shows every action allowed by the groups and capabilities.

## Guides

Query-language guides (FQL fields and operators per area, CQL for NGSIEM, the RTR investigation workflow, AIDR and SaaS Security parameters) are served two ways:
- as MCP resources at `falcon://...` URIs, for clients that read resources;
- through `falcon_status` with `action=guide` and the guide's `name`, for clients that only call tools.

Each filter's description and each action's help names its guide. Only the guides of visible actions are served. The guides come from [CrowdStrike/falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) under its MIT licence ([`guides/LICENSE`](guides/LICENSE)).

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--cloud` (`us-1`, `us-2`, `us-3`, `eu-1`, `us-gov-1`, `us-gov-2`) | `FALCON_CLOUD` | autodiscovered, except gov clouds |
| `--base-url` | `FALCON_BASE_URL` | instead of `--cloud`; https only, except to loopback |
| `--client-id` | `FALCON_CLIENT_ID` | required, or a file below |
| `--client-id-file` | `FALCON_CLIENT_ID_FILE` | the systemd credential `client-id`; a file wins over `--client-id` |
| `--client-secret-file` | `FALCON_CLIENT_SECRET_FILE` | see below |
| `--allow-<capability>` | | all off |
| `--max-bulk` | | 1000 |
| `--tool-groups` (`core`, `respond`, `hosts`, `prevent`, `intel`, `siem`, `exposure`, `identity`, `ai`) | | all; `core` is always on |
| `--no-probe` | | probe on |
| `--stdio` / `--http` | | stdio |
| `--addr`, `--path` | | `127.0.0.1:8235`, `/mcp` |
| `--http-auth-token-file` | `FALCON_MCP_HTTP_AUTH_TOKEN_FILE` | the systemd credential `http-auth-token`, else none (a non-loopback listener requires one) |
| `--request-timeout` | | `30s` |
| `--log-level` (`debug`, `info`, `warn`, `error`) | `FALCON_MCP_LOG_LEVEL` | `info` |
| `--version` | | |

Over HTTP, clients send the token as `Authorization: Bearer <token>`. `/healthz` stays open. Logs, including the write audit log, go to stderr.

**Client secret.** The server looks for it in this order:
1. `--client-secret-file`
2. `FALCON_CLIENT_SECRET_FILE`
3. `FALCON_CLIENT_SECRET` (logs a warning)
4. the systemd credential `client-secret`

There is no flag that takes the secret directly.

### Getting an API client

1. In the Falcon console, go to **Support and resources → Resources and tools → Client Management**, and open the **API clients** tab. Not **MCP clients**: that tab registers MCP clients for CrowdStrike's hosted Falcon MCP, and its credentials do not work here.
2. Add a client and tick the scopes below, using the console's names. Give it only what you will use: a missing scope just hides those actions.
3. Do not add **API Client Management**: it cannot be combined with product scopes, and the server does not need it.
4. Save, then copy the client ID and secret. The secret is shown once.

**Read** scopes, by tool group:

| Group | Read |
|---|---|
| respond | Alerts, Cases, Case Templates, Real time response, real-time-response-audit, Quarantined Files |
| hosts | Hosts, Host Groups, Assets, Zero Trust Assessment, Sensor Usage |
| prevent | Prevention Policies, Sensor Update Policies, Firewall Management, Device Control Policies, Response Policies, Content Update Policies, IOA Exclusions, Machine Learning Exclusions, Sensor Visibility Exclusions, Custom IOA Rules, IOC Management |
| intel | Actors (Falcon Intelligence), Indicators (Falcon Intelligence), Reports (Falcon Intelligence), Monitoring rules (Falcon Intelligence Recon) |
| siem | NGSIEM (**read and write**: a search is started and stopped with write calls), Correlation Rules, Workflows, Scheduled Reports |
| exposure | Vulnerabilities, Falcon Container Image, Cloud Security API Assets, Cloud Security API Detections, Cloud Security API Risks, Cloud Security Policies, Cloud Groups V2, SaaS Security, Data Protection |
| identity | Identity Protection Entities (read), Identity Protection GraphQL (**write**: the GraphQL route is a write scope, but the server sends queries only and refuses mutations) |
| ai | AIDR, Charlotte AI Agent Definition |

**Write** scopes, by capability (each also needs its family's read):

| Capability | Write |
|---|---|
| triage | Alerts, Cases |
| host-tags, containment, destructive | Hosts |
| detection-add | Custom IOA Rules, IOC Management |
| detection-remove | IOA Exclusions, Machine Learning Exclusions, Sensor Visibility Exclusions, Custom IOA Rules, IOC Management, Quarantined Files, Hosts |
| fleet-config | Prevention Policies, Sensor Update Policies, Firewall Management, Device Control Policies, Response Policies, Content Update Policies, Host Groups |
| rtr-read, rtr-respond | Real time response |
| destructive | Quarantined Files |
| workflows | Workflows |

`falcon_api`'s untyped writes also need their own write scopes: Correlation Rules, Cloud Security Policies, SaaS Security and Charlotte AI Agent Definition.

`falcon_status` shows which scopes the probe found missing. A 401 at startup means the ID or secret is wrong. A 403 from the token endpoint usually means an IP allowlist or a disabled client.

## Nix

```nix
{
  inputs.falcon-mcp.url = "github:lcleveland/falcon-mcp";

  outputs = { nixpkgs, falcon-mcp, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        falcon-mcp.nixosModules.default
        {
          services.falcon-mcp = {
            enable = true;      # falcon-mcp on PATH, for stdio
            http.enable = true; # and the HTTP service
            cloud = "us-1";     # or leave unset to autodiscover
            clientId = "<client id>";
            # or, to keep the ID out of the Nix config:
            # clientIdFile = "/persist/secrets/falcon-client-id";
            # sops-nix / agenix path, or a root-only file:
            #   printf %s '<secret>' | sudo install -m 0400 /dev/stdin /persist/secrets/falcon-client-secret
            clientSecretFile = "/persist/secrets/falcon-client-secret";
            allow.triage = true;
          };
        }
      ];
    };
  };
}
```

`enable` puts the binary on PATH; `http.enable` adds the systemd service, which every other option configures. The module:
- passes secrets through systemd `LoadCredential`, so they never reach the Nix store, argv or the environment, and refuses secret paths inside the store;
- runs the service as a hardened DynamicUser;
- refuses a non-loopback listener without `http.authTokenFile`;
- warns when `allow.destructive` or `allow.rtr-respond` is on.

| Option | Default | Notes |
|---|---|---|
| `enable`, `package` | off, this flake's build | |
| `cloud` / `baseUrl` | both unset (autodiscover) | at most one |
| `clientId` / `clientIdFile` | | exactly one |
| `clientSecretFile` | | a runtime path string, never a Nix path |
| `allow.<capability>` | `false` | one per capability, e.g. `allow.rtr-read` |
| `toolGroups` | all | |
| `maxBulk`, `noProbe` | 1000, `false` | |
| `http.enable` | off | |
| `http.addr`, `http.path` | `127.0.0.1:8235`, `/mcp` | |
| `http.authTokenFile` | none | required for a non-loopback `addr` |
| `logLevel` | `info` | |
| `extraArgs` | `[ ]` | e.g. `--request-timeout`; never put a secret here |

`overlays.default` provides `pkgs.falcon-mcp`.

### Claude Code

Over HTTP, against the NixOS service:

```sh
claude mcp add --scope user --transport http falcon http://127.0.0.1:8235/mcp
```

With a bearer token, add `--header "Authorization: Bearer <token>"`.

Over stdio:

```sh
claude mcp add falcon -e FALCON_CLIENT_ID=<id> \
  -e FALCON_CLIENT_SECRET_FILE=$HOME/.config/falcon-mcp/client-secret -- falcon-mcp
```

Add flags after `falcon-mcp`, e.g. `-- falcon-mcp --allow-triage --tool-groups respond,hosts`.

## Compared with other Falcon MCP servers

**[CrowdStrike/falcon-mcp](https://github.com/CrowdStrike/falcon-mcp)**, the official open-source server, is the reference for coverage: this server covers the same modules and serves the same guides.
- It registers about 170 tools, one per operation; this one has one tool per area with an `action`, so a client loads a few dozen schemas.
- Its writes are on unless you pass `--read-only`, and are gated by module. Here writes are off and gated by capability, which separates, say, adding a detection from removing one.
- It has no reason, audit log, bulk cap, filter confirmation or hostname confirmation on writes.
- It does not probe: a missing scope shows up as a 403 when a tool is called. Here those actions are hidden.
- It has no host containment, no RTR active-responder commands and no raw API tool. This server adds them, each behind a capability.
- It is Python; this is one static Go binary with a NixOS module.

**CrowdStrike's hosted Falcon MCP** needs nothing deployed. Clients connect to it through the console's **MCP clients** tab, and it works by discovery (`search_tools`, then `execute_tool`). It does not offer Fusion SOAR, Zero Trust Assessment or RTR. This server runs on your own infrastructure, with an API client and capability flags you control.

## Development

```sh
nix develop            # go and tools
go test ./...
go generate ./internal/falcon   # regenerate the op table and guides
nix flake check        # package build + Go tests + module eval checks + VM test
nix build .#checks.x86_64-linux.vm   # the VM test alone, against a stub Falcon
```

The design decisions are recorded on [Falcon MCP v1 spec](https://github.com/lcleveland/falcon-mcp/issues/1) and in [`docs/adr/`](docs/adr/). Research notes are in [`docs/research/`](docs/research/). Terms are defined in [`GLOSSARY.md`](GLOSSARY.md).
