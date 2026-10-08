# falcon-mcp

An MCP server for the [CrowdStrike Falcon](https://www.crowdstrike.com/) REST API, written in Go. It serves over stdio or streamable HTTP and is packaged as a Nix flake with a NixOS module.

The server is read-only by default. Writes are turned on per **capability** (triage, containment, RTR, ...), every write needs a reason that goes to the audit log, and some writes are never exposed at all: RTR admin commands and runscript, batch RTR responder commands, quarantine changes selected by query, permanent host deletion, revealing uninstall tokens or turning off uninstall protection, and user, API-client and installation-token administration.

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

Every tool takes an `action`; each tool's description lists its actions and what they take. A write action exists only while its capability is on:

| Tool | Read actions | Write actions (capability) |
|---|---|---|
| `falcon_status` | check (the default), guide | |
| `falcon_api` | any GET, by `op` or `method` and `path` | see below |
| `falcon_alert` | search, get, aggregate | update (triage) |
| `falcon_case` | search, get, list_templates, aggregate_slas, aggregate_templates, aggregate_access_tags, aggregate_notification_groups, aggregate_file_details | create, update, add_alert_evidence, add_event_evidence, add_tags, remove_tags (triage) |
| `falcon_rtr` | search_sessions, search_audit_sessions, aggregate_sessions, get_session | init_session, pulse_session, delete_session, run_command, check_command_status, list_files, init_batch, pulse_batch, run_batch_command (rtr-read); run_responder_command, check_responder_status (rtr-respond) |
| `falcon_quarantine` | search, get, preview_actions | release, unrelease (detection-remove); delete (destructive) |
| `falcon_host` | search, get | add_tags, remove_tags (host-tags); contain, lift_containment (containment); suppress_detections, unsuppress_detections (detection-remove); hide_host, unhide_host (destructive) |
| `falcon_host_group` | search, search_members | create, update, delete, add_hosts, remove_hosts (fleet-config) |
| `falcon_discover` | search_applications, search_unmanaged_assets, search_managed_assets |  |
| `falcon_zta` | search, get, get_audit |  |
| `falcon_sensor_usage` | search_weekly |  |
| `falcon_policy` | search, get, search_members | create, update, delete, perform, set_precedence (fleet-config) |
| `falcon_exclusion` | search, get, get_certificate_details | create, update, delete (detection-remove) |
| `falcon_firewall` | search_rules, search_rule_groups, search_policy_rules, get_rules, get_rule_groups | create_rule_group, update_rule_group, delete_rule_groups (fleet-config) |
| `falcon_custom_ioa` | search_rule_groups, get_platforms, get_rule_types, get_rule_type | create_rule_group, create_rule, enable_rule_group, enable_rules (detection-add); disable_rule_group, disable_rules, delete_rule_groups, delete_rules (detection-remove) |
| `falcon_ioc` | search, get | create, update (detection-add); create_allow, update_allow, delete (detection-remove) |
| `falcon_intel` | search_actors, search_indicators, search_reports, get_mitre_report |  |
| `falcon_recon` | search_notifications, get_notifications, search_rules, get_rules, search_exposed_data_records, get_exposed_data_records, aggregate_notifications, aggregate_exposed_data_records, preview_rule |  |
| `falcon_ngsiem` | search |  |
| `falcon_correlation_rule` | search |  |
| `falcon_workflow` | search_definitions, search_executions, get_execution_results | execute (workflows) |
| `falcon_report` | search, get, search_executions, get_executions, download_execution | launch (workflows) |
| `falcon_vulnerability` | search, search_serverless |  |
| `falcon_cloud` | search_cspm_assets, search_kubernetes_containers, count_kubernetes_containers, search_images_vulnerabilities, search_insights, get_asset_insights, list_insight_definitions, search_iom_findings, search_suppression_rules, search_risks, search_groups, get_groups |  |
| `falcon_shield` | search_checks, get_check_affected_entities, get_posture_metrics, get_check_compliance, search_alerts, get_activity_monitor, search_users, search_devices, search_apps, get_app_users, search_data_shares, get_integrations, get_system_users, get_supported_saas, get_system_logs |  |
| `falcon_data_protection` | search_classifications, search_policies, search_content_patterns |  |
| `falcon_identity` | investigate_entity |  |
| `falcon_guardian` | search_, get_ and aggregate_ actions over agents, sessions, tools, skills, OS users, MCP servers, installs, models, executions, tool and skill usage, prompts and detections, plus get_session_activity, get_process_tree, get_network_events, get_file_events, get_classified_file_access |  |
| `falcon_agentworks` | search_agents, get_agents, search_agent_versions, get_agent_versions, search_spans, get_spans, get_invocation |  |

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
- Every write requires `reason`. It goes to the audit log (with the tool, action, capability, target ids and Falcon's trace ID) before the call is sent and again with the outcome. Where Falcon has a comment or note field, the reason goes there too: alert comments, the note on containment and detection suppression, and the comment on quarantine, custom IOA, IOC, exclusion and firewall rule-group writes. Elsewhere (RTR, cases, workflow and report runs) it is audit-logged only.
- A write touches at most `--max-bulk` records (1000), or Falcon's own per-call limit when that is lower.
- Writes that act on records take `ids`; some (alert updates, for one) take a `filter` instead. A filter is first resolved to ids with reads only; if it matches nothing, or more than the limit, nothing is sent. Otherwise the reply says how many records it matches, and the write runs only when repeated with `confirm` equal to that count.
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

### Setting up the API client

1. In the Falcon console, go to **Support and resources → Resources and tools → Client Management**, and open the **API clients** tab. Not **MCP clients**: that tab registers MCP clients for CrowdStrike's hosted Falcon MCP, and its credentials do not work here.
2. Add a client and tick the scopes below, using the console's names. Give it only what you will use: a missing scope just hides those actions.
3. Do not add **API Client Management**: it cannot be combined with product scopes, and the server does not need it.
4. Save, then copy the client ID and secret. The secret is shown once.
5. Put the secret in a file only you can read. Paste it into `cat`, so it stays out of argv and shell history, then press Ctrl-D:
   ```sh
   mkdir -p ~/.config/falcon-mcp
   (umask 077; cat > ~/.config/falcon-mcp/client-secret)
   ```
   Surrounding whitespace and the trailing newline are trimmed. For the NixOS service, use a root-only file or a sops-nix/agenix path instead (see [Nix](#nix)).
6. Point the server at it with `--client-id <id> --client-secret-file ~/.config/falcon-mcp/client-secret` (or the `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET_FILE` env vars). Set `--cloud` for a gov cloud; other clouds are autodiscovered.
7. Call `falcon_status`. It shows whether the token works, the cloud, and which scopes the probe found missing. Grant any you need, then restart the server: the probe runs only at startup.

To rotate the secret, reset it on the API client in the console, overwrite the file, and restart the server.

Every scope, in the console's order; leave the "not used" ones unticked. **Read** names the tool group that needs read; **Write** names the capabilities that need write, and each also needs that scope's read.

| Scope | Read | Write |
|---|---|---|
| Access Scopes | not used | |
| Alerts | respond | triage |
| API Client Management | $\color{red}\textbf{Do not enable}$ | $\color{red}\textbf{Do not enable}$ |
| API integrations | not used | |
| Application Abuse Exclusions | not used | |
| App Logs | not used | |
| Apps | not used | |
| Audit Logs | not used | |
| Case Analyst Dashboards | not used | |
| Case SOC Dashboards | not used | |
| Case Templates | respond | |
| Cases | respond | triage |
| Charlotte AI Agent Definition | ai | workflows (agent invoke, through `falcon_api`) |
| Charlotte AI Agent Evaluation Runs | not used | |
| Charlotte AI Agent Evaluations | not used | |
| Cloud Security AWS Registration | not used | |
| Cloud Security Azure Registration | not used | |
| Cloud Security Google Cloud Registration | not used | |
| Cloud ML Policies | not used | |
| Cloud Security OCI Registration | not used | |
| Cloud Security Registration | not used | |
| Content Update Policy | prevent | fleet-config |
| Correlation Rules Admin | not used | |
| Correlation Rules | siem | detection-add, detection-remove (through `falcon_api`) |
| Custom IOA rules | prevent | detection-add, detection-remove |
| Custom storage | not used | |
| Delete Managed Assets | not used | |
| Channel File Control Settings | not used | |
| Deployment Coordinator | not used | |
| Detections | not used | |
| Device Content | not used | |
| Device control policies | prevent | fleet-config |
| Hosts | hosts | host-tags, containment, detection-remove, destructive |
| Assets | hosts | |
| Falcon Complete Dashboard | not used | |
| Actors (Falcon Intelligence) | intel | |
| Indicators (Falcon Intelligence) | intel | |
| Malware Families (Falcon Intelligence) | not used | |
| Reports (Falcon Intelligence) | intel | |
| Sandbox (Falcon Intelligence) | not used | |
| Foundry Extensions | not used | |
| Foundry Navigations | not used | |
| Foundry Pages | not used | |
| Host groups | hosts | fleet-config |
| Host Migration | not used | |
| NGSIEM | siem | siem: **needed to search**, since a search is started and stopped with write calls |
| Identity Protection Assessment | not used | |
| Identity Protection Detections | not used | |
| Identity Protection Enforcement | not used | |
| Identity Protection Entities | identity | |
| Identity Protection GraphQL | | identity: **needed to query**; the GraphQL route is a write scope, but the server sends queries only and refuses mutations |
| Identity Protection Health | not used | |
| Identity Protection on-premise enablement | not used | |
| Identity Protection Policy Rules | not used | |
| Identity Protection Timeline | not used | |
| Incidents | not used | |
| Falcon Indicator Graph | not used | |
| Installation Tokens Settings | not used | |
| Installation Tokens | not used | |
| IOC Management | prevent | detection-add, detection-remove |
| Bulk uninstallation token | not used | |
| MalQuery | not used | |
| Message Center | not used | |
| Machine Learning Exclusions | prevent | detection-remove |
| Network Containment Allowlist | not used | |
| NGSIEM Dashboards | not used | |
| NGSIEM Data Connections API | not used | |
| NGSIEM Lookup Files | not used | |
| NGSIEM Parsers | not used | |
| NGSIEM Persisted Aggregations | not used | |
| NGSIEM Saved Queries | not used | |
| NGSIEM Scheduled Reports | not used | |
| On-demand scans (ODS) | not used | |
| Prevention policies | prevent | fleet-config |
| Quarantined Files | respond | detection-remove, destructive |
| Quick Scan (Falcon Intelligence) | not used | |
| Real time response (admin) | not used | |
| Real time response app | not used | |
| Real time response audit | respond | |
| Real time response | respond | rtr-read, rtr-respond |
| Response policies | prevent | fleet-config |
| Sample uploads | not used | |
| Scheduled Reports | siem (also report launch) | |
| IOA Exclusions | prevent | detection-remove |
| Sensor Download | not used | |
| Sensor update policies | prevent | fleet-config |
| Sensor Usage | hosts | |
| Sensor Visibility Exclusions | prevent | detection-remove |
| Event streams | not used | |
| Third Party Detection Exclusions | not used | |
| Third-Party IOC Exports API | not used | |
| Third-Party IOC Feeds API | not used | |
| Third-Party IOCs API | not used | |
| Threatgraph | not used | |
| User management | not used | |
| Workflow | siem | workflows |
| XDR 3rd Party Response | not used | |
| Zero Trust Assessment | hosts | |

Scopes the server uses that are not in that list; find them by name:

| Scope | Read | Write |
|---|---|---|
| Firewall Management | prevent | fleet-config |
| Monitoring rules (Falcon Intelligence Recon) | intel | |
| Vulnerabilities | exposure | |
| Falcon Container Image | exposure | |
| Cloud Security API Assets, Cloud Security API Detections, Cloud Security API Risks, Cloud Groups V2 | exposure | |
| Cloud Security Policies | exposure | detection-add, detection-remove (suppression rules, through `falcon_api`) |
| SaaS Security | exposure | detection-remove (check dismissal, through `falcon_api`) |
| Data Protection | exposure | |
| AIDR | ai | |

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
- It registers one tool per operation; this one has one tool per area with an `action`, so a client loads a few dozen schemas.
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
