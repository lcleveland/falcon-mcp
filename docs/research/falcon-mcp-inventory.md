# Official CrowdStrike falcon-mcp: module and tool inventory

Research for the wayfinder ticket "Official falcon-mcp module and tool inventory".

**Source snapshot:** [CrowdStrike/falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) at commit `82d5031` (2026-10-06), package version 0.19.0 (`pyproject.toml`). Everything below was extracted from that source with a Python AST walk, not from secondary write-ups:

- Tool names, read/write/destructive flags: `_add_tool(...)` calls in `falcon_mcp/modules/**/*.py` ([base.py](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/falcon_mcp/modules/base.py) prefixes every name with `falcon_` and defaults annotations to read-only).
- Operations per tool: string literals in each tool method (and the private helpers it calls) that are keys of `API_SCOPE_REQUIREMENTS`.
- Scopes: [`falcon_mcp/common/api_scopes.py`](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/falcon_mcp/common/api_scopes.py) (operation ID to scope map, 228 entries). Cross-checked against the generated per-module pages in [`docs/modules/`](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/docs/modules).
- HTTP routes: resolved from the operation ID via FalconPy's endpoint tables ([`src/falconpy/_endpoint/`](https://github.com/CrowdStrike/falconpy/tree/main/src/falconpy/_endpoint)). The operation IDs are the swagger `operationId`s, so they are the same names gofalcon uses.

## Headline numbers

| | Count |
|---|---|
| Modules (`--modules` keys) | 28 (cloud is one module built from 5 mixins) |
| Module tools | 166 |
| Server-level tools | 3: `falcon_check_connectivity`, `falcon_list_enabled_modules`, `falcon_list_enabled_tools` ([server.py](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/falcon_mcp/server.py)); dynamic mode swaps the module tools for `falcon_search_tools` + `falcon_execute_tool` ([dynamic-mode.md](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/docs/usage/dynamic-mode.md)) |
| Tools with `readOnlyHint=False` | 45, of which 31 are also `destructiveHint=True` |
| MCP resources | 54 static `TextResource`s, all `falcon://...` query guides (FQL, CQL, AIDR schema, RTR workflow) |
| MCP prompts | **0** (no `add_prompt`/`@prompt` anywhere in the package) |

Server-wide controls worth copying ([cli.md](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/docs/usage/cli.md)): `--modules`, `--read-only` (drops every tool whose annotations are not read-only), `--tools` (additive allow-list), `--exclude-tools`, `--dynamic`.

## Mapping onto sibling-style tools (one tool per area, `action` param)

Proposed grouping; "actions" are the official tools with the `falcon_` prefix and the area noun stripped. **W** marks actions that mutate tenant state.

| Sibling tool | Official module(s) | Actions | Scope family |
|---|---|---|---|
| `falcon_alert` | detections | search, get, aggregate, update **W** | Alerts |
| `falcon_host` | hosts | search, get, manage_tags **W** | Hosts |
| `falcon_host_group` | host_groups | search, search_members, create **W**, update **W**, delete **W**, perform_action **W** | Host Groups |
| `falcon_policy` | policies (`policy_type`: prevention, sensor_update, firewall, device_control, response, content_update) | search, search_members, create **W**, update **W**, delete **W**, perform_action **W**, set_precedence **W** | one scope per policy type |
| `falcon_exclusion` | exclusions (`exclusion_type`: ioa, ml, sensor_visibility, certificate) | search, create **W**, update **W**, delete **W**, get_certificate_details | IOA / ML / Sensor Visibility Exclusions |
| `falcon_firewall` | firewall | search_rules, search_rule_groups, search_policy_rules, create_rule_group **W**, delete_rule_groups **W** | Firewall Management |
| `falcon_custom_ioa` | custom_ioa | search_rule_groups, get_platforms, get_rule_types, create/update/delete rule_group **W**, create/update/delete rule **W** | Custom IOA Rules |
| `falcon_ioc` | ioc | search, add **W**, remove **W** | IOC Management |
| `falcon_intel` | intel | search_actors, search_indicators, search_reports, get_mitre_report | Falcon Intelligence (Actors / Indicators / Reports) |
| `falcon_vulnerability` | spotlight, serverless | search (hosts), search_serverless | Vulnerabilities, Falcon Container Image |
| `falcon_case` | cases | search, get, create **W**, update **W**, add_alert_evidence **W**, add_event_evidence **W**, manage_tags **W**, list_templates, aggregate_{slas,templates,access_tags,notification_groups,file_details} | Cases, Case Templates |
| `falcon_rtr` | rtr | search_sessions, search_audit_sessions, aggregate_sessions, get_session, init_session **W**, pulse_session **W**, execute_read_only_command **W**, run_read_only_command_and_wait **W**, check_command_status, list_session_files, delete_session **W** | Real time response (+ audit) |
| `falcon_ngsiem` | ngsiem | search (start/poll/stop query job) | NGSIEM |
| `falcon_correlation_rule` | correlation_rules | search, create **W**, update **W**, delete **W** | Correlation Rules |
| `falcon_workflow` | fusion | search_definitions, search_executions, get_execution_results, execute **W** | Workflows |
| `falcon_quarantine` | quarantine | search, preview_actions, update **W**, delete **W** | Quarantined Files |
| `falcon_discover` | discover | search_applications, search_unmanaged_assets, search_managed_assets | Assets |
| `falcon_identity` | idp | investigate_entity (GraphQL) | Identity Protection * |
| `falcon_cloud` | cloud (assets, containers, insights, iom, risks) | search_cspm_assets, search_kubernetes_containers, count_kubernetes_containers, search_images_vulnerabilities, search_insights, get_asset_insights, list_insight_definitions, search_iom_findings, search_suppression_rules, create_suppression_rule **W**, delete_suppression_rules **W**, search_risks, search_groups, get_groups | Cloud Security *, Falcon Container Image, Cloud Groups V2 |
| `falcon_shield` | shield (SaaS Security) | 15 read actions (checks, affected entities, posture metrics, compliance, alerts, activity monitor, users, devices, apps, app users, data shares, integrations, system users, supported SaaS, system logs), dismiss_check **W** | SaaS Security |
| `falcon_recon` | recon | search_notifications, search_rules, search_exposed_data_records, aggregate_notifications, aggregate_exposed_data_records, preview_rule | Monitoring rules (Falcon Intelligence Recon) |
| `falcon_data_protection` | data_protection | search_classifications, search_policies, search_content_patterns | Data Protection |
| `falcon_report` | scheduled_reports | search, launch **W**, search_executions, download_execution | Scheduled Reports |
| `falcon_zta` | zero_trust_assessment | search, get, get_audit | Zero Trust Assessment |
| `falcon_sensor_usage` | sensor_usage | search_weekly | Sensor Usage |
| `falcon_guardian` | guardian (AIDR) | 25 read actions (agents, MCP servers, sessions, tools, executions, prompts, skills, OS users, process tree, network/file events, detections, installs, models, report, pivot) | AIDR:read |
| `falcon_agentworks` | agentworks (Charlotte AI agents) | search_agents, search_agent_versions, search_spans, get_invocation, invoke **W** | Charlotte AI Agent Definition |
| `falcon_api` (escape hatch) | none upstream | raw op-ID call | caller-supplied |

## Findings worth knowing before porting

- **Write surface is concentrated**: 17 of 28 modules have at least one write tool; the heavy ones are custom_ioa (6), rtr (6), cases (5), policies (5), host_groups (4). Guardian (25 tools), shield (15 of 16), recon, intel, discover, cloud reads are pure read.
- **Annotation vs scope mismatches in upstream**: `falcon_search_ngsiem` is annotated read-only but needs `NGSIEM:write` (`StartSearchV1`/`StopSearchV1`); `falcon_idp_investigate_entity` is read-only but needs `Identity Protection GraphQL:write`; `falcon_list_rtr_session_files` (read-only) maps `RTR_ListFilesV2` to `Real time response:write`; while `init/pulse/execute` RTR tools need only `Real time response:read` but are flagged non-read-only. A read-only mode in our server should key off what the tool does, not the scope name.
- **RTR is deliberately read-only-command only** (`execute_rtr_read_only_command`, plus the `falcon://rtr/workflows/investigation-guide` resource); there is no active-responder/admin command tool and no host containment tool anywhere.
- **Policies and exclusions are already "one tool, typed param"**: they dispatch on `policy_type`/`exclusion_type` through an `_OPERATIONS` table, the same shape as our `action` design.
- **Raw-route escape hatch**: guardian (`/aidr/*`), agentworks (`/agentic-studio/*`) and cloud suppression rules (`/cloud-policies/*`) bypass FalconPy service classes via `override="METHOD,/route"`; ~~guardian's routes are not in FalconPy's swagger tables at all~~ **Correction (2026-10-08):** current FalconPy (`_endpoint/_aidr.py`, 33 routes) and gofalcon v0.23.0 (`falcon/client/aidr_events`) both have the `/aidr/*` routes, and gofalcon also has `/agentic-studio/*`; the official server's `override=` use reflects an older FalconPy, not a gap in CrowdStrike's API spec.
- **NGSIEM route safety**: `repository` is the only caller value reaching a URL path (`/humio/api/v1/repositories/{repository}/queryjobs`); upstream rejects `/ \ %` and dot segments ([ngsiem.py](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/falcon_mcp/modules/ngsiem.py) L50-95).
- **Certificate exclusions** (`cb_exclusions_*`) are scoped under `Machine Learning Exclusions` in upstream's map.
- **No prompts**: guidance is shipped only as resources, and every `filter` param description points at its `falcon://.../fql-guide`. The server `instructions` string tells the client to read the guide before composing a filter ([server.py](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/falcon_mcp/server.py) L45).

## Policies op table (`falcon_mcp/modules/policies.py` `_OPERATIONS`)

Each of 6 policy types has the same 9 ops; routes follow `/policy/{combined,queries,entities}/<type>[-members|-actions|-precedence]/vN`.

| policy_type | route segment | combined search | get | members | create / update / delete | action | precedence | scope |
|---|---|---|---|---|---|---|---|---|
| prevention | `prevention` | queryCombinedPreventionPolicies | getPreventionPolicies | queryCombinedPreventionPolicyMembers | create/update/deletePreventionPolicies | performPreventionPoliciesAction | setPreventionPoliciesPrecedence | Prevention Policies |
| sensor_update | `sensor-update` (v2 for combined/get/create/update) | queryCombinedSensorUpdatePoliciesV2 | getSensorUpdatePoliciesV2 | queryCombinedSensorUpdatePolicyMembers | createSensorUpdatePoliciesV2 / updateSensorUpdatePoliciesV2 / deleteSensorUpdatePolicies | performSensorUpdatePoliciesAction | setSensorUpdatePoliciesPrecedence | Sensor Update Policies |
| firewall | `firewall` | queryCombinedFirewallPolicies | getFirewallPolicies | queryCombinedFirewallPolicyMembers | create/update/deleteFirewallPolicies | performFirewallPoliciesAction | setFirewallPoliciesPrecedence | Firewall Management |
| device_control | `device-control` (v2 get/create/patch) | two-step: queryDeviceControlPolicies + getDeviceControlPoliciesV2 | getDeviceControlPoliciesV2 | queryCombinedDeviceControlPolicyMembers | postDeviceControlPoliciesV2 / patchDeviceControlPoliciesV2 / deleteDeviceControlPolicies | performDeviceControlPoliciesAction | setDeviceControlPoliciesPrecedence | Device Control Policies |
| response | `response` | queryCombinedRTResponsePolicies | getRTResponsePolicies | queryCombinedRTResponsePolicyMembers | create/update/deleteRTResponsePolicies | performRTResponsePoliciesAction | setRTResponsePoliciesPrecedence | Response Policies |
| content_update | `content-update` | queryCombinedContentUpdatePolicies | getContentUpdatePolicies | queryCombinedContentUpdatePolicyMembers | create/update/deleteContentUpdatePolicies | performContentUpdatePoliciesAction | setContentUpdatePoliciesPrecedence | Content Update Policies |

## Exclusions op table (`falcon_mcp/modules/exclusions.py` `_OPERATIONS`)

| exclusion_type | query | get | create | update | delete | route | scope |
|---|---|---|---|---|---|---|---|
| ioa | ss_ioa_exclusions_search_v2 | ss_ioa_exclusions_get_v2 | ss_ioa_exclusions_create_v2 | ss_ioa_exclusions_update_v2 | ss_ioa_exclusions_delete_v2 | `/exclusions/{queries,entities}/ss-ioa-exclusions/v2` | IOA Exclusions |
| ml | exclusions_search_v2 | exclusions_get_v2 | exclusions_create_v2 | exclusions_update_v2 | exclusions_delete_v2 | `/exclusions/{queries,entities}/exclusions/v2` | Machine Learning Exclusions |
| sensor_visibility | querySensorVisibilityExclusionsV1 | getSensorVisibilityExclusionsV1 | createSVExclusionsV1 | updateSensorVisibilityExclusionsV1 | deleteSensorVisibilityExclusionsV1 | `/policy/{queries,entities}/sv-exclusions/v1` | Sensor Visibility Exclusions |
| certificate | cb_exclusions_query_v1 | cb_exclusions_get_v1 | cb_exclusions_create_v1 | cb_exclusions_update_v1 | cb_exclusions_delete_v1 | `/exclusions/{queries,entities}/cert-based-exclusions/v1` | Machine Learning Exclusions |

Plus `get_certificate_details`: `certificates_get_v1` (`GET /exclusions/entities/certificates/v1`).

## Guardian (AIDR) routes

All 25 tools are read-only and go through `override=` against `/aidr/queries/{agents,agent-sessions,executions,tools,tool-usage,skills,skill-usage,agent-os-users,prompts,detections,mcp-server-names,agent-installations,model-names}/v1`, `/aidr/entities/{agents,executions,session-activity,process-tree,network-events,file-events,classified-file-access}/v1` and `/aidr/aggregates/{agents,agent-sessions,tools,skills,detections}/v1`, all under scope `AIDR:read` ([guardian.py](https://github.com/CrowdStrike/falcon-mcp/blob/82d5031dddca464bb81d74bfec31fcc51a0d5854/falcon_mcp/modules/guardian.py) L39-75).

## Full tool inventory

Kind: `read` = default read-only annotation; **write** = `readOnlyHint=False`; **write, destructive** = also `destructiveHint=True`.

### agentworks

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_agentworks_agents` | read | `GetAgentsV2`: `GET /agentic-studio/entities/agents/v2`<br>`QueryAgentsV2`: `GET /agentic-studio/queries/agents/v2` | Charlotte AI Agent Definition:read |
| `falcon_search_agentworks_agent_versions` | read | `GetAgentVersionsV1`: `GET /agentic-studio/entities/agent-versions/v1`<br>`QueryAgentVersionsV1`: `GET /agentic-studio/queries/agent-versions/v1` | Charlotte AI Agent Definition:read |
| `falcon_search_agentworks_spans` | read | `EntitiesSpansV1`: `GET /agentic-studio/entities/spans/v1`<br>`QueriesSpansV1`: `GET /agentic-studio/queries/spans/v1` | Charlotte AI Agent Definition:read |
| `falcon_get_agentworks_agent_invocation` | read | GetAgentInvocationV3: GET /agentic-studio/entities/agent-invocations/v3 | Charlotte AI Agent Definition:read |
| `falcon_invoke_agentworks_agent` | **write, destructive** | `InvokeAgentVersionExternalV1`: `POST /agentic-studio/entities/agent-version-invocations/v1`<br>`InvokePublishedAgentExternalV1`: `POST /agentic-studio/entities/agent-invocations/v1` | Charlotte AI Agent Definition:write |

### cases

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_cases` | read | `entities_cases_post_v2`: `POST /cases/entities/cases/v2`<br>`queries_cases_get_v1`: `GET /cases/queries/cases/v1` | Cases:read |
| `falcon_get_cases` | read | `entities_cases_post_v2`: `POST /cases/entities/cases/v2` | Cases:read |
| `falcon_create_case` | **write** | `entities_cases_put_v2`: `PUT /cases/entities/cases/v2` | Cases:write |
| `falcon_update_case` | **write, destructive** | `entities_cases_patch_v2`: `PATCH /cases/entities/cases/v2` | Cases:write |
| `falcon_add_case_alert_evidence` | **write** | `entities_alert_evidence_post_v1`: `POST /cases/entities/alert-evidence/v1` | Cases:write |
| `falcon_add_case_event_evidence` | **write** | `entities_event_evidence_post_v1`: `POST /cases/entities/event-evidence/v1` | Cases:write |
| `falcon_manage_case_tags` | **write, destructive** | `entities_case_tags_delete_v1`: `DELETE /cases/entities/case-tags/v1`<br>`entities_case_tags_post_v1`: `POST /cases/entities/case-tags/v1` | Cases:write |
| `falcon_list_case_templates` | read | `entities_templates_get_v1`: `GET /casemgmt/entities/templates/v1`<br>`queries_templates_get_v1`: `GET /casemgmt/queries/templates/v1` | Case Templates:read |
| `falcon_aggregate_case_slas` | read | `aggregates_slas_post_v1`: `POST /casemgmt/aggregates/slas/v1` | Case Templates:read |
| `falcon_aggregate_case_templates` | read | `aggregates_templates_post_v1`: `POST /casemgmt/aggregates/templates/v1` | Case Templates:read |
| `falcon_aggregate_case_access_tags` | read | `aggregates_access_tags_post_v1`: `POST /casemgmt/aggregates/access-tags/v1` | Case Templates:read |
| `falcon_aggregate_case_notification_groups` | read | `aggregates_notification_groups_post_v2`: `POST /casemgmt/aggregates/notification-groups/v2` | Case Templates:read |
| `falcon_aggregate_case_file_details` | read | `aggregates_file_details_post_v1`: `POST /case-files/aggregates/file-details/v1` | Cases:read |

### cloud: cloud_assets

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_cspm_assets` | read | `cloud_security_assets_entities_get`: `GET /cloud-security-assets/entities/resources/v1`<br>`cloud_security_assets_queries`: `GET /cloud-security-assets/queries/resources/v1` | Cloud Security API Assets:read |

### cloud: cloud_containers

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_kubernetes_containers` | read | `ReadContainerCombined`: `GET /container-security/combined/containers/v1` | Falcon Container Image:read |
| `falcon_count_kubernetes_containers` | read | `ReadContainerCount`: `GET /container-security/aggregates/containers/count/v1` | Falcon Container Image:read |
| `falcon_search_images_vulnerabilities` | read | `ReadCombinedVulnerabilities`: `GET /container-security/combined/vulnerabilities/v1` | Falcon Container Image:read |

### cloud: cloud_insights

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_cloud_insights` | read | `GetRule`: `GET /cloud-policies/entities/rules/v1`<br>`QueryRule`: `GET /cloud-policies/queries/rules/v1`<br>`cloud_security_assets_entities_get`: `GET /cloud-security-assets/entities/resources/v1`<br>`cloud_security_assets_queries`: `GET /cloud-security-assets/queries/resources/v1` | Cloud Security API Assets:read, Cloud Security Policies:read |
| `falcon_get_cloud_asset_insights` | read | `cloud_security_assets_entities_get`: `GET /cloud-security-assets/entities/resources/v1` | Cloud Security API Assets:read |
| `falcon_list_cloud_insight_definitions` | read | `GetRule`: `GET /cloud-policies/entities/rules/v1`<br>`QueryRule`: `GET /cloud-policies/queries/rules/v1` | Cloud Security Policies:read |

### cloud: cloud_iom

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_iom_findings` | read | `cspm_evaluations_iom_entities`: `GET /cloud-security-evaluations/entities/ioms/v1`<br>`cspm_evaluations_iom_queries`: `GET /cloud-security-evaluations/queries/ioms/v1` | Cloud Security API Detections:read |
| `falcon_search_cspm_suppression_rules` | read | `GetSuppressionRules`: `GET /cloud-policies/entities/suppression-rules/v1`<br>`QuerySuppressionRules`: `GET /cloud-policies/queries/suppression-rules/v1` | Cloud Security Policies:read |
| `falcon_create_cspm_suppression_rule` | **write, destructive** | `CreateSuppressionRule`: `POST /cloud-policies/entities/suppression-rules/v1`<br>`GetSuppressionRules`: `GET /cloud-policies/entities/suppression-rules/v1` | Cloud Security Policies:read, Cloud Security Policies:write |
| `falcon_delete_cspm_suppression_rules` | **write, destructive** | `DeleteSuppressionRules`: `DELETE /cloud-policies/entities/suppression-rules/v1` | Cloud Security Policies:write |

### cloud: cloud_risks

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_cloud_risks` | read | `combined_cloud_risks`: `GET /cloud-security-risks/combined/cloud-risks/v1` | Cloud Security API Risks:read |
| `falcon_search_cloud_groups` | read | `ListCloudGroupsExternal`: `GET /cloud-security/combined/cloud-groups/v1` | Cloud Groups V2:read |
| `falcon_get_cloud_groups` | read | `ListCloudGroupsByIDExternal`: `GET /cloud-security/entities/cloud-groups/v1` | Cloud Groups V2:read |

### correlation_rules

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_correlation_rules` | read | `combined_rules_get_v2`: `GET /correlation-rules/combined/rules/v2` | Correlation Rules:read |
| `falcon_create_correlation_rule` | **write** | `entities_rules_post_v1`: `POST /correlation-rules/entities/rules/v1` | Correlation Rules:write |
| `falcon_update_correlation_rule` | **write, destructive** | `entities_rules_patch_v1`: `PATCH /correlation-rules/entities/rules/v1` | Correlation Rules:write |
| `falcon_delete_correlation_rules` | **write, destructive** | `entities_rules_delete_v1`: `DELETE /correlation-rules/entities/rules/v1` | Correlation Rules:write |

### custom_ioa

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_ioa_rule_groups` | read | `query_rule_groups_full`: `GET /ioarules/queries/rule-groups-full/v1` | Custom IOA Rules:read |
| `falcon_get_ioa_platforms` | read | `get_platformsMixin0`: `GET /ioarules/entities/platforms/v1`<br>`query_platformsMixin0`: `GET /ioarules/queries/platforms/v1` | Custom IOA Rules:read |
| `falcon_get_ioa_rule_types` | read | `get_rule_types`: `GET /ioarules/entities/rule-types/v1`<br>`query_rule_types`: `GET /ioarules/queries/rule-types/v1` | Custom IOA Rules:read |
| `falcon_create_ioa_rule_group` | **write** | `create_rule_groupMixin0`: `POST /ioarules/entities/rule-groups/v1` | Custom IOA Rules:write |
| `falcon_update_ioa_rule_group` | **write, destructive** | `update_rule_groupMixin0`: `PATCH /ioarules/entities/rule-groups/v1` | Custom IOA Rules:write |
| `falcon_delete_ioa_rule_groups` | **write, destructive** | `delete_rule_groupsMixin0`: `DELETE /ioarules/entities/rule-groups/v1` | Custom IOA Rules:write |
| `falcon_create_ioa_rule` | **write** | `create_rule`: `POST /ioarules/entities/rules/v1` | Custom IOA Rules:write |
| `falcon_update_ioa_rule` | **write, destructive** | `update_rules_v2`: `PATCH /ioarules/entities/rules/v2` | Custom IOA Rules:write |
| `falcon_delete_ioa_rules` | **write, destructive** | `delete_rules`: `DELETE /ioarules/entities/rules/v1` | Custom IOA Rules:write |

### data_protection

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_data_protection_classifications` | read | `entities_classification_get_v2`: `GET /data-protection/entities/classifications/v2`<br>`queries_classification_get_v2`: `GET /data-protection/queries/classifications/v2` | Data Protection:read |
| `falcon_search_data_protection_policies` | read | `entities_policy_get_v2`: `GET /data-protection/entities/policies/v2`<br>`queries_policy_get_v2`: `GET /data-protection/queries/policies/v2` | Data Protection:read |
| `falcon_search_data_protection_content_patterns` | read | `entities_content_pattern_get`: `GET /data-protection/entities/content-patterns/v1`<br>`queries_content_pattern_get_v2`: `GET /data-protection/queries/content-patterns/v2` | Data Protection:read |

### detections

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_detections` | read | `GetQueriesAlertsV2`: `GET /alerts/queries/alerts/v2`<br>`PostEntitiesAlertsV2`: `POST /alerts/entities/alerts/v2` | Alerts:read |
| `falcon_get_detection_details` | read | `PostEntitiesAlertsV2`: `POST /alerts/entities/alerts/v2` | Alerts:read |
| `falcon_aggregate_detections` | read | `PostAggregatesAlertsV2`: `POST /alerts/aggregates/alerts/v2` | Alerts:read |
| `falcon_update_detections` | **write, destructive** | `PatchEntitiesAlertsV3`: `PATCH /alerts/entities/alerts/v3` | Alerts:write |

### discover

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_applications` | read | `combined_applications`: `GET /discover/combined/applications/v1` | Assets:read |
| `falcon_search_unmanaged_assets` | read | `combined_hosts`: `GET /discover/combined/hosts/v1` | Assets:read |
| `falcon_search_managed_assets` | read | `combined_hosts`: `GET /discover/combined/hosts/v1` | Assets:read |

### exclusions

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_exclusions` | read | per `exclusion_type` (ioa, ml, sensor_visibility, certificate): see Exclusions op table | see module |
| `falcon_create_exclusion` | **write, destructive** | per `exclusion_type` (ioa, ml, sensor_visibility, certificate): see Exclusions op table | see module |
| `falcon_update_exclusion` | **write, destructive** | per `exclusion_type` (ioa, ml, sensor_visibility, certificate): see Exclusions op table | see module |
| `falcon_delete_exclusions` | **write, destructive** | per `exclusion_type` (ioa, ml, sensor_visibility, certificate): see Exclusions op table | see module |
| `falcon_get_certificate_details` | read | `certificates_get_v1`: `GET /exclusions/entities/certificates/v1` | Machine Learning Exclusions:read |

### firewall

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_firewall_rules` | read | `get_rules`: `GET /fwmgr/entities/rules/v1`<br>`query_rules`: `GET /fwmgr/queries/rules/v1` | Firewall Management:read |
| `falcon_search_firewall_rule_groups` | read | `get_rule_groups`: `GET /fwmgr/entities/rule-groups/v1`<br>`query_rule_groups`: `GET /fwmgr/queries/rule-groups/v1` | Firewall Management:read |
| `falcon_search_firewall_policy_rules` | read | `get_rules`: `GET /fwmgr/entities/rules/v1`<br>`query_policy_rules`: `GET /fwmgr/queries/policy-rules/v1` | Firewall Management:read |
| `falcon_create_firewall_rule_group` | **write** | `create_rule_group`: `POST /fwmgr/entities/rule-groups/v1` | Firewall Management:write |
| `falcon_delete_firewall_rule_groups` | **write, destructive** | `delete_rule_groups`: `DELETE /fwmgr/entities/rule-groups/v1` | Firewall Management:write |

### fusion

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_workflow_definitions` | read | `WorkflowDefinitionsCombined`: `GET /workflows/combined/definitions/v1` | Workflows:read |
| `falcon_search_workflow_executions` | read | `WorkflowExecutionsCombined`: `GET /workflows/combined/executions/v1` | Workflows:read |
| `falcon_get_workflow_execution_results` | read | `WorkflowExecutionResults`: `GET /workflows/entities/execution-results/v1` | Workflows:read |
| `falcon_execute_workflow` | **write, destructive** | `WorkflowExecute`: `POST /workflows/entities/execute/v1` | Workflows:write |

### guardian

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_guardian_agents` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_agent` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_mcp_servers` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_agent_sessions` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_session_detail` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_session_activity` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_tools` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_tool_usage` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_executions` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_prompts` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_inventory` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_skills` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_skill_usage` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_fleet_skill_inventory` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_os_users` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_pivot_on_guardian_attribute` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_process_tree` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_network_events` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_file_events` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_classified_file_access` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_generate_guardian_report` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_detections` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_get_guardian_detection_scores` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_installs` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |
| `falcon_search_guardian_models` | read | raw `/aidr/{queries,entities,aggregates}/*` routes (op label `aidr_events_query`); see Guardian note | AIDR:read |

### host_groups

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_host_groups` | read | `queryCombinedHostGroups`: `GET /devices/combined/host-groups/v1` | Host Groups:read |
| `falcon_search_host_group_members` | read | `queryCombinedGroupMembers`: `GET /devices/combined/host-group-members/v1` | Host Groups:read |
| `falcon_create_host_group` | **write** | `createHostGroups`: `POST /devices/entities/host-groups/v1` | Host Groups:write |
| `falcon_update_host_group` | **write, destructive** | `updateHostGroups`: `PATCH /devices/entities/host-groups/v1` | Host Groups:write |
| `falcon_delete_host_groups` | **write, destructive** | `deleteHostGroups`: `DELETE /devices/entities/host-groups/v1` | Host Groups:write |
| `falcon_perform_host_group_action` | **write, destructive** | `performGroupAction`: `POST /devices/entities/host-group-actions/v1` | Host Groups:write |

### hosts

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_hosts` | read | `PostDeviceDetailsV2`: `POST /devices/entities/devices/v2`<br>`QueryDevicesByFilter`: `GET /devices/queries/devices/v1` | Hosts:read |
| `falcon_get_host_details` | read | `PostDeviceDetailsV2`: `POST /devices/entities/devices/v2` | Hosts:read |
| `falcon_manage_host_grouping_tags` | **write, destructive** | `UpdateDeviceTags`: `PATCH /devices/entities/devices/tags/v1` | Hosts:write |

### idp

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_idp_investigate_entity` | read | `api_preempt_proxy_post_graphql`: `POST /identity-protection/combined/graphql/v1` | Identity Protection Assessment:read, Identity Protection Detections:read, Identity Protection Entities:read, Identity Protection GraphQL:write, Identity Protection Timeline:read |

### intel

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_actors` | read | `QueryIntelActorEntities`: `GET /intel/combined/actors/v1` | Actors (Falcon Intelligence):read |
| `falcon_search_indicators` | read | `QueryIntelIndicatorEntities`: `GET /intel/combined/indicators/v1` | Indicators (Falcon Intelligence):read |
| `falcon_search_reports` | read | `QueryIntelReportEntities`: `GET /intel/combined/reports/v1` | Reports (Falcon Intelligence):read |
| `falcon_get_mitre_report` | read | `GetMitreReport`: `GET /intel/entities/mitre-reports/v1`<br>`QueryIntelActorEntities`: `GET /intel/combined/actors/v1` | Actors (Falcon Intelligence):read |

### ioc

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_iocs` | read | `indicator_get_v1`: `GET /iocs/entities/indicators/v1`<br>`indicator_search_v1`: `GET /iocs/queries/indicators/v1` | IOC Management:read |
| `falcon_add_ioc` | **write, destructive** | `indicator_create_v1`: `POST /iocs/entities/indicators/v1` | IOC Management:write |
| `falcon_remove_iocs` | **write, destructive** | `indicator_delete_v1`: `DELETE /iocs/entities/indicators/v1` | IOC Management:write |

### ngsiem

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_ngsiem` | read | `GetSearchStatusV1`: `GET /humio/api/v1/repositories/{repository}/queryjobs/{id}`<br>`StartSearchV1`: `POST /humio/api/v1/repositories/{repository}/queryjobs`<br>`StopSearchV1`: `DELETE /humio/api/v1/repositories/{repository}/queryjobs/{id}` | NGSIEM:read, NGSIEM:write |

### policies

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_policies` | read | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |
| `falcon_search_policy_members` | read | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |
| `falcon_create_policy` | **write** | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |
| `falcon_update_policy` | **write, destructive** | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |
| `falcon_delete_policies` | **write, destructive** | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |
| `falcon_perform_policy_action` | **write, destructive** | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |
| `falcon_set_policy_precedence` | **write, destructive** | per `policy_type` (prevention, sensor_update, firewall, device_control, response, content_update): see Policies op table | see module |

### quarantine

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_quarantined_files` | read | `GetQuarantineFiles`: `POST /quarantine/entities/quarantined-files/GET/v1`<br>`QueryQuarantineFiles`: `GET /quarantine/queries/quarantined-files/v1` | Quarantined Files:read |
| `falcon_preview_quarantine_actions` | read | `ActionUpdateCount`: `GET /quarantine/aggregates/action-update-count/v1` | Quarantined Files:read |
| `falcon_update_quarantined_files` | **write, destructive** | `UpdateQfByQuery`: `PATCH /quarantine/queries/quarantined-files/v1`<br>`UpdateQuarantinedDetectsByIds`: `PATCH /quarantine/entities/quarantined-files/v1` | Quarantined Files:write |
| `falcon_delete_quarantined_files` | **write, destructive** | `UpdateQfByQuery`: `PATCH /quarantine/queries/quarantined-files/v1`<br>`UpdateQuarantinedDetectsByIds`: `PATCH /quarantine/entities/quarantined-files/v1` | Quarantined Files:write |

### recon

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_recon_notifications` | read | `GetNotificationsDetailedV1`: `GET /recon/entities/notifications-detailed/v1`<br>`QueryNotificationsV1`: `GET /recon/queries/notifications/v1` | Monitoring rules (Falcon Intelligence Recon):read |
| `falcon_search_recon_rules` | read | `GetRulesV1`: `GET /recon/entities/rules/v1`<br>`QueryRulesV1`: `GET /recon/queries/rules/v1` | Monitoring rules (Falcon Intelligence Recon):read |
| `falcon_search_recon_exposed_data_records` | read | `GetNotificationsExposedDataRecordsV1`: `GET /recon/entities/notifications-exposed-data-records/v1`<br>`QueryNotificationsExposedDataRecordsV1`: `GET /recon/queries/notifications-exposed-data-records/v1` | Monitoring rules (Falcon Intelligence Recon):read |
| `falcon_aggregate_recon_notifications` | read | `AggregateNotificationsV1`: `POST /recon/aggregates/notifications/GET/v1` | Monitoring rules (Falcon Intelligence Recon):read |
| `falcon_aggregate_recon_exposed_data_records` | read | `AggregateNotificationsExposedDataRecordsV1`: `POST /recon/aggregates/notifications-exposed-data-records/GET/v1` | Monitoring rules (Falcon Intelligence Recon):read |
| `falcon_preview_recon_rule` | read | `PreviewRuleV1`: `POST /recon/aggregates/rules-preview/GET/v1` | Monitoring rules (Falcon Intelligence Recon):read |

### rtr

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_rtr_sessions` | read | `RTR_ListAllSessions`: `GET /real-time-response/queries/sessions/v1`<br>`RTR_ListSessions`: `POST /real-time-response/entities/sessions/GET/v1` | Real time response:read |
| `falcon_search_rtr_audit_sessions` | read | `RTRAuditSessions`: `GET /real-time-response-audit/combined/sessions/v1` | real-time-response-audit:read |
| `falcon_aggregate_rtr_sessions` | read | `RTR_AggregateSessions`: `POST /real-time-response/aggregates/sessions/GET/v1` | Real time response:read |
| `falcon_get_rtr_session_details` | read | `RTR_ListSessions`: `POST /real-time-response/entities/sessions/GET/v1` | Real time response:read |
| `falcon_init_rtr_session` | **write** | `RTR_InitSession`: `POST /real-time-response/entities/sessions/v1` | Real time response:read |
| `falcon_pulse_rtr_session` | **write** | `RTR_PulseSession`: `POST /real-time-response/entities/refresh-session/v1` | Real time response:read |
| `falcon_execute_rtr_read_only_command` | **write** | `RTR_ExecuteCommand`: `POST /real-time-response/entities/command/v1` | Real time response:read |
| `falcon_run_rtr_read_only_command_and_wait` | **write** | `RTR_CheckCommandStatus`: `GET /real-time-response/entities/command/v1`<br>`RTR_ExecuteCommand`: `POST /real-time-response/entities/command/v1` | Real time response:read |
| `falcon_check_rtr_command_status` | read | `RTR_CheckCommandStatus`: `GET /real-time-response/entities/command/v1` | Real time response:read |
| `falcon_list_rtr_session_files` | read | `RTR_ListFilesV2`: `GET /real-time-response/entities/file/v2` | Real time response:write |
| `falcon_delete_rtr_session` | **write, destructive** | `RTR_DeleteSession`: `DELETE /real-time-response/entities/sessions/v1` | Real time response:read |

### scheduled_reports

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_scheduled_reports` | read | `scheduled_reports_get`: `GET /reports/entities/scheduled-reports/v1`<br>`scheduled_reports_query`: `GET /reports/queries/scheduled-reports/v1` | Scheduled Reports:read |
| `falcon_launch_scheduled_report` | **write** | `scheduled_reports_launch`: `POST /reports/entities/scheduled-reports/execution/v1` | Scheduled Reports:read |
| `falcon_search_report_executions` | read | `report_executions_get`: `GET /reports/entities/report-executions/v1`<br>`report_executions_query`: `GET /reports/queries/report-executions/v1` | Scheduled Reports:read |
| `falcon_download_report_execution` | read | `report_executions_download_get`: `GET /reports/entities/report-executions-download/v1` | Scheduled Reports:read |

### sensor_usage

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_sensor_usage` | read | `GetSensorUsageWeekly`: `GET /billing-dashboards-usage/aggregates/weekly-average/v1` | Sensor Usage:read |

### serverless

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_serverless_vulnerabilities` | read | `GetCombinedVulnerabilitiesSARIF`: `GET /lambdas/combined/vulnerabilities/sarif/v1` | Falcon Container Image:read |

### shield

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_shield_checks` | read | `GetSecurityChecksV3`: `GET /saas-security/entities/checks/v3` | SaaS Security:read |
| `falcon_get_shield_check_affected_entities` | read | `GetSecurityCheckAffectedV3`: `GET /saas-security/entities/check-affected/v3` | SaaS Security:read |
| `falcon_get_shield_posture_metrics` | read | `GetMetricsV3`: `GET /saas-security/aggregates/check-metrics/v3` | SaaS Security:read |
| `falcon_get_shield_check_compliance` | read | `GetSecurityCheckComplianceV3`: `GET /saas-security/entities/compliance/v3` | SaaS Security:read |
| `falcon_search_shield_alerts` | read | `GetAlertsV3`: `GET /saas-security/entities/alerts/v3` | SaaS Security:read |
| `falcon_get_shield_activity_monitor` | read | `GetActivityMonitorV3`: `GET /saas-security/entities/monitor/v3` | SaaS Security:read |
| `falcon_search_shield_users` | read | `GetUserInventoryV3`: `GET /saas-security/entities/users/v3` | SaaS Security:read |
| `falcon_search_shield_devices` | read | `GetDeviceInventoryV3`: `GET /saas-security/entities/devices/v3` | SaaS Security:read |
| `falcon_search_shield_apps` | read | `GetAppInventory`: `GET /saas-security/entities/apps/v3` | SaaS Security:read |
| `falcon_get_shield_app_users` | read | `GetAppInventoryUsers`: `GET /saas-security/entities/app-users/v3` | SaaS Security:read |
| `falcon_search_shield_data_shares` | read | `GetAssetInventoryV3`: `GET /saas-security/entities/data/v3` | SaaS Security:read |
| `falcon_get_shield_integrations` | read | `GetIntegrationsV3`: `GET /saas-security/entities/integrations/v3` | SaaS Security:read |
| `falcon_get_shield_system_users` | read | `GetSystemUsersV3`: `GET /saas-security/entities/system-users/v3` | SaaS Security:read |
| `falcon_get_shield_supported_saas` | read | `GetSupportedSaasV3`: `GET /saas-security/entities/supported-saas/v3` | SaaS Security:read |
| `falcon_get_shield_system_logs` | read | `GetSystemLogsV3`: `GET /saas-security/entities/system-logs/v3` | SaaS Security:read |
| `falcon_dismiss_shield_check` | **write, destructive** | `DismissAffectedEntityV3`: `POST /saas-security/entities/check-dismiss-affected/v3`<br>`DismissSecurityCheckV3`: `POST /saas-security/entities/check-dismiss/v3` | SaaS Security:write |

### spotlight

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_vulnerabilities` | read | `combinedQueryVulnerabilities`: `GET /spotlight/combined/vulnerabilities/v1` | Vulnerabilities:read |

### zero_trust_assessment

| Tool | Kind | Operations (FalconPy op ID: HTTP route) | Scopes |
|---|---|---|---|
| `falcon_search_zta_assessments` | read | `getAssessmentV1`: `GET /zero-trust-assessment/entities/assessments/v1`<br>`getAssessmentsByScoreV1`: `GET /zero-trust-assessment/queries/assessments/v1` | Zero Trust Assessment:read |
| `falcon_get_zta_assessments` | read | `getAssessmentV1`: `GET /zero-trust-assessment/entities/assessments/v1` | Zero Trust Assessment:read |
| `falcon_get_zta_audit` | read | `getAuditV1`: `GET /zero-trust-assessment/entities/audit/v1` | Zero Trust Assessment:read |


## MCP resources (54)

| Module | URI |
|---|---|
| agentworks | `falcon://agentworks/agents/fql-guide` |
| agentworks | `falcon://agentworks/agent-versions/fql-guide` |
| agentworks | `falcon://agentworks/spans/fql-guide` |
| cases | `falcon://cases/search/fql-guide` |
| cases | `falcon://cases/aggregates/fql-guide` |
| cases | `falcon://cases/file-aggregates/fql-guide` |
| cloud: cloud_assets | `falcon://cloud/cspm-assets/fql-guide` |
| cloud: cloud_containers | `falcon://cloud/kubernetes-containers/fql-guide` |
| cloud: cloud_containers | `falcon://cloud/images-vulnerabilities/fql-guide` |
| cloud: cloud_insights | `falcon://cloud/cloud-insights/fql-guide` |
| cloud: cloud_iom | `falcon://cloud/cspm-iom-findings/fql-guide` |
| cloud: cloud_risks | `falcon://cloud/cloud-risks/fql-guide` |
| correlation_rules | `falcon://correlation-rules/search/fql-guide` |
| custom_ioa | `falcon://custom-ioa/rule-groups/fql-guide` |
| data_protection | `falcon://data-protection/classifications/fql-guide` |
| data_protection | `falcon://data-protection/policies/fql-guide` |
| data_protection | `falcon://data-protection/content-patterns/fql-guide` |
| detections | `falcon://detections/search/fql-guide` |
| discover | `falcon://discover/applications/fql-guide` |
| discover | `falcon://discover/hosts/fql-guide` |
| discover | `falcon://discover/managed-assets/fql-guide` |
| exclusions | `falcon://exclusions/search/fql-guide` |
| firewall | `falcon://firewall/rules/fql-guide` |
| fusion | `falcon://fusion/workflow-definitions/fql-guide` |
| fusion | `falcon://fusion/workflow-executions/fql-guide` |
| guardian | `falcon://guardian/events/query-guide` |
| guardian | `falcon://guardian/entities/schema-guide` |
| guardian | `falcon://guardian/inventory/schema-guide` |
| guardian | `falcon://guardian/events/examples-guide` |
| host_groups | `falcon://host-groups/search/fql-guide` |
| hosts | `falcon://hosts/search/fql-guide` |
| intel | `falcon://intel/actors/fql-guide` |
| intel | `falcon://intel/indicators/fql-guide` |
| intel | `falcon://intel/reports/fql-guide` |
| ioc | `falcon://ioc/search/fql-guide` |
| ngsiem | `falcon://ngsiem/search/cql-guide` |
| policies | `falcon://policies/search/fql-guide` |
| quarantine | `falcon://quarantine/files/search/fql-guide` |
| recon | `falcon://recon/notifications/search/fql-guide` |
| recon | `falcon://recon/rules/search/fql-guide` |
| recon | `falcon://recon/exposed-data-records/search/fql-guide` |
| recon | `falcon://recon/notifications/aggregate-guide` |
| recon | `falcon://recon/exposed-data-records/aggregate-guide` |
| recon | `falcon://recon/rules/preview-guide` |
| rtr | `falcon://rtr/sessions/search/fql-guide` |
| rtr | `falcon://rtr/audit/sessions/search/fql-guide` |
| rtr | `falcon://rtr/sessions/aggregate-guide` |
| rtr | `falcon://rtr/workflows/investigation-guide` |
| scheduled_reports | `falcon://scheduled-reports/search/fql-guide` |
| scheduled_reports | `falcon://scheduled-reports/executions/search/fql-guide` |
| sensor_usage | `falcon://sensor-usage/weekly/fql-guide` |
| serverless | `falcon://serverless/vulnerabilities/fql-guide` |
| shield | `falcon://shield/search/query-guide` |
| spotlight | `falcon://spotlight/vulnerabilities/fql-guide` |
