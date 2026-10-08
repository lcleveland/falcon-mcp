# Falcon API write endpoints and their blast radius

Research for #4 (part of #1, blocks #9). Researched 2026-10-08.

## Sources

- **[S1] FalconPy endpoint modules**, https://github.com/CrowdStrike/falconpy/tree/main/src/falconpy/_endpoint at `06a5df8` (2026-09-24). These modules are generated from CrowdStrike's swagger. They give each operation's id, method, path, description, query parameters, `enum`s and `maxItems`. This is the main source for the inventory.
- **[S2] FalconPy service classes** (`src/falconpy/hosts.py`, `alerts.py`, ...), same commit. The docstrings list the action-parameter names that the swagger body hides (alert `append_comment`, host action `note`, and so on).
- **[S3] gofalcon generated client and models**, https://github.com/CrowdStrike/gofalcon at `9e66b54` (2026-10-02), `falcon/client/*/*_parameters.go` and `falcon/models/*.go`. Used for request-body field names (for example, which bodies have a `comment` field). gofalcon generates `Validate()` from swagger, and none of the write bodies below carries a `MaxItems` constraint. **The swagger does not state body batch limits.**
- **[S4] Official CrowdStrike/falcon-mcp**, https://github.com/CrowdStrike/falcon-mcp at `82d5031` (2026-10-06), `docs/modules/*.md` (scopes for each tool) and `falcon_mcp/modules/*.py`. This repo gives the API scope names. It also records limits CrowdStrike's own team found in practice, for example the alert PATCH 413 above 1000 ids and the tag limits.
- The public swagger at `assets.falcon.crowdstrike.com/support/api/swagger.json` returns 403 without a console session, so it was not read directly.

Claims marked **(inference)** are my own reasoning and are not documented. Check them against a test CID.

## Key findings

1. **Scopes are fine-grained, unlike NinjaOne's.** Each service collection has its own `<Name>:read` and `<Name>:write` [S4]. Examples: `Hosts:write` (containment and tags), `Alerts:write`, `IOC Management:write`, one scope for each exclusion type, one scope for each policy type, and `Real time response:write`. So the API client's scopes are already a real least-privilege gate. Even so, **one scope often covers more than one risk class.** `Hosts:write` covers adding a tag, network containment, hiding a host and *permanent host deletion*. `IOC Management:write` covers both adding a block and adding an `allow`. The capability flags still have to split these.
2. **Read-only RTR needs no write scope.** The official server opens sessions and runs read-only commands (`ls`, `ps`, `cat`, `filehash`, `reg`) with only `Real time response:read` [S4 rtr.md]. These commands still execute on the live endpoint and can read any file, so read-only RTR should be its own opt-in capability, not part of the read-only default (inference).
3. **No operation takes an idempotency key** [S1]: no write operation has such a parameter. Retrying a POST that timed out may apply it twice. This matches the sibling rule "never auto-retry". Writes that set state (status, assignment, containment, enable/disable, `UpdateDeviceTags`) converge (inference). Writes that append (`append_comment`, IOC create, put-file or script upload, RTR commands) do not. [S4] chunks alert updates and reports `partial_success` "rather than re-applying non-idempotent actions".
4. **Several deletes and actions can select by FQL filter instead of by ids.** This makes them unbounded fleet-wide operations: `DevicesActionsDeleteV1` (`MsaEntityActionRequestV3` has `filter`) [S3], `indicator_delete_v1` (`filter` query param) [S1], `indicator_update_v1` (`bulk_update.filter`, which can change `action` on every matching IOC) [S3 APIBulkUpdateReqV1], and quarantine `PATCH /quarantine/queries/quarantined-files/v1` ("Apply quarantine file actions by query") [S1]. A server that wants a ceiling on batch size must refuse `filter` on these or resolve it to ids and count them first. (Policy and host-group actions take ids only.)
5. **About half the write paths take an audit `comment`, and the other half do not.** The table below records which. Where the API has no comment field, the server's `reason` exists only in its own audit log.
6. **The legacy write APIs are gone.** Incidents `PerformIncidentAction` is marked "DECOMMISSIONED ... removed in March 2026" [S1]. The legacy `/detects` PATCH has been replaced by `PatchEntitiesAlertsV3` (v1 and v2 are deprecated) [S1]. Cases (`/cases/entities/cases/v2`) take over the incident workflow [S4].
7. **Batch limits are mostly undocumented.** The documented ones: RTR batch session "maximum of 10000 hosts" [S1 BatchInitSessions]. Alerts PATCH rejects more than 1000 composite ids with HTTP 413 [S4 detections.py:537]. `UpdateDeviceTags` accepts at most 5000 device ids and 50 tags, and "fails the whole call above that" [S4 hosts.py:31-32]. Every other id list in a query string is bounded only by URL length ("The max number of IDs is constrained by URL size" [S1 custom_ioa get_rules]).

## Endpoint inventory

Columns: **Comment** = whether the API itself accepts an audit comment or reason, and where. **Idem.** = idempotency (inference unless cited). **Batch** = per-call limit (see finding 7, "n/s" = not stated in spec).

### Alerts, cases, host annotations

| Endpoint | What it does | Scope | Comment | Idem. | Batch |
|---|---|---|---|---|---|
| `PATCH /alerts/entities/alerts/v3` (`composite_ids`, `action_parameters[{name,value}]`) | Actions `update_status` (new/in_progress/reopened/closed), `assign_to_uuid`, `assign_to_user_id`, `assign_to_name`, `unassign`, `append_comment`, `add_tag`, `remove_tag`, `remove_tags_by_prefix`, `show_in_ui`, `new_behavior_processed` [S2 alerts.py:444]. Resolution is tag-based (`true_positive`/`false_positive`/`ignored`) [S4] | `Alerts:write` | Yes, `append_comment` is itself an action | Status, assignment and tags converge. `append_comment` does not | 1000 ids (413 above) [S4] |
| `PUT /cases/entities/cases/v2` (create), `PATCH .../cases/v2` (update), `POST /cases/entities/alert-evidence/v1`, `.../event-evidence/v1`, `POST/DELETE /cases/entities/case-tags/v1`, `POST /cases/entities/merge/v1` | Case lifecycle [S1] | `Cases:write` [S4] | Update and fields are freeform. No separate audit comment | Create and merge: no. Tags: yes | n/s |
| `PATCH /devices/entities/devices/tags/v1` (`action` add\|remove, `device_ids`, `tags`) | Falcon Grouping Tags (`FalconGroupingTags/...`) [S1][S3] | `Hosts:write` | **No** | Yes | 5000 ids, 50 tags [S4] |

Tags are not cosmetic. Dynamic host groups can match on tags, and policies are assigned to host groups, so a tag write can change which prevention or sensor-update policy a host gets (inference from the `assignment_rule` field on host groups [S3]).

### Host actions

| Endpoint | What it does | Scope | Comment | Idem. | Batch |
|---|---|---|---|---|---|
| `POST /devices/entities/devices-actions/v2?action_name=contain\|lift_containment` | Network containment. The host can talk only to the CrowdStrike cloud and the containment-policy allow-list [S3 perform_action_v2_parameters.go] | `Hosts:write` [S4] | Yes, `action_parameters` `note` ("a custom note that is attached to the action") [S2 hosts.py:520] | Converges | n/s |
| same, `hide_host` / `unhide_host` | "will delete a host ... no new detections for that host will be reported" / restore [S3] | `Hosts:write` | `note` | Converges | n/s |
| same, `detection_suppress` / `detection_unsuppress` | Suppress detections from the host [S2] | `Hosts:write` | `note` | Converges | n/s |
| `POST /devices/entities/devices-actions-delete/v1` (`ids` **or `filter`**) | "Permanently delete hosts from the system" [S1] | `Hosts:write` (inference) | No | n/a, cannot be undone | Unbounded through `filter` |

### Host groups

| Endpoint | Scope | Comment | Idem. |
|---|---|---|---|
| `POST/PATCH/DELETE /devices/entities/host-groups/v1` (`name`, `group_type`, `assignment_rule` FQL) | `Host Groups:write` [S4] | No [S3] | Create: no. Update and delete: yes |
| `POST /devices/entities/host-group-actions/v1?action_name=add-hosts\|remove-hosts` (`disable_hostname_check`) | `Host Groups:write` | No | Yes |
| `POST /devices/entities/group-actions/v1?action_name=add_group_member\|remove_group_member\|remove_all` | `Hosts:write` (inference) | No | Yes |

Membership drives policy assignment, so **these are policy-scope changes in practice** (inference). Editing `assignment_rule` on a dynamic group can move thousands of hosts at once.

### Detection content: IOCs, custom IOA, exclusions

| Endpoint | Scope | Comment | Idem. |
|---|---|---|---|
| `POST /iocs/entities/indicators/v1` (`retrodetects`, `ignore_warnings`). Body `{comment, indicators[{type,value,action,severity,platforms,host_groups,applied_globally,expiration,...}]}` | `IOC Management:write` | **Yes**, body `comment` [S3 APIIndicatorCreateReqsV1] | No (a duplicate value raises a warning or error, inference) |
| `PATCH /iocs/entities/indicators/v1` (body has `bulk_update` with a filter) | `IOC Management:write` | **Yes**, body `comment` [S3] | Yes. `bulk_update` is filter-wide |
| `DELETE /iocs/entities/indicators/v1` (`ids` **or `filter`**) | `IOC Management:write` | **Yes**, `comment` query [S1] | Yes |
| Custom IOA: `POST/PATCH/DELETE /ioarules/entities/rule-groups/v1`, `POST /ioarules/entities/rules/v1`, `PATCH .../rules/v1` (full group state) and `/v2` (subset) | `Custom IOA Rules:write` [S4] | **Yes**, body `comment` on create and modify, `comment` query on delete [S1][S3]. The group PATCH needs `rulegroup_version` (optimistic concurrency) | Create: no. Modify: yes, version-checked |
| ML exclusions `POST/PATCH/DELETE /policy/entities/ml-exclusions/v1` and `/exclusions/entities/exclusions/v2` (+ `exclusion-actions/v2` add_item, remove_item) | `Machine Learning Exclusions:write` | **Yes**, body `comment` and `comment` query on delete | Create: no |
| Sensor visibility `POST/PATCH/DELETE /policy/entities/sv-exclusions/v1` | `Sensor Visibility Exclusions:write` | **Yes** | Create: no |
| IOA exclusions `POST/PATCH/DELETE /policy/entities/ioa-exclusions/v1`, self-service `/exclusions/entities/ss-ioa-exclusions/v2` | `IOA Exclusions:write` | **Yes** | Create: no |
| Certificate-based `POST/PATCH/DELETE /exclusions/entities/cert-based-exclusions/v1` | (official module groups it with exclusions. Exact scope not listed in [S4]) | `comment` on delete only [S1] | Create: no |

The IOC `action` value decides which side a write is on. `prevent`/`detect` add protection. `allow`/`no_action` remove it. Every exclusion type removes protection, and a sensor-visibility exclusion hides activity from the sensor entirely.

### Policies (prevention, sensor update, response, device control, firewall, content update)

The same shape for each type [S1]: `POST/PATCH/DELETE /policy/entities/<type>/v1`, `POST /policy/entities/<type>-actions/v1?action_name=enable|disable|add-host-group|remove-host-group|add-rule-group|remove-rule-group`, `POST /policy/entities/<type>-precedence/v1` ("You must specify all non-Default Policies", which makes it a full replace). The content update policy actions also take `override-allow|override-pause|override-revert|set-pinned-content-version|remove-pinned-content-version`. Sensor update v2 adds uninstall-protection settings. Device control has `default-device-control` and `-default-settings` PATCHes. Firewall also has `/fwmgr/entities/rule-groups/v1` and `network-locations` (these take a **`comment` query**) and `PUT /fwmgr/entities/policies/v2` (policy container).

- **Scope:** `<Type> Policies:write`, or `Firewall Management:write` [S4].
- **Comment:** none on the policy entities or actions [S1][S3]. Firewall rule groups and network locations have one.
- **Idempotency:** update, enable/disable and precedence converge. Create does not.
- **Batch:** n/s.
- Deleting or editing a policy applies to every host in its groups at the next check-in (inference). Turning off sensor-update uninstall protection, or setting prevention settings to off, weakens the whole fleet.

### Quarantine

`PATCH /quarantine/entities/quarantined-files/v1` (ids) and `PATCH /quarantine/queries/quarantined-files/v1` (**filter**), body `{action: release|unrelease|delete, comment, ids}` [S1][S3 DomainEntitiesPatchRequest]. Scope `Quarantined Files:write`. Accepts a **comment**. Release puts a quarantined (likely malicious) file back on disk. [S4] has a read-only `preview_quarantine_actions` that returns counts before a filter-based action. That is a pattern worth copying for every filter-capable write.

### Real Time Response

| Endpoint | Scope | Comment | Notes |
|---|---|---|---|
| `POST /real-time-response/entities/sessions/v1` (`device_id`, `queue_offline`), `refresh-session`, `DELETE sessions` | `Real time response:read` [S4] | No (`origin` field only) | Sessions expire after 10 minutes unless refreshed [S1] |
| `POST .../entities/command/v1` (read-only command tier) | `Real time response:read` [S4] | No | Single host |
| `POST .../entities/active-responder-command/v1` | `Real time response:write` | No | Single host. Changes the host (file get, kill, rm, registry and so on) |
| `POST .../entities/admin-command/v1` | RTR Admin write scope (the "Real Time Response Admin" collection [S1]. Exact scope string not in the sources read) | No | Single host. Arbitrary script or exe execution (`runscript`, `run`) |
| `POST .../combined/batch-init-session/v1`, `batch-command`, `batch-active-responder-command`, `batch-admin-command`, `batch-get-command` | Same tiers as above | No | **Up to 10000 hosts** per batch [S1]. Timeout up to 5 minutes |
| `POST/DELETE .../put-files/v1,v2`, `POST/PATCH/DELETE .../scripts/v1,v2` | RTR Admin write | **Yes**, `comments_for_audit_log` form field [S1] | Changes the tenant script library |
| `DELETE .../queued-sessions/command/v1`, `DELETE .../file/v2` | `Real time response:write` (inference) | No | Housekeeping |

Retrying an RTR command runs it again: commands have no dedupe key. Mapping RTR commands to capabilities is a separate open question on #1.

### Other writes in the official server's modules

From [S4]: `falcon_execute_workflow` (`Workflows:write`: runs an on-demand Fusion workflow, whose blast radius is whatever the workflow does, possibly containment). Correlation rules CRUD (`Correlation Rules:write`). CSPM suppression rules (`Cloud Security Policies:write`). Shield `dismiss_shield_check` (`SaaS Security:write`). AgentWorks agent invoke. Firewall rule groups. Two modules ask for a `:write` scope only to run reads: NGSIEM search jobs (`NGSIEM:write`) and the IDP GraphQL investigate tool (`Identity Protection GraphQL:write`). Treat those two as reads in the capability map, even though the API client must hold a write scope.

The official hosts module **does not expose containment** (only grouping tags) [S4 hosts.md], and its RTR module is read-only commands only [S4 rtr.md].

## Candidate risk clusters

A proposal only. The capability map itself is #9's decision.

| Cluster | Members | Why grouped | Reversible? |
|---|---|---|---|
| **1. Triage notes** | Alert status, assignment, comment, tags, show_in_ui. Case create, update, tags, evidence, merge | SOC bookkeeping. Nothing changes on an endpoint or in protection | Yes (except comments and merge) |
| **2. Host labels** | Grouping tags | Low on its face, but can move hosts between dynamic groups and so change their policies | Yes |
| **3. Containment** | contain, lift_containment | Instant per-host network cut. The classic IR action. Bounded by ids | Yes |
| **4. Detection add** | IOC create/update with `prevent`/`detect`, custom IOA rule create/enable | Adds blocking. A bad global IOC (for example a common hash or domain) can break business apps across the fleet | Yes |
| **5. Detection remove** | All exclusion types, IOC `allow`/`no_action`, IOC/IOA delete or disable, alert `detection_suppress`, quarantine release | Lowers protection silently. This is where an attacker with the agent would aim | Yes, but harm happens before it is noticed |
| **6. Fleet configuration** | Host group CRUD and membership, all policy CRUD, actions and precedence, firewall rule groups, content-update pinning, sensor update incl. uninstall protection | Tenant-wide. Changes apply at check-in to every member host | Mostly, but needs the prior state captured |
| **7. RTR read** | Session init and read-only commands | Read scope, but runs on the endpoint and can read any file | n/a |
| **8. RTR respond** | Active-responder commands (single and batch) | Changes the host | Often no |
| **9. RTR admin** | Admin commands, script and put-file library | Arbitrary code as SYSTEM or root, up to 10k hosts per batch | No |
| **10. Destructive lifecycle** | `DevicesActionsDeleteV1` (filter-capable), hide_host, quarantine delete | Cannot be undone, or removes visibility | No (hide: yes) |
| **11. Workflow execute** | Fusion on-demand workflows | Opaque. Inherits the blast radius of the workflow | Depends |

Suggestions for #9:
- Refuse `filter` selectors on writes, or resolve and count them first (finding 4).
- Cap batches below the API ceilings (1000 alerts, 5000 tag ids, 10000 RTR hosts).
- Where the API has a comment field, send the MCP `reason` in it (alerts `append_comment` optional, IOC, IOA, exclusions, quarantine, firewall, RTR uploads, containment `note`), so the Falcon console's audit trail matches the server log.

## Open questions (need a test CID)

- Exact behaviour of contain or lift on a host already in that state (error or no-op).
- How large an id list in a body `PerformActionV2`, `performGroupAction` and the policy actions accept before rejecting it.
- The RTR admin scope string, and the cert-based exclusion scope string, as shown in the API client UI.
- Whether `DevicesActionsDeleteV1` needs `Hosts:write` or a separate scope.
