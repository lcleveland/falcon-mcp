# Falcon "MCP clients" registration

Research for [What is Falcon's MCP clients registration](https://github.com/lcleveland/falcon-mcp/issues/11). Researched 2026-10-08.

The question: the Falcon console's Client Management page (Support and resources → Resources and tools) now has an **MCP clients** tab next to **API clients**, with a banner saying you can now register MCP clients alongside API clients. What is it, and does it change how falcon-mcp authenticates?

Sources (pinned):

- **Official MCP** `CrowdStrike/falcon-mcp` @ `ece8575` (2026-10-08): `docs/modules/overview.md` § "CrowdStrike-hosted MCP differences", `scripts/generate_module_docs.py` (`HOSTED_MCP_MODULE_NOTES`, `HOSTED_MCP_TOOL_NOTES`)
- **FalconPy** `CrowdStrike/falconpy` @ `06a5df8` (2026-09-24): `src/falconpy/_endpoint/_oauth2.py`, `_api_clients.py`
- **Press release** [CrowdStrike Unveils the Next Evolution of the Agentic SOC](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-unveils-next-evolution-of-the-agentic-soc/) (2026-09-02)
- **Dev docs** [falcon-mcp changelog](https://developer.crowdstrike.com/falcon-mcp/changelog/) (0.1.0 to 0.19.0)

Labels: **[src]** means read in a first-party source. **[inferred]** means a conclusion from those sources that no source states. **[unverified]** needs someone with console access to confirm.

**Public documentation is thin.** CrowdStrike's console help (support portal) is behind login, and nothing public describes the MCP clients tab, its form fields, its auth flow or its scopes. The findings below are what can be pinned down from public first-party material.

## TL;DR

1. **CrowdStrike runs a hosted Falcon MCP server.** [src] It is separate from the open-source falcon-mcp and is discovery-shaped: clients call `search_tools`, then `execute_tool`. Its tool coverage differs from the open-source server (no Fusion SOAR, Zero Trust Assessment or RTR; policy tools split per type).
2. **The MCP clients tab is almost certainly where you register third-party MCP clients (Claude, IDEs, custom agents) to connect *to* that hosted server.** [inferred] The September 2026 press release describes "bidirectional MCP" that "connects any third-party agent into Falcon". No public source names the tab or describes it.
3. **It adds nothing to the public API.** [src] FalconPy main has only `/oauth2/token` (client credentials) and `/oauth2/revoke`, and the `/api-clients/*` routes have no client-type or MCP field. Nothing in the public API spec manages or uses "MCP clients".
4. **No change for our server.** falcon-mcp stays an OAuth2 client-credentials **API client**. We should not accept MCP-client credentials, and we should say in the README which tab to use.

## What is confirmed

### A CrowdStrike-hosted Falcon MCP exists [src]

The official repo's module overview has a section "CrowdStrike-hosted MCP differences" (`docs/modules/overview.md` L40-54 @ `ece8575`):

> The hosted Falcon MCP works through discovery: a client calls `search_tools` to find a Falcon tool by name or keyword, then `execute_tool` to run it with arguments. The self-hosted falcon-mcp server registers each `falcon_*` tool up front instead.

Coverage differences it lists:

- Fusion SOAR, Zero Trust Assessment and Real Time Response exist only on the self-hosted server.
- Cloud Security: `falcon_search_cloud_insights`, `falcon_list_cloud_insight_definitions` and `falcon_get_cloud_asset_insights` are not on the hosted MCP.
- Discover: `falcon_search_managed_assets` is not on the hosted MCP.
- Policies: the hosted MCP has six per-policy-type variants of each tool (for example `falcon_search_policies_firewall`) instead of the unified `policy_type` tools.

These notes are kept in `scripts/generate_module_docs.py` and enforced by `tests/test_generate_module_docs.py::TestHostedMcpNotes`, so CrowdStrike treats the hosted MCP as a maintained product whose tool names track the open-source server.

Neither the repo nor developer.crowdstrike.com publishes the hosted server's endpoint URL or its auth model. The falcon-mcp changelog (0.1.0 to 0.19.0) has no entry about the hosted MCP, OAuth for MCP clients, or client registration.

### "Bidirectional MCP" [src]

The press release of 2026-09-02 contains a single MCP sentence, under Charlotte Agentic SOAR:

> Bidirectional MCP connects any third-party agent into Falcon and any CrowdStrike agent – custom or Agentic Security Workforce – out to external tools

There are no technical details, scopes or dates.

### The public API has no MCP-client surface [src]

- `_oauth2.py` has only `/oauth2/token` (form `client_id`, `client_secret`, optional `member_cid`) and `/oauth2/revoke`. There is no authorization-code endpoint, no `/authorize`, no dynamic client registration endpoint and no `grant_type` parameter.
- `_api_clients.py` (`/api-clients/entities/api-clients/v1`, `/api-clients/queries/api-clients/v1`, `api-clients-actions`, `accessible-scopes`) has no client-type field and nothing that mentions MCP.
- The only `mcp` hits in FalconPy's endpoint tables are telemetry fields (`_threatgraph.py` `mcp_server`, `mcp_tool_call`; `_discover.py` application category `mcp`) and the AIDR `/aidr/*` routes, which *observe* MCP use on endpoints. None of these registers anything.

## What is inferred

- **What the tab is for.** [inferred] Registering third-party MCP clients that connect to the hosted Falcon MCP, the "into Falcon" half of bidirectional MCP. The name fits (it registers *clients*, not servers), and a remote, CrowdStrike-hosted MCP server needs a way to admit and scope outside clients. The "out to external tools" half would more naturally be a place to register external MCP *servers*, so the tab is unlikely to be that.
- **Auth model.** [unverified] The MCP authorization spec for remote servers is OAuth 2.1 with authorization-code + PKCE, optionally with dynamic client registration. A tab for registering clients by hand suggests pre-registered OAuth clients (client ID, maybe a redirect URI, maybe a secret) rather than open dynamic registration, but nothing public confirms which flow, which scopes, or whether the hosted MCP acts as the signed-in user (user RBAC) or as the client (API scopes).
- **Not Charlotte AI or AgentWorks or AIDR specifically.** [inferred] AgentWorks (`/agentic-studio/*`) and AIDR (`/aidr/*`) are ordinary API-scoped services already covered by API clients. The MCP clients tab is about who may connect over MCP, not about those modules, although Charlotte agents may well be reachable through the hosted MCP.

## Open questions for someone with console access

These are generic product behaviours, so the answers can go in this file. Anything tenant-specific (IDs, URLs that name a cloud, licences) goes in `~/.config/falcon-mcp/tenant-notes.md` instead.

1. What does the "Add MCP client" form ask for: name, redirect URI, scopes, a secret?
2. Does it show the hosted MCP endpoint URL, and does that URL depend on the cloud?
3. Does an MCP-client credential work at `POST /oauth2/token` with client credentials? (Expected: no.)
4. Does the hosted MCP act with the signed-in user's RBAC role, or with scopes picked on the MCP client?

## Implications for falcon-mcp

- **Authentication does not change.** falcon-mcp calls the public REST API with an **API client** (OAuth2 client credentials, `/oauth2/token`, optional `member_cid`), as in [falcon-auth-and-scopes.md](falcon-auth-and-scopes.md). Do not accept MCP-client credentials. Their flow is undocumented and they are probably not valid for client credentials at all.
- **Nothing to support.** There are no per-client tokens or MCP-client scopes in the public API for our server to use. If the operator wants per-user or per-client scoping, our capability flags on top of Falcon scopes ([ADR 0002](../adr/0002-capability-flags-over-falcon-scopes.md)) and separate API clients per deployment already give that.
- **Document it.** One line in the README's setup section: "Create an **API client** (Client Management → API clients), not an MCP client. The MCP clients tab is for connecting MCP clients to CrowdStrike's hosted Falcon MCP." Optionally add a short "hosted vs self-hosted" note: the hosted MCP needs no deployment but uses discovery (`search_tools`/`execute_tool`) and has a different tool set, while falcon-mcp runs on your own infrastructure with your own capability flags.
- **For the v1 spec:** treat the hosted Falcon MCP as an alternative a user might choose, not as something falcon-mcp integrates with.
