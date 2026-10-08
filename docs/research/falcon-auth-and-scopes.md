# Falcon auth, cloud and scope discovery

Research for [#5](https://github.com/lcleveland/falcon-mcp/issues/5). Researched 2026-10-08.

Sources (pinned):

- **FalconPy** `CrowdStrike/falconpy` @ `06a5df8` (2026-09-24)
- **gofalcon** `github.com/crowdstrike/gofalcon` v0.23.0 (module cache)
- **Official MCP** `CrowdStrike/falcon-mcp` @ `82d5031` (2026-10-06)
- **Dev docs**: developer.crowdstrike.com API reference ([oauth2](https://developer.crowdstrike.com/api-reference/collections/oauth2/), [api-clients](https://developer.crowdstrike.com/api-reference/collections/api-clients/)), [FalconPy configuration](https://developer.crowdstrike.com/sdks/python/configuration/), [falcon-mcp credentials](https://developer.crowdstrike.com/falcon-mcp/getting-started/credentials/)

Labels: **[src]** means read in first-party source or docs. **[2nd]** means secondary-source only. **[unverified]** means it needs a live tenant to confirm.

## TL;DR

1. **Token.** Call `POST /oauth2/token` with the form fields `client_id`, `client_secret` and optionally `member_cid`. The response is 201 with `access_token` and `expires_in`, and the token lives 30 min. Refresh it about 2 min before expiry. Revoke it with `POST /oauth2/revoke`, sending `token` in the body and the client id and secret as HTTP Basic auth.
2. **Clouds.** There is one host per cloud. Autodiscovery works only for commercial clouds: get a token from us-1 and read the `X-CS-Region` response header. Gov clouds must be configured explicitly.
3. **Rate limits.** Every response carries `X-RateLimit-Limit` (requests per minute) and `X-RateLimit-Remaining` (sliding one-minute window). A 429 carries `X-RateLimit-RetryAfter`, a Unix epoch.
4. **Scopes.** There is **no cheap, unprivileged "what scopes do I have" endpoint.**
   - `GET /api-clients/entities/accessible-scopes/v1` exists but needs the `Api Client Mgmt: READ` scope, and it lists the *customer's* available scopes, not this client's.
   - A 403 body does not reliably say whether the cause is a missing scope, a missing subscription or an IP allowlist.
   - **Recommendation:** probe at startup with one `limit=1` GET per tool group. 403 hides the group. 2xx or 404 shows it. Anything else keeps it visible and logs a warning.
5. **Official falcon-mcp does no probing.** It authenticates once at startup and fails fast. It keeps a static operation-to-scope table and appends "Required scopes: …" to any 403 that a tool returns.

## Token endpoint

| | |
|---|---|
| Request | `POST {base}/oauth2/token`, form-encoded `client_id`, `client_secret`, optional `member_cid` [src: FalconPy `_util/_auth.py` `login_payloads`; dev docs oauth2] |
| Success | **201** (not 200) with body `access_token`, `expires_in`, `token_type` [src: FalconPy `_falcon_interface.py` `_login_handler` checks `== 201`]. The swagger model also declares `scope`, `id_token`, `refresh_token` and `issued_token_type` [src: gofalcon `models/domain_access_token_response_v1.go`]. **[unverified]** whether `scope` is filled in for client-credentials tokens. Check this on a live tenant: if it is filled in, it is the scope oracle, so log it once at debug. |
| Lifetime | 30 minutes ("standard 30-minute lifespan", oauth2RevokeToken description) [src: FalconPy `_endpoint/_oauth2.py`; dev docs]. Use `expires_in`, don't hard-code it. |
| Refresh | FalconPy refreshes when `now - issued >= expires_in - renew_window`. The default window is 120 s, clamped to 120–1200 s [src: FalconPy `_constant`, `_falcon_interface.py:574`]. gofalcon uses `golang.org/x/oauth2/clientcredentials`, which refreshes transparently and adds `member_cid` through `EndpointParams` [src: gofalcon `falcon/api_client.go` `clientCredentialsHTTPClient`]. **For us:** reuse `clientcredentials.Config` as gofalcon does, either through gofalcon itself or with the same few lines. |
| Token format | JWT. gofalcon notes "There is nothing in the access token (JWT) which identifies the cloud" [src: gofalcon `api_client.go` `NewClient`]. **[unverified]** whether claims carry scopes. |
| Revoke | `POST {base}/oauth2/revoke` with form `token` (plus optional `client_id`) and the header `Authorization: basic b64(id:secret)` [src: FalconPy `logout_payloads`; dev docs]. Revoke in the token's *home* region [src: gofalcon `cloud.go` Autodiscover step 4]. |
| Token errors | 401 means bad id or secret. 403 means the client is disabled or IP-allowlisted, or (when `member_cid` is set) the child CID is invalid [src: official MCP `client.py` `auth_failure_message`]. gofalcon treats the 403 body message `"access denied, authorization failed"` *on the token endpoint* as an IP-allowlist failure [src: gofalcon `cloud.go`]. |
| Redirects | FalconPy enables `allow_redirects` **only** for `/oauth2/token` and `/oauth2/revoke` [src: FalconPy `_util/_functions.py` ~L438]. Go's `http.Client` follows 307 and 308 by default, so we need nothing special. |

### member_cid (Flight Control / MSSP)

A parent-CID client passes `member_cid` on the token request, and the token is then locked to that child [src: dev docs oauth2 param description "For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID"]. One token covers one child, so switching children means a new token (FalconPy `child_login`). Official MCP exposes this as `FALCON_MEMBER_CID` [src: official MCP `client.py`]. **For us:** a single optional `member_cid` config value is enough. Scope and subscription probing must run *with* the member token, because the child's licences are what count.

## Clouds and autodiscovery

| Cloud | API host |
|---|---|
| us-1 | `api.crowdstrike.com` |
| us-2 | `api.us-2.crowdstrike.com` |
| us-3 | `api.us-3.crowdstrike.com` (enumerated in both SDKs) |
| eu-1 | `api.eu-1.crowdstrike.com` |
| us-gov-1 (aka gov1) | `api.laggar.gcw.crowdstrike.com` |
| us-gov-2 (aka gov2) | `api.us-gov-2.crowdstrike.mil` |

[src: FalconPy `_enum/_base_url.py`; gofalcon `falcon/cloud.go` `Host()` and `CloudValidate`, which also accepts `autodiscover`. The official MCP docs list only us-1, us-2, eu-1 and US-GOV.]

**Autodiscovery** [src: gofalcon `cloud.go` `Autodiscover`; FalconPy `autodiscover_region`]:

1. Request a token from **us-1**.
2. Read the `X-CS-Region` response header, for example `us-2`.
3. If the region differs, switch the host. gofalcon then **revokes** that discovery token in the home region and lets `clientcredentials` mint a fresh one there. FalconPy keeps the token and just swaps `base_url`.

Only us-1, us-2 and eu-1 support this. US-GOV-1 and US-GOV-2 "will still need to provide this value" [src: FalconPy configuration docs, README]. FalconPy notes that us-gov-1 started returning the header but "autoselection is still unsupported" [src: `_functions.py` L933]. Commercial and gov clouds are separate identity planes, so a gov key never reaches the us-1 token endpoint.

A wrong commercial region does not fail the token call; the header is how you notice. Pointing API calls at the wrong region gives 401 or 403 [2nd].

**For us:** the config takes `cloud = auto|us-1|us-2|us-3|eu-1|us-gov-1|us-gov-2`, defaulting to `auto`, plus an optional host override. Gofalcon's `falcon.NewClient` with `Cloud: falcon.Cloud(s)` already does all of this.

## Rate limits

- Response headers: `X-RateLimit-Limit` is the "Request limit per minute". `X-RateLimit-Remaining` is "The number of requests remaining for the sliding one minute window" [src: gofalcon `client/oauth2/oauth2_access_token_responses.go` header docs]. FalconPy exposes the same two headers on `Result` [src: `_result/_headers.py`].
- On a 429, `X-RateLimit-RetryAfter` gives the Unix epoch at which to retry [src: gofalcon `api_client.go` `parseRetryAfter`].
- The default quota is 6,000 requests per minute **per customer CID**, shared by all API clients in that CID [2nd: industry write-ups; CrowdStrike's portal docs are login-walled]. Treat the header as authoritative.
- What gofalcon does [src: `api_client.go`]:
  - It slows down proactively: 200 ms when Remaining ≤ 10, 500 ms when ≤ 5.
  - With `RetryConfig` set, it retries 429 and 5xx with exponential backoff (2 s initial, 1 min max).
  - It honours `RetryAfter` and shares a cooldown across requests.
- The official MCP caps concurrency through anyio's thread limiter as deliberate backpressure, and does no retry handling of its own [src: `modules/base.py` L53].
- The token endpoint has its own, tighter limit (it returns 429 per the swagger). Collapse concurrent refreshes into one, as the official MCP does with `_token_lock` [src: `client.py` `_ensure_token_fresh`]. `x/oauth2`'s `ReuseTokenSource` already does this.

## Scope and subscription discovery (the important part)

### What exists

| Endpoint | Gives | Needs | Verdict |
|---|---|---|---|
| `GET /api-clients/entities/accessible-scopes/v1` (`GetAccessibleScopes`) | "Get all available scopes for customer": a list of `{id, group, action}` [src: gofalcon `models/msaspec_scope.go`; dev docs] | `Api Client Mgmt: READ` [src: dev docs api-clients] | These are the tenant's grantable scopes, a good *subscription* proxy, since the console only offers scopes for licensed modules **[unverified inference]**. They are not *this client's* scopes. It needs an admin-ish scope we should not ask users to grant an MCP server. Use it opportunistically only. |
| `GET /api-clients/entities/api-clients/v1?ids=<own client_id>` (`GetAPIClients`) | The client record, whose request model carries `scopes []string` [src: gofalcon `models/api_client_request.go`] | `Api Client Mgmt: READ` | This would be exact, but has the same privilege problem. Optional path: if it succeeds, trust it and skip the probes. |
| `/access-scope-management/*` | RBAC "Access Scopes" (host-population scoping), **not** OAuth scopes [src: FalconPy `_endpoint/_access_scopes.py`] | n/a | Irrelevant. Don't let the name mislead you. |
| Token response `scope` field | Declared in swagger | none | **[unverified]**. The cheapest possible answer if it is filled in. |
| Any "subscriptions / licences / entitlements" endpoint | None found. A grep of all FalconPy endpoint paths for subscri, entitle, licens and ccid turns up nothing relevant. | | Doesn't exist publicly. |

### Can a 403 tell missing scope from missing subscription?

**Not reliably.** The canonical 403 body is `{"errors":[{"code":403,"message":"access denied, authorization failed"}]}`.

- FalconPy and PSFalcon maintainers describe a 403 as "either a scoping issue … or an IP Blocklist" [src: [falconpy discussion #1138](https://github.com/CrowdStrike/falconpy/discussions/1138), [psfalcon #75](https://github.com/CrowdStrike/psfalcon/discussions/75)].
- An unlicensed Discover module produced exactly the same message [src: falconpy issue #682].
- The official MCP does not try to tell them apart. It just appends the statically known required scopes [src: official MCP `common/errors.py`].
- For hiding a tool group, the cause doesn't matter: either way the group is unusable. Surface the 403 `message` in logs for humans.

### Recommended probe

1. Authenticate (autodiscover, plus `member_cid` if set). On failure, exit non-zero with the official MCP-style hint (401: credentials; 403: allowlist, disabled client or bad `member_cid`).
2. *Optional fast path:* try `GetAPIClients?ids=<client_id>`. On 200, take its scopes as truth and map each group's required scopes to visibility. On 403, fall through to step 3.
3. Run one read probe per tool group, concurrently, each with `limit=1`:
   - **2xx** (or 404 / empty) means visible.
   - **403** means hidden. Log the group, the scope it needs and the API's message.
   - **401** means re-auth once, then fail.
   - **429, 5xx or timeout** means **keep the group visible** and warn. Don't hide on a transient failure.
4. The cost is roughly 15–25 requests against a 6,000/min budget, so it is negligible. Re-probe lazily: if a visible tool later gets a 403, report the missing scope. The official MCP's `get_required_scopes` pattern is worth copying as a static table.

Write scopes can't be probed with a safe read. The options:

- **(a)** Show write tools whenever the read probe passes, and let the 403 at call time explain. This is the simplest choice.
- **(b)** Send a deliberately invalid write, such as an empty-body PATCH, and treat 400 as allowed and 403 as denied. **[unverified]** It relies on the gateway checking scope before validating the body. Don't build on it until it has been tested on a tenant.

### Cheap read probe per module

These operations and scopes come from the official MCP `common/api_scopes.py`. The paths come from FalconPy `_endpoint/*`. All are `GET` with `limit=1`.

| Group | Probe operation | Path | Scope |
|---|---|---|---|
| Hosts | `QueryDevicesByFilter` | `/devices/queries/devices/v1` | Hosts:read |
| Alerts / detections | `GetQueriesAlertsV2` | `/alerts/queries/alerts/v2` | Alerts:read |
| Host groups | `queryHostGroups` | `/devices/queries/host-groups/v1` | Host Groups:read |
| Intel | `QueryIntelActorIds` | `/intel/queries/actors/v1` | Actors (Falcon Intelligence):read |
| IOC management | `indicator_search_v1` | `/iocs/queries/indicators/v1` | IOC Management:read |
| Spotlight | `queryVulnerabilities` | `/spotlight/queries/vulnerabilities/v1` | Vulnerabilities:read. `filter` is required, e.g. `status:'open'`. |
| Discover (asset inventory) | `query_hosts` | `/discover/queries/hosts/v1` | Assets:read |
| RTR | `RTR_ListAllSessions` | `/real-time-response/queries/sessions/v1` | Real time response:read |
| Cases | `queries_cases_get_v1` | `/cases/queries/cases/v1` | Cases:read |
| Fusion workflows | `WorkflowDefinitionsCombined` | `/workflows/combined/definitions/v1` | Workflows:read |
| Prevention policies | `queryPreventionPolicies` | `/policy/queries/prevention/v1` | Prevention Policies:read |
| Content update policies | `queryCombinedContentUpdatePolicies` | `/policy/combined/content-update/v1` | Content Update Policies:read |
| Exclusions (ML) | `exclusions_search_v2` | `/exclusions/queries/exclusions/v2` | Machine Learning Exclusions:read |
| Recon | `QueryNotificationsV1` | `/recon/queries/notifications/v1` | Monitoring rules (Falcon Intelligence Recon):read |
| Sensor usage | `GetSensorUsageWeekly` | `/billing-dashboards-usage/aggregates/weekly-average/v1` | Sensor Usage:read |

Some groups have no read-only probe:

- **NGSIEM:** starting a search needs `NGSIEM:write` (`StartSearchV1`).
- **Identity Protection:** GraphQL needs `Identity Protection GraphQL:write`.

For these, try the fast path in step 2, or show the group and rely on the 403 at call time.

## How the reference implementations handle this

- **Official falcon-mcp** (Python, FalconPy `APIHarnessV2`):
  - Env `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL` (default us-1) and `FALCON_MEMBER_CID`.
  - Calls `login()` once at startup and raises with a status-specific hint on failure.
  - Modules are enabled by a `--modules` flag. **There is no scope or subscription probing.**
  - On a 403 it appends the required scopes from a static table.
  - A `falcon_check_connectivity` tool does a stateless token request.
  - Concurrent refreshes are serialised by a lock.

  [src: `client.py`, `server.py` L148–163 and L384–398, `common/errors.py`, `common/api_scopes.py`]
- **FalconPy:**
  - Lazy refresh with `renew_window`, plus region autodiscovery by `X-Cs-Region` (commercial clouds only).
  - Redirects are followed only for the oauth2 endpoints.
  - Rate-limit headers are surfaced on the result, with no automatic retry.
  - Logs redact `member_cid` and tokens.
- **gofalcon:**
  - `falcon.NewClient(&falcon.ApiConfig{ClientId, ClientSecret, MemberCID, Cloud, Context})` gives autodiscovery (with revocation of the discovery token), `x/oauth2` client credentials, a User-Agent, proactive rate-limit pacing and opt-in retry that honours `X-RateLimit-RetryAfter`.
  - **This is the Go dependency that covers everything above.**

## Open items to verify on a live tenant

1. Is the token response's `scope` filled in, and do the JWT claims carry scopes? If either is true, probing collapses to zero extra calls.
2. Does an unlicensed module's endpoint return 403 with the same message as a missing scope? This only matters for the log wording.
3. Is scope checked before body validation (needed for write probe option b)?
4. What is the actual `X-RateLimit-Limit` value on this tenant?
