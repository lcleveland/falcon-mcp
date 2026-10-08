# gofalcon vs hand-rolled Falcon client

Research for [#3](https://github.com/lcleveland/falcon-mcp/issues/3). This is input to the client decision (#8), not the decision itself.

Sources examined (2026-10-08):

- gofalcon at `v0.23.0` (commit `9e66b54`, 2026-10-02): <https://github.com/CrowdStrike/gofalcon>
- Official falcon-mcp (Python) at `82d5031` (2026-10-06, v0.19.0): <https://github.com/CrowdStrike/falcon-mcp>
- Sibling hand-rolled client: `ninjaone-mcp/internal/ninjaone/client.go` (306 lines, stdlib only) and `ninjaone-mcp/pkgs/ninjaone-mcp.nix`

## Summary

| Criterion | gofalcon v0.23.0 | Hand-rolled (ninjaone-style) |
|---|---|---|
| Endpoint coverage for the official modules | All of them, typed (168 service packages, about 1,660 operations) | Whatever we add to an operation table (about 140 for parity) |
| Stripped static binary, tiny test program | **22.9 MB** | **6.1 MB** |
| Clean `buildGoModule` build (32 cores) | **24 s** | **4 s** |
| Local `go build` cache | **over 1.2 GB** (the 2 GB scratch tmpfs filled up before the build finished) | about 93 MB |
| Go modules pulled in | 55 (`go list -m all`) | 1 |
| Vendored source (vendorHash FOD) | 84 MB (82 MB of it gofalcon itself) | none (stdlib) |
| Cloud autodiscovery | Built in (`Cloud: autodiscover`) | About 20 lines: POST `/oauth2/token` on us-1 and read `X-Cs-Region` |
| Token handling | `x/oauth2` clientcredentials: caches the token and refreshes it before expiry. Does not retry once on a 401. | Copy the ninjaone `bearer()` pattern: cache, refresh 1 minute early, force-refresh on 401 |
| Rate limit / retry | Proactive slowdown on `X-Ratelimit-Remaining`. Opt-in retry that honours `X-RateLimit-RetryAfter` | Ours to write (ninjaone already has GET-only retry with backoff) |
| Versioning | v0.x. The README warns that minor versions may break things. About 1 release a month (10 tags since 2025-07) | Ours |
| Response fidelity | Decodes into typed swagger models, so fields the spec omits are dropped | Raw JSON passthrough, nothing dropped |

**Recommendation (input to #8): use a hand-rolled client.** Build it on the ninjaone `Client` shape plus a static `operationId -> (method, path)` table for the endpoints we expose. Keep gofalcon as the reference for paths, cloud hosts and rate-limit headers. gofalcon's main selling point is typed coverage of the whole Falcon API. An MCP server does not benefit from that, because it hands JSON to a model, and the official server gets by with about 140 untyped operations. In exchange, gofalcon costs about 4x the binary size, 6x the clean Nix build time, an 84 MB vendor FOD and a v0.x API that can break on minor bumps. The parts worth having (autodiscovery, rate-limit handling) are small and easy to copy.

## Endpoint coverage

The official server goes through falconpy's untyped `APIHarnessV2.command(operation, **kwargs)` (`falcon_mcp/client.py:18,87,204`). The modules (`falcon_mcp/modules/`) name **141 distinct operation IDs** as string literals. A few more reach `command()` through variables in `shield.py`, `recon.py`, `rtr.py`, `serverless.py` and `sensor_usage.py`.

I matched those IDs against gofalcon's generated `func (a *Client) X(` methods, ignoring case and underscores:

- 130 of 141 matched by name.
- The other 11 are all present but **under different names**. gofalcon's transformed spec renames operation IDs, so I checked these by `PathPattern`:
  - `GetQueriesAlertsV2` -> `alerts.QueryV2` (`/alerts/queries/alerts/v2`)
  - `PatchEntitiesAlertsV3` -> `alerts.UpdateV3` (`/alerts/entities/alerts/v3`)
  - `PostAggregatesAlertsV2` and `PostEntitiesAlertsV2` -> the `/alerts/aggregates/alerts/v2` and `/alerts/entities/alerts/v2` methods
  - `ReadContainerCombined` and `ReadContainerCount` -> `kubernetes_protection.ContainerCombined` and `ContainerCount`
  - `scheduled_reports_query/get/launch` -> `scheduled_reports.Query`, `QueryByID`, and `/reports/entities/scheduled-reports/execution/v1`
  - `WorkflowExecute` and `WorkflowExecutionResults` -> `workflows.Execute` and `/workflows/entities/execution-results/v1`

So gofalcon has **full coverage** of what the official server uses. One practical consequence: falconpy operation IDs (which the official server's docs, and probably our tool names, use) do not map 1:1 onto gofalcon method names.

A hand-rolled client covers exactly the operations we put in its table. About 140 `{method, path}` entries can be generated once from the swagger spec that gofalcon vendors (`specs/`) or from falconpy's `_endpoint` modules. falcon-mcp's dispatch is already "operation ID + params -> JSON", so a table plus one generic `Do` is a direct translation.

## Binary size and build time (measured)

Two throwaway programs were built with nixpkgs `go1.26.8`, `CGO_ENABLED=0` and `-ldflags "-s -w"` through `buildGoModule` (the same settings as `ninjaone-mcp.nix`):

- `hr`: stdlib only. POSTs to `/oauth2/token` and decodes the JSON.
- `gf`: `falcon.NewClient(...)` with autodiscover, plus one `Hosts.QueryDevicesByFilter` call.

| | hr | gf |
|---|---|---|
| Binary | 6,131,088 B | 22,902,192 B |
| Clean Nix build (`--rebuild`) | 4 s | 24 s |
| go-modules FOD | n/a | 83,578,888 B |

Calling `falcon.NewClient` links all 168 service packages, because `client.New` wires up every service (172 crowdstrike packages appear in `go list -deps`). Importing only the services you use does not help, because auth and autodiscovery live in the same `falcon` package that calls `client.New`. The MCP go-sdk and the server code add roughly the same amount to both binaries, so the gap is about 17 MB of fixed overhead.

The local `go build` of `gf` needed over 1.2 GB of `GOCACHE` and `$WORK` and ran out of space on a 2 GB tmpfs. That will matter in a small CI runner or a devshell on tmpfs.

## Cloud autodiscovery

gofalcon (`falcon/cloud.go`, `Autodiscover`) requests a token from us-1 (`api.crowdstrike.com`), reads the `X-Cs-Region` response header, maps it to a host (us-1, us-2, us-3, eu-1, us-gov-1 and us-gov-2 are hard-coded in `CloudType.Host()`), then revokes the discovery token in the home region. Autodiscovery is refused when using a raw access token.

The official falcon-mcp does **not** autodiscover. It uses `FALCON_BASE_URL`, defaulting to `https://api.crowdstrike.com` (`falcon_mcp/client.py:53-54`).

A hand-rolled version needs one token request and one header read. Skipping the revoke is optional, because the token is simply reused if the region is us-1.

## Token handling

gofalcon (`falcon/api_client.go`) uses `golang.org/x/oauth2/clientcredentials` with `TokenURL = https://<host>/oauth2/token`, with optional `member_cid` for MSSP (Flight Control). `oauth2` caches the token and refreshes it shortly before expiry. Nothing re-authenticates after a 401 mid-life, for example when a token is revoked.

On top of that, gofalcon adds:

- A User-Agent and `CrowdStrike-SDK` header.
- A proactive 200 to 500 ms delay when `X-Ratelimit-Remaining` is 10 or less.
- An opt-in `RetryConfig` that retries on 429 and 5xx, and honours `X-RateLimit-RetryAfter` (an epoch timestamp) with a shared cooldown.
- A default 5-minute HTTP timeout.
- A `logrus` global logger.

The ninjaone `bearer(ctx, force)` pattern (cache, refresh 1 minute before expiry, force-refresh on 401, mutex-guarded) already covers more than this, minus the Falcon-specific rate-limit headers. Adding `member_cid` and the `X-RateLimit-RetryAfter` handling is a few lines each.

## Maintenance cadence and versioning

- gofalcon tags since mid-2025: v0.16.0 (2025-07-18), v0.17.0, v0.18.0, v0.19.0 (2026-01-07), v0.20.0, v0.20.1, v0.21.0, v0.21.1, v0.22.0 (2026-08-04), v0.23.0 (2026-10-02). That is roughly one release a month, with 101 commits since 2025-10-01.
- Most commits are "regenerate SDK from updated swagger spec" plus hand fixes to the spec transform (`specs/transformation.jq`).
- README "Versioning": *"since this module is currently in the v0.x.x stage, backward compatibility cannot be guaranteed between minor versions... recommended to pin... to a specific patch version."*
- Recent history shows real churn in the typed models. For example, `1c892441` "restore pre-v0.22.0 dropped fields so Container decodes them" and `aaff3e2d` "return exported definition as io.Writer instead of []int64". Typed decoding means a spec bug silently drops fields from what the model sees. A raw-JSON client cannot fail this way.
- License: MIT (compatible).

## Dependency footprint

gofalcon's direct requirements are: `go-openapi/{errors,runtime,strfmt,swag,validate}`, `cenkalti/backoff/v5`, `sirupsen/logrus`, `golang.org/x/oauth2`, `gopkg.in/yaml.v3` and `blang/semver`. Indirect requirements include `go.mongodb.org/mongo-driver` (via strfmt), `opentelemetry` (via go-openapi/runtime), `mailru/easyjson` and `mitchellh/mapstructure`. In total that is 55 modules in the build list.

ninjaone-mcp's whole `go.mod` is 2 direct and 7 indirect modules. A hand-rolled Falcon client adds nothing beyond the MCP go-sdk.

## Nix packaging (vendorHash)

Both options package cleanly with `buildGoModule`. Neither needs cgo, and gofalcon needs no `proxyVendor` or patches. The measured `vendorHash` for gofalcon v0.23.0 alone is `sha256-pSlpOoYlebz0Zo+VJt0TN4DAU3RKZ0fWeRrG3Y7cNbY=`. The differences are:

- With gofalcon, the vendor FOD is about 84 MB and every monthly SDK bump changes `vendorHash`. Given the v0.x warning, each bump also needs a review of the release notes.
- With a hand-rolled client, `vendorHash` only changes with the MCP go-sdk, as it does in ninjaone-mcp today.

## What a hand-rolled client must replicate

- OAuth2 client credentials against `/oauth2/token`, with optional `member_cid`, using the ninjaone `bearer()` logic.
- Cloud selection: a `FALCON_BASE_URL` or region name mapped to a host (the host table is in gofalcon `cloud.go`), plus optional `autodiscover` via `X-Cs-Region`.
- 429 handling with `X-RateLimit-RetryAfter` (an epoch timestamp, not seconds).
- An operation table generated once from the swagger spec, so operations can be called by their falconpy ID.
- Multipart/binary for the few upload/download endpoints (RTR files, sample uploads), if those tools are in scope. ninjaone already has a `Multipart` helper.
