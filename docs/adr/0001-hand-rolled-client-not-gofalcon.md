# Hand-rolled Falcon client, not gofalcon

CrowdStrike's Go SDK, gofalcon, covers every operation we need, but we build a small net/http client in the sibling MCPs' style instead, driven by an operation table generated once (`go:generate`) from FalconPy's endpoint tables. A four-member council voted for this unanimously. These were the deciding reasons:

- **Credential leak.** gofalcon's cloud autodiscovery builds its own transport, which ignores `ApiConfig.Debug`. With `DEBUG=1` in the environment it logs `client_secret` to stderr, and under systemd stderr goes to the journal.
- **Retries replay writes.** gofalcon's retry treats every request the same and replays POST, PATCH and DELETE bodies. We need retry safety decided per operation, because Falcon also has POST-shaped reads, so each op-table entry carries its own write bit.
- **Typed models drop fields** the spec omits. The tool layer projects, truncates and pages raw JSON for the model to read.
- **No call by operation name**, which the `falcon_api` escape hatch needs.
- **The token URL is hard-coded to https**, so gofalcon can't talk to the plain-HTTP stub the VM test uses.
- **Supply chain and upkeep.** gofalcon adds about 50 transitive modules and a monthly v0.x `vendorHash` churn to a process that holds containment and RTR credentials.

What we give up: gofalcon tracks CrowdStrike's API automatically, and it already handles several quirks. We copy those quirks deliberately, each with an httptest case:

- `Content-Type: application/json` is sent even on empty bodies.
- A 403 that looks like an IP-allowlist block gets a hint.
- `X-Cs-Region` is mapped to a hard-coded host through a fixed allowlist; a URL is never built from the header's value.
- `X-RateLimit-RetryAfter` is an epoch timestamp. We cap the wait at about 60s, respect the context deadline, and use it for reads only.
- Requests slow down early when `X-Ratelimit-Remaining` runs low.
- `ids=` query parameters are repeated rather than joined.
- RTR uploads are multipart.

When we add operations, we rerun the generator.

See [Pick the Falcon client library](https://github.com/lcleveland/falcon-mcp/issues/8) and the [gofalcon vs hand-rolled research](https://github.com/lcleveland/falcon-mcp/blob/main/docs/research/gofalcon-vs-hand-rolled.md).
