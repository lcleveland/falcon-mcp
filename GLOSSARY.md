# Falcon MCP

An MCP server that lets an MCP client read and, when permitted, act on one CrowdStrike Falcon tenant.

## Language

**Tenant**:
The single Falcon customer environment, identified by its CID, that a server process talks to.
_Avoid_: instance, account, customer

**CID**:
Falcon's customer ID; the identity of a tenant.
_Avoid_: customer ID (spelled out), org ID

**Cloud**:
The Falcon hosting region a tenant lives in (`us-1`, `us-2`, `eu-1`, `us-gov-1`), which fixes its API base URL.
_Avoid_: region, datacenter, host

**API client**:
The Falcon OAuth2 client whose ID and secret the server authenticates as; its API scopes bound what the server can reach.
_Avoid_: app, service account, token

**Module**:
A functional area of the official falcon-mcp server (e.g. detections, hosts, spotlight); the unit of parity.
_Avoid_: feature, product

**Tool group**:
A named set of tools the operator can enable or disable together.
_Avoid_: module, feature, category

**Action**:
One named operation of a tool, selected by its `action` argument (e.g. `search`, `get`, `contain`).
_Avoid_: command, method, operation

**Probe**:
The startup check that tries one cheap read per action's scope and hides the actions the API client cannot reach.
_Avoid_: health check, scope check

**Capability**:
A named class of write the operator opts into; writes outside an enabled capability do not exist for the client.
_Avoid_: permission, verb flag
