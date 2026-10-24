# Capability flags on top of Falcon's scopes

Falcon's API scopes are already split per service, so they look like enough of a gate. They aren't. `Hosts:write` covers tagging, network containment, hiding a host and permanent deletion. `IOC Management:write` covers both blocking and allowing. Read-only RTR runs commands on live endpoints with only a read scope. So, as in the sibling MCPs, writes are gated by eleven opt-in **capabilities**, split by blast radius rather than by scope:

- triage
- host tags
- containment
- detection add
- detection remove
- fleet config
- RTR read
- RTR respond
- destructive
- workflows
- uninstall token

Detection *add* and *remove* are separate flags because lowering protection is where an attacker driving the agent would aim.

Some operations are never exposed, whatever the flags:

- RTR admin
- permanent host delete
- revealing the bulk maintenance token, rotating it, or disabling uninstall protection
- user, API-client and installation-token administration

Revealing one host's uninstall token was on that list until IT asked for it to remove and reinstall sensors. It has its own capability rather than riding on destructive: the token is a secret that lets anyone at the host remove the sensor, a different risk from hiding a host. It takes one host, confirmed by hostname, and sends the reason as Falcon's audit message.

Reads that happen to need `:write` scopes (NGSIEM search, query-only Identity Protection GraphQL) are gated as reads: we key off what an action does, not the name of its scope.

See [Draw the write capability map](https://github.com/lcleveland/falcon-mcp/issues/9) and the [write-endpoint research](https://github.com/lcleveland/falcon-mcp/blob/main/docs/research/falcon-write-endpoints.md).
