## Agent skills

### Issue tracker

Issues live in GitHub Issues on `lcleveland/falcon-mcp` (via `gh`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` + `docs/adr/`. See `docs/agents/domain.md`.

## Tenant privacy

This repo and its issues are public. Never write identifying details of the operator's Falcon tenant into them: CID, cloud/region, hostnames, base URLs that name a cloud, licensed modules/subscriptions, rate-limit values, API client IDs, host/user/detection data from live calls. Keep such facts in `~/.config/falcon-mcp/tenant-notes.md` (outside the repo). Docs, tests and fixtures use generic placeholders (e.g. `us-1`, made-up CIDs). Generic Falcon API behaviour learned from live calls is fine to record.
