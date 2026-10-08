Recon Exposed-Data Record Aggregation Guide

Use `falcon_aggregate_recon_exposed_data_records` to summarize leaked credential and PII
records — top breach sites, credential-status mix, volume over time — without pulling
individual rows. For the rows themselves, use `falcon_search_recon_exposed_data_records`.

=== AGGREGATION FIELDS: A STRICT LIST ===
This endpoint accepts only the fourteen fields below and rejects anything else with a
400. That is a much narrower set than the tool's `filter` parameter accepts, so a field
you can filter on is not necessarily a field you can aggregate on.

• cid
• notification_id
• notification_group_id
• created_date — epoch millis; use with date_histogram or date_range
• rule.id
• rule.name
• rule.topic — SA_DOMAIN, SA_EMAIL
• source_category — chat_medium, other, and similar
• site — telegram.org, stealer_logs, malware_logs, and similar
• author
• file.name
• credential_status — newly_reported, previously_reported, confirmed_active
• bot.operating_system.hardware_id
• bot.bot_id

Note the dotted spellings: this endpoint uses `rule.topic` and `rule.name`, whereas
`falcon_aggregate_recon_notifications` uses `rule_topic`. They are not interchangeable.
Commonly attempted but rejected here: id, email, domain, login_id, exposure_date,
hash_type, user_uuid, site_id, author_id, status, rule_topic, and any location.*,
financial.*, or social.* field.

=== AGGREGATION TYPES ===
• terms: Top values of a field, ranked by document count. The default.
• date_histogram: Evenly spaced time buckets. Set `interval` to hour, day, week,
  month, quarter, or year.
• date_range: Explicit time windows. Set `date_ranges`, e.g.
  [{"from": "now-30d", "to": "now"}]
• range: Explicit numeric windows. Set `ranges`, e.g. [{"From": 0, "To": 100}]
• cardinality: Distinct-value count for a field.
• max / min: Largest and smallest value of a numeric field.

`date_histogram`, `date_range`, and `range` each fail without their companion
argument — `interval`, `date_ranges`, and `ranges` respectively. Always supply it
when choosing those types.

Not supported on either recon aggregate endpoint: sum, avg, and percentiles all
return a 400, including on numeric date fields.

=== READING THE RESPONSE ===
Each aggregation returns `{"name": ..., "buckets": [...]}`, where `name` echoes the
`name` you passed — use it to tell results apart. Bucket entries key on `label` and
`count`, not `key`.

For cardinality, max, and min the single bucket looks like `{"count": 0, "value": N}`.
The answer is `value`; the `count: 0` is an artifact of the shape and does NOT mean
"no data".

Date fields bucket as epoch-millisecond integers. `date_histogram` also returns
`key_as_string` with a readable ISO timestamp.

=== NARROWING AND NESTING ===
• `filter` accepts the same FQL as the matching search tool, applied before aggregating.
• `q` does a free-text search across the record.
• `size` caps the number of terms buckets returned.
• `sort` orders buckets, e.g. `_count|asc`.
• `sub_aggregates` nests a second aggregation inside every bucket of the first, which
  is how you get a breakdown-within-a-breakdown.

A filter that references an unknown field returns an empty `resources` list with HTTP
200 — indistinguishable from a filter that legitimately matched nothing. Malformed FQL
syntax returns a 400. Stick to the fields in the matching search FQL guide.

=== EXAMPLES ===

# Credential-status mix across all exposed data
field: credential_status, aggregate_type: terms

# Top sites leaking your credentials
field: site, aggregate_type: terms, size: 10

# Newly reported exposures by site
field: site, aggregate_type: terms, size: 10, filter: credential_status:'newly_reported'

# Exposure volume per day
field: created_date, aggregate_type: date_histogram, interval: day

# Which monitoring rules surface the most exposed records
field: rule.name, aggregate_type: terms, size: 10

# Credential-status breakdown within each rule topic
field: rule.topic, aggregate_type: terms, sub_aggregates:
  [{"type": "terms", "field": "credential_status", "name": "by_status"}]
