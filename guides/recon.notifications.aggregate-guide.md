Recon Notification Aggregation Guide

Use `falcon_aggregate_recon_notifications` to answer "how many" and "which are the top"
questions about recon notifications without pulling individual records. For the records
themselves, use `falcon_search_recon_notifications`.

=== VERIFIED AGGREGATION FIELDS ===
Notification attributes:
• status — new, in-progress, pending-review, closed-true-positive,
  closed-false-positive, closed-no-action-true-positive
• rule_topic — SA_TYPOSQUATTING, SA_THIRD_PARTY, SA_CUSTOM, SA_DOMAIN, SA_IP,
  SA_BRAND_PRODUCT, SA_ALIAS, SA_VIP, SA_EMAIL, SA_CVE, SA_AUTHOR, SA_BIN
• rule_priority — low, medium, high, critical
• rule_id, item_type, item_site, source_category, cid, user_uuid, id
• assigned_to_uuid — unassigned, or a user UUID
• created_date, updated_date — epoch millis; use with date_histogram or date_range

Breach and typosquatting detail:
• breach_summary.credential_statuses, breach_summary.is_retroactively_deduped
• typosquatting.id, typosquatting.unicode_format, typosquatting.punycode_format
• typosquatting.parent_domain.{id,unicode_format,punycode_format}
• typosquatting.base_domain.{id,unicode_format,punycode_format,is_registered}
• typosquatting.base_domain.whois.registrar.{name,status}
• typosquatting.base_domain.whois.registrant.{email,name,org}
• typosquatting.base_domain.whois.name_servers

Do not aggregate on `rule_name` — it returns a server error on this endpoint. Aggregate
on `rule_id` instead, then resolve names with `falcon_search_recon_rules`. The fields
`notification_id`, `site`, and `author` belong to the exposed-data-record schema and
return no buckets here.

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

# Notification volume by status
field: status, aggregate_type: terms

# Busiest monitoring rules in the past 30 days
field: rule_id, aggregate_type: terms, size: 10, filter: created_date:>'now-30d'

# Daily notification trend
field: created_date, aggregate_type: date_histogram, interval: day

# Priority mix for typosquatting only
field: rule_priority, aggregate_type: terms, filter: rule_topic:'SA_TYPOSQUATTING'

# How many distinct rules have fired
field: rule_id, aggregate_type: cardinality

# Which registrars host the most typosquatting domains
field: typosquatting.base_domain.whois.registrar.name, aggregate_type: terms, size: 10
