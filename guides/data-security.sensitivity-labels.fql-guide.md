Falcon Query Language (FQL) - Search Data Security Sensitivity Labels Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===
• No operator = equals (default)
• ! = not equal to
• > = greater than
• >= = greater than or equal
• < = less than
• <= = less than or equal
• ~ = text match (ignores case, spaces, punctuation)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' (use ~ for case-insensitive matching)
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition

=== falcon_search_data_security_entities (entity_type='sensitivity_label') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Sensitivity label name (a unique identifier). Supports text match (~). Ex: name:~'confidential'|
|display_name|String|Yes|Human-readable label name. Ex: display_name:~'confidential'|
|external_id|String|Yes|The provider (Microsoft/Google) label ID. Ex: external_id:'label-123'|
|deleted|Boolean|No|Whether the sensitivity label has been soft-deleted. Ex: deleted:false|
|created|Timestamp|Yes|Date the label was created (RFC3339). Ex: created:>'2024-01-01'|
|last_updated|Timestamp|Yes|Date the label was last updated (RFC3339). Ex: last_updated:>'2024-06-01'|

=== SORTING ===

Supported sort fields: name.asc, name.desc, created.desc, last_updated.desc

=== IMPORTANT NOTES ===
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Boolean values have no quotes (e.g. deleted:false)
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Relative dates such as 'now-7d' are rejected; use an absolute UTC timestamp
