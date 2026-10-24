Falcon Query Language (FQL) - Search Data Security Content Patterns Guide

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

=== falcon_search_data_security_entities (entity_type='content_pattern') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Content pattern name. Supports text match (~) for case-insensitive search. Ex: name:~'credit card' Ex: name:'SSN Pattern'|
|type|String|Yes|Pattern type. Values: custom, predefined. Ex: type:'custom' Ex: type:'predefined'|
|category|String|Yes|Pattern category. Values: PII, PCI DSS, PHI, Custom, ITAR, Secret. Ex: category:'PII' Ex: category:'Custom'|
|region|String|Yes|Geographic region the pattern applies to. Ex: ALL, US, EU. Ex: region:'ALL' Ex: region:'US'|
|deleted|Boolean|No|Whether the content pattern has been deleted. Ex: deleted:false Ex: deleted:true|
|example|String|Yes|Example text for the content pattern. Ex: example:~'4111'|
|created|Timestamp|Yes|Date the content pattern was created (RFC3339). Ex: created:>'2024-01-01'|
|last_updated|Timestamp|Yes|Date the content pattern was last updated (RFC3339). Ex: last_updated:>'2024-06-01'|

=== EXAMPLE USAGE ===

• type:'custom' - Custom patterns only
• type:'predefined' - CrowdStrike-provided patterns
• category:'PCI DSS' - Payment-card data patterns
• deleted:false - Active (non-deleted) patterns
• region:'US'+type:'predefined' - US-specific predefined patterns
• name:~'credit' - Patterns with "credit" in the name

=== SORTING ===

Supported sort fields: name.asc, name.desc, category.asc, region.asc
(name ordering ignores case and punctuation)

=== IMPORTANT NOTES ===
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Boolean values have no quotes: deleted:false
• type values are lowercase: 'custom', 'predefined'
• Relative dates such as 'now-7d' are rejected; use an absolute UTC timestamp
