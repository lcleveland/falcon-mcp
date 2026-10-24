Falcon Query Language (FQL) - Search Data Security Cloud Applications Guide

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

=== falcon_search_data_security_entities (entity_type='cloud_application') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Cloud application name. Supports text match (~). Ex: name:~'salesforce'|
|type|String|Yes|Cloud application origin. Values: integrated, predefined, custom. Ex: type:'custom'|
|deleted|Boolean|No|Whether the cloud application has been soft-deleted. Ex: deleted:false|
|supports_network_inspection|Boolean|No|Whether network-level inspection is supported. Ex: supports_network_inspection:true|
|application_group_id|String|Yes|Cloud application group ID this application belongs to. Ex: application_group_id:'google'|
|created|Timestamp|Yes|Date the cloud application was created (RFC3339). Ex: created:>'2024-01-01'|
|last_updated|Timestamp|Yes|Date the cloud application was last updated (RFC3339). Ex: last_updated:>'2024-06-01'|

=== SORTING ===

Supported sort fields: name.asc, name.desc

=== IMPORTANT NOTES ===
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Boolean values have no quotes (e.g. deleted:false)
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Relative dates such as 'now-7d' are rejected; use an absolute UTC timestamp
