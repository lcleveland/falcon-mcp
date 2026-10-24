Falcon Query Language (FQL) - Search Data Security Web Locations Guide

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

=== falcon_search_data_security_entities (entity_type='web_location') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Web location name. Supports text match (~). Ex: name:~'sharepoint'|
|type|String|Yes|Whether predefined or user-created. Values: predefined, custom. Ex: type:'custom'|
|deleted|Boolean|No|Whether the web location has been soft-deleted. Ex: deleted:false|
|application_id|String|Yes|ID of the cloud application the web location belongs to. Ex: application_id:'0123456789abcdef0123456789abcdef'|
|enterprise_account_id|String|Yes|ID of the enterprise account this web location belongs to. Ex: enterprise_account_id:'0123456789abcdef0123456789abcdef'|
|web_location_group_id|String|Yes|Matches web locations whose web_location_group_ids include this group ID. Ex: web_location_group_id:'0123456789abcdef0123456789abcdef'|
|web_location_group_count|Integer|Yes|Number of web location groups the web location belongs to. Ex: web_location_group_count:>0|
|supports_network_inspection|Boolean|No|Whether network-level inspection is supported. Ex: supports_network_inspection:true|
|created|Timestamp|Yes|Date the web location was created (RFC3339). Ex: created:>'2024-01-01'|
|last_updated|Timestamp|Yes|Date the web location was last updated (RFC3339). Ex: last_updated:>'2024-06-01'|

=== SORTING ===

Supported sort fields: name.asc, name.desc, created.desc, last_updated.desc

=== IMPORTANT NOTES ===
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Boolean values have no quotes (e.g. deleted:false)
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Relative dates such as 'now-7d' are rejected; use an absolute UTC timestamp
