Falcon Query Language (FQL) - Search Data Security Local Applications Guide

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

=== falcon_search_data_security_entities (entity_type='local_application') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Local application name. Supports text match (~). Ex: name:~'excel'|
|executable_name|String|Yes|Name of the executable representing the local application (e.g. excel.exe, notepad.exe, cmd.exe - Windows only). Ex: executable_name:'excel.exe'|
|deleted|Boolean|No|Whether the local application has been soft-deleted. Ex: deleted:false|
|created|Timestamp|Yes|Date the local application was created (RFC3339). Ex: created:>'2024-01-01'|
|last_updated|Timestamp|Yes|Date the local application was last updated (RFC3339). Ex: last_updated:>'2024-06-01'|

=== SORTING ===

Supported sort fields: name.asc, name.desc, created.desc, last_updated.desc

=== IMPORTANT NOTES ===
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Boolean values have no quotes (e.g. deleted:false)
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Relative dates such as 'now-7d' are rejected; use an absolute UTC timestamp
