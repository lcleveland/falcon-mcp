Falcon Query Language (FQL) - Search Data Security Policies Guide

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
• Numbers: 123 (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition

=== IMPORTANT: platform_name parameter ===

The falcon_search_data_security_entities tool (entity_type='policy') requires a platform_name parameter ('win' or 'mac')
which is separate from the FQL filter. The filter applies within the selected platform.

=== falcon_search_data_security_entities (entity_type='policy') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Policy name. Only the ~ operator works on this field; exact match (without ~) is not supported for policies. Ex: name:~'production'|
|is_enabled|Boolean|No|Whether the policy is enabled. Ex: is_enabled:true Ex: is_enabled:false|
|is_default|Boolean|No|Whether this is the default policy. Ex: is_default:true|
|created_at|Timestamp|Yes|Date the policy was created. Ex: created_at:>'2024-01-01'|
|description|String|Yes|Policy description text. Only the ~ operator works on this field; exact match returns nothing. Ex: description:~'compliance'|
|precedence|Integer|Yes|Policy precedence (evaluation order). Lower = higher priority. Ex: precedence:>0 Ex: precedence:0|
|modified_by|String|Yes|Email of the user who last modified the policy. Exact match returns nothing on this field; use ~ with the full address or its full local part. Partial words do not match. Ex: modified_by:~'user@example.com'|

=== EXAMPLE USAGE ===

• is_enabled:true - All enabled policies
• is_default:true - Default policy only
• is_enabled:true+precedence:>0 - Enabled non-default policies
• name:~'production' - Policies with "production" in the name
• created_at:>'2024-01-01' - Recently created policies

=== SORTING ===

Supported sort fields: name.asc, name.desc, precedence.asc, created_at.desc

=== IMPORTANT NOTES ===
• platform_name ('win' or 'mac') is required and is not an FQL filter
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Boolean values have no quotes: is_enabled:true
