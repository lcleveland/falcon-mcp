Falcon Query Language (FQL) - Search Data Security Classifications Guide

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
• !~ = does not text match

=== DATA TYPES & SYNTAX ===
• Strings: 'value' (use ~ for case-insensitive matching)
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition

=== falcon_search_data_security_entities (entity_type='classification') FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Classification name. Only the ~ operator works on this field; exact match (without ~) is not supported for classifications. Ex: name:~'credit'|
|created_at|Timestamp|Yes|Date the classification was created. Ex: created_at:>'2024-01-01' Ex: created_at:<'2025-06-01'|
|modified_at|Timestamp|Yes|Date the classification was last modified. Ex: modified_at:>'2024-01-01'|
|created_by|String|Yes|Email of the user who created the classification. Exact match returns nothing on this field; use ~ with the full address or its full local part. Partial words do not match. Ex: created_by:~'user@example.com'|
|modified_by|String|Yes|Email of the user who last modified the classification. Exact match returns nothing on this field; use ~ with the full address or its full local part. Partial words do not match. Ex: modified_by:~'user@example.com'|

=== EXAMPLE USAGE ===

• name:~'credit' - Classifications with "credit" in the name (case-insensitive)
• created_at:>'2024-01-01' - Created after a date
• modified_at:>'2024-06-01' - Recently modified

=== SORTING ===

Supported sort fields: name.asc, name.desc, created_at.asc, created_at.desc, modified_at.desc

=== IMPORTANT NOTES ===
• Use single quotes around values: 'value'
• Use ~ operator for case-insensitive name matching
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
