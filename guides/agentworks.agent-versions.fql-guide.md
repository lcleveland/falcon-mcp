Falcon Query Language (FQL) - Search AgentWorks Agent Versions Guide

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
• * = wildcard matching (not supported on all fields — see endpoint-specific notes below)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' or ['exact_value'] for exact match
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format) or relative: 'now-7d', 'now-24h' (lowercase, single-quoted)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition (e.g., platform_name:'Windows'+status:'normal')
• , = OR condition (e.g., severity_name:'Critical',severity_name:'High')
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.
Values must be single-quoted. Relative dates must be lowercase ('now-7d' not 'NOW-7d').

=== falcon_search_agentworks_agent_versions FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|agent_id|String|No|ID of the parent agent. The primary way to list a single agent's versions. Ex: agent_id:'467e856f-0000-1111-2222-333344445555'|
|name|String|No|Exact version name. Wildcards are NOT supported here (name:'x*' returns 0). Ex: name:'IOC Review Agent'|
|model|String|No|Model backing the version. Ex: model:'bedrock.claude-3-7-sonnet'|
|is_published|Boolean|No|Whether the version is published. Quoted or unquoted both work. Ex: is_published:true|
|is_enabled|Boolean|No|Whether the version is enabled. Ex: is_enabled:true|
|created_at|Timestamp|Yes|When the version was created. Range operators work. Ex: created_at:>'2026-01-01'|

=== IMPORTANT NOTES ===
• Use single quotes around string values: 'value'
• Wildcards (*) are NOT supported here (e.g. name:'x*' returns 0 results) — use
  exact names.
• Booleans work quoted or unquoted: is_published:true
• Dates support range operators: created_at:>'2026-01-01'
• sort supports: created_at

=== COMMON FILTER EXAMPLES ===
• All versions of one agent: agent_id:'467e856f-...'
• Published versions only: is_published:true
• Versions on a model: model:'bedrock.claude-3-7-sonnet'
