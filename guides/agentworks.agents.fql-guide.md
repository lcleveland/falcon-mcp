Falcon Query Language (FQL) - Search AgentWorks Agents Guide

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

=== falcon_search_agentworks_agents FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|template_id|String|No|ID of the agent template the agent was created from. Ex: template_id:'ioc-review-agent'|
|active_version.model|String|No|Model backing the agent's active version. This is a nested field; the top-level agent record has no filterable name/model of its own. Ex: active_version.model:'bedrock.claude-4-6-sonnet'|
|published_version_ids|String|No|Matches agents that publish a given agent-version ID. Ex: published_version_ids:'a1b2c3d4-0000-1111-2222-333344445555'|

=== IMPORTANT NOTES ===
• Use single quotes around string values: 'value'
• The agent record has no top-level name/model — filter the model via the nested
  active_version.model field.
• Wildcards (*) are not supported on these fields.
• sort supports: created_date

=== COMMON FILTER EXAMPLES ===
• Agents on a specific model: active_version.model:'bedrock.claude-4-6-sonnet'
• Agents from a template: template_id:'ioc-review-agent'
