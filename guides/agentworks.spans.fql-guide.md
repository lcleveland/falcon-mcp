Falcon Query Language (FQL) - Search AgentWorks Spans Guide

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

=== falcon_search_agentworks_spans FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|trace_id|String|No|Trace the span belongs to. This is the primary use of the spans tool: pass an invocation's `ai_trace_id` here to retrieve that run's spans. Ex: trace_id:'a1b2c3d4-0000-1111-2222-333344445555'|
|span_type|String|No|Type of span. Values seen live include: llm, aw_agent, aiplatform_agent, aw_agent_response, aiplatform_agent_response, charlotteai_reply, charlotteai_agent. Ex: span_type:'llm'|
|status|String|No|Span status. Values: unset, ok, error. Ex: status:'error'|
|name|String|No|Exact span name. Ex: name:'llm'|
|duration_ms|Number|Yes|Span duration in milliseconds. Numeric operators work. Ex: duration_ms:>100|
|start_time|Timestamp|Yes|When the span started. Range operators work, but the API enforces a 90-day retention window: a start_time older than 90 days returns a 400. Ex: start_time:>'now-7d'|

=== IMPORTANT NOTES ===
• Spans total in the hundreds of thousands — ALWAYS filter, usually by trace_id.
• The invocation→spans link is trace_id only: pass an invocation's `ai_trace_id`
  as trace_id:'<value>' to see that run's spans.
• start_time is limited to the last 90 days (older values return a 400).
• Use single quotes around string values: 'value'
• sort supports: start_time

=== COMMON FILTER EXAMPLES ===
• One run's spans: trace_id:'<ai_trace_id from an invocation>'
• Errored LLM spans in a trace: trace_id:'...'+span_type:'llm'+status:'error'
• Slow spans in a trace: trace_id:'...'+duration_ms:>1000
