package tools

// AIDR field names come from upstream's schema guide.
var (
	aidrAgentBrief      = []string{"Id", "SensorId", "AgentName", "AgentProductName", "Hostname", "LastExecutionTime", "FirstSeen", "LastSeen"}
	aidrSessionBrief    = []string{"Id", "ProductName", "Name", "Cim.AIAgentSession.sessionId", "Cim.AIAgentSession.modelsInvoked", "Cim.AIAgentSession.workingDirectory", "LastSeen"}
	aidrExecutionBrief  = []string{"AgenticSessionId", "aid", "AgenticModel", "AgenticWorkingDirectory", "AgenticInputTokens", "AgenticOutputTokens", "ContextProcessId", "timestamp"}
	aidrToolBrief       = []string{"Id", "Name", "SensorId", "FirstSeen", "LastSeen"}
	aidrToolUsageBrief  = []string{"AgenticSessionId", "aid", "AgenticToolName", "AgenticPath", "CommandLine", "Url", "AgenticDescription"}
	aidrSkillBrief      = []string{"Id", "SkillName", "SkillDescription", "SkillDirectoryHash", "FirstSeen", "LastSeen"}
	aidrSkillUsageBrief = []string{"AgenticSessionId", "aid", "AgenticSkill", "AgenticToolUseId"}
	aidrOSUserBrief     = []string{"Aid", "Username", "ObjectSid", "FirstSeen", "LastSeen"}
	aidrPromptBrief     = []string{"AgenticSessionId", "aid", "AgenticPrompt", "timestamp"}
	aidrDetectionBrief  = []string{"CompositeId", "AgentId", "Name", "SeverityName", "Severity", "RiskScore", "AgenticProductTagName", "Tactic", "Technique", "Status", "Timestamp"}
	aidrMCPServerBrief  = []string{"Id", "Cim.MCPServerName.serverName", "LastUsedTime", "FirstSeen", "LastSeen"}
	aidrInstallBrief    = []string{"Id", "SensorId", "Hostname", "AgentName", "AgentProductName", "AgentVersion", "InstallSource", "BinaryPath", "LastSeen"}
	aidrModelBrief      = []string{"Id", "Cim.AIModelName.modelName", "LastUsedTime", "FirstSeen", "LastSeen"}

	studioAgentBrief   = []string{"id", "template_id", "active_version.name", "active_version.model", "published_version_ids", "created_date"}
	studioVersionBrief = []string{"id", "agent_id", "name", "model", "is_published", "is_enabled", "created_at"}
	studioSpanBrief    = []string{"id", "trace_id", "span_type", "name", "status", "duration_ms", "start_time"}
)

const (
	aidrSchema = "falcon://guardian/inventory/schema-guide"
	aidrEvents = "falcon://guardian/events/query-guide"
)

// Upstream's composite guardian tools (report, pivot, inventory, session
// detail) are not ported: each is a fixed sequence of the plain actions
// below, which the model can run itself.
var aiTools = []Tool{
	{Name: "falcon_guardian", Group: "ai", Title: "AI agent detection (AIDR)",
		Guides: []string{"falcon://guardian/entities/schema-guide", "falcon://guardian/events/examples-guide"},
		Description: "Falcon AIDR: AI agents (Claude Code, Cursor, Copilot...) seen on hosts, and their sessions, tools, skills, prompts, process activity and detections. " +
			"These actions take no FQL filter or sort; they narrow by params, chiefly time_range (e.g. 24h, 7d; hours or days only; the event routes default to 2h and cap at 7d, the inventory routes allow up to 90d). " +
			"Ids: aid/sensor_id is a 32-hex HOST id (an agent's SensorId); an agent's Id is an opaque record token; session_id is the AgenticSessionId UUID (or aisess:{aid}:{uuid}). " +
			"product takes a name like CLAUDE_CODE, never the numeric tag the API returns. Offsets above 1000 are refused; narrow time_range instead.",
		Actions: []Action{
			// Inventory. The queries return full records, so nothing is hydrated.
			{Name: "search_agents", Help: "AI agents; params time_range, product, hostname.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryAgentsV1", Params: []string{"time_range", "product", "hostname"}, Brief: aidrAgentBrief, Guide: aidrSchema},
			{Name: "get_agents", Help: "full agents by Id (ids), not by SensorId.", Kind: Get, Op: "entitiesAgentsV1"},
			{Name: "search_sessions", Help: "fleet-wide agent sessions (for one host use search_executions with aid); params time_range, product.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryAgentSessionsV1", Params: []string{"time_range", "product"}, Brief: aidrSessionBrief, Guide: aidrSchema},
			{Name: "get_sessions", Help: "full session records by Id (ids).", Kind: Get, Op: "entitiesAgentSessionsV1"},
			{Name: "search_tools", Help: "the tool catalog (sparse); params time_range, sensor_id.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryToolsV1", Params: []string{"time_range", "sensor_id"}, Brief: aidrToolBrief, Guide: aidrSchema},
			{Name: "get_tools", Help: "tool records by Id (ids).", Kind: Get, Op: "entitiesToolsV1"},
			{Name: "search_skills", Help: "skill definitions found on hosts; params time_range, name_filter.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "querySkillsV1", Params: []string{"time_range", "name_filter"}, Brief: aidrSkillBrief, Guide: aidrSchema},
			{Name: "get_skills", Help: "skill records by Id (ids).", Kind: Get, Op: "entitiesSkillsV1"},
			{Name: "search_os_users", Help: "OS accounts that ran agents; params time_range, aid, username, object_sid.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryAgentOSUsersV1", Params: []string{"time_range", "aid", "username", "object_sid"}, Brief: aidrOSUserBrief, Guide: aidrSchema},
			{Name: "get_os_user", Help: "one OS user record; params aid and username, both required.", Kind: Aggregate, NoFilter: true,
				Op: "entitiesAgentOSUsersV1", Params: []string{"aid", "username"}},
			{Name: "search_mcp_servers", Help: "MCP server names agents connected to, fleet-wide; params time_range.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryMcpServerNamesV1", Params: []string{"time_range"}, Brief: aidrMCPServerBrief, Guide: aidrSchema},
			{Name: "search_installs", Help: "agent installations on hosts; params time_range, sensor_id, product, hostname.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryAgentInstallationsV1", Params: []string{"time_range", "sensor_id", "product", "hostname"}, Brief: aidrInstallBrief, Guide: aidrSchema},
			{Name: "get_installs", Help: "install records by Id (ids).", Kind: Get, Op: "entitiesAgentInstallationsV1"},
			{Name: "search_models", Help: "LLM model names seen fleet-wide; params time_range.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryModelNamesV1", Params: []string{"time_range"}, Brief: aidrModelBrief, Guide: aidrSchema},
			{Name: "get_models", Help: "model records by Id (ids).", Kind: Get, Op: "entitiesModelNamesV1"},

			// Events: per-invocation activity.
			{Name: "search_executions", Help: "agent process runs with model and token counts (the per-host session view); params time_range, aid, session_id.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryExecutionsV1", Params: []string{"time_range", "aid", "session_id"}, Brief: aidrExecutionBrief, Guide: aidrSchema},
			{Name: "get_executions", Help: "executions of one session (ids: one session_id); params context_process_id.", Kind: Get,
				Op: "entitiesExecutionsV1", IDs: "one:id", Params: []string{"context_process_id"}},
			{Name: "search_tool_usage", Help: "tool calls (Bash, Read, WebFetch...); params time_range, tool_name (exact, case-sensitive), aid, session_id.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryToolUsageV1", Params: []string{"time_range", "tool_name", "aid", "session_id"}, Brief: aidrToolUsageBrief, Guide: aidrSchema},
			{Name: "search_skill_usage", Help: "skill invocations; params time_range, name (exact), aid, session_id.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "querySkillUsageV1", Params: []string{"time_range", "name", "aid", "session_id"}, Brief: aidrSkillUsageBrief, Guide: aidrSchema},
			{Name: "search_prompts", Help: "user prompt text; params time_range, session_id, aid.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryPromptsV1", Params: []string{"time_range", "session_id", "aid"}, Brief: aidrPromptBrief, Guide: aidrSchema},
			{Name: "search_detections", Help: "alerts involving an AI agent process; params time_range, agent_id (the 32-hex SensorId, not the agent Id), product.", Kind: Search, NoFilter: true, TotalIsEnd: true,
				Op: "queryDetectionsV1", Params: []string{"time_range", "agent_id", "product"}, Brief: aidrDetectionBrief, Guide: aidrEvents},

			// Graph of one session or process.
			{Name: "get_session_activity", Help: "graph of sessions (ids: session UUIDs or aisess: keys): tools, models, processes, MCP servers, child sessions.", Kind: Get,
				Op: "entitiesSessionActivityV1"},
			{Name: "get_process_tree", Help: "processes a session launched (ids: one session id); params depth.", Kind: Get,
				Op: "entitiesProcessTreeV1", IDs: "one:id", Params: []string{"depth"}},
			{Name: "get_network_events", Help: "network connections of a session (ids: one session id).", Kind: Get, Op: "entitiesNetworkEventsV1", IDs: "one:id"},
			{Name: "get_file_events", Help: "files written by a session's processes (ids: one session id).", Kind: Get, Op: "entitiesFileEventsV1", IDs: "one:id"},
			{Name: "get_classified_file_access", Help: "Data Protection-classified files a process touched (ids: one process vertex id pid:{aid}:{upid}).", Kind: Get,
				Op: "entitiesClassifiedFileAccessV1", IDs: "one:id"},

			// Aggregates: fixed server-side grouping, at most 500 groups.
			{Name: "aggregate_agents", Help: "agent counts by product tag; params time_range.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateAgentsV1", Params: []string{"time_range"}, Guide: aidrEvents},
			{Name: "aggregate_sessions", Help: "session counts by product tag (count is a string); params time_range, product.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateAgentSessionsV1", Params: []string{"time_range", "product"}, Guide: aidrEvents},
			{Name: "aggregate_detections", Help: "Agentic Threat Score: max severity per (AgentId, AgenticProductTag); join to agents on both SensorId and AgentProduct; params time_range, agent_id, product.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateDetectionsV1", Params: []string{"time_range", "agent_id", "product"}, Guide: aidrEvents},
			{Name: "aggregate_tools", Help: "tool counts by name; params time_range, sensor_id.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateToolsV1", Params: []string{"time_range", "sensor_id"}, Guide: aidrEvents},
			{Name: "aggregate_skills", Help: "most-used skills {SkillName, count}; params time_range, name_filter.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateSkillsV1", Params: []string{"time_range", "name_filter"}, Guide: aidrEvents},
			{Name: "aggregate_tool_usage", Help: "tool-call counts; params time_range, session_id, aid.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateToolUsageV1", Params: []string{"time_range", "session_id", "aid"}, Guide: aidrEvents},
			{Name: "aggregate_skill_usage", Help: "skill-invocation counts; params time_range, session_id, aid.", Kind: Aggregate, NoFilter: true,
				Op: "aggregateSkillUsageV1", Params: []string{"time_range", "session_id", "aid"}, Guide: aidrEvents},
		}},
	{Name: "falcon_agentworks", Group: "ai", Title: "Charlotte AI agents",
		Description: "Charlotte AI AgentWorks (Agentic Studio): custom agents, their versions, and the trace spans of their runs. Invoking an agent is a separate, opt-in capability.",
		Actions: []Action{
			{Name: "search_agents", Help: "agents matching filter, e.g. template_id:'ioc-review-agent'; sort created_date.", Kind: Search,
				Op: "QueryAgentsV2", Hydrate: "GetAgentsV2", Brief: studioAgentBrief, Guide: "falcon://agentworks/agents/fql-guide"},
			{Name: "get_agents", Help: "full agents by id (ids).", Kind: Get, Op: "GetAgentsV2"},
			{Name: "search_agent_versions", Help: "agent versions matching filter, e.g. agent_id:'<id>'+is_published:true; sort created_at.", Kind: Search,
				Op: "QueryAgentVersionsV1", Hydrate: "GetAgentVersionsV1", Brief: studioVersionBrief, Guide: "falcon://agentworks/agent-versions/fql-guide"},
			{Name: "get_agent_versions", Help: "full agent versions by id (ids).", Kind: Get, Op: "GetAgentVersionsV1"},
			{Name: "search_spans", Help: "run trace spans; usually filter trace_id:'<ai_trace_id of an invocation>'; start_time only reaches the last 90 days; sort start_time.", Kind: Search,
				Op: "QueriesSpansV1", Hydrate: "EntitiesSpansV1", Brief: studioSpanBrief, Guide: "falcon://agentworks/spans/fql-guide"},
			{Name: "get_spans", Help: "full spans by id (ids).", Kind: Get, Op: "EntitiesSpansV1"},
			{Name: "get_invocation", Help: "the state of one agent invocation (ids: one invocation id): status, conversation, ai_trace_id, pending tool approvals.", Kind: Get,
				Op: "GetAgentInvocationV3", IDs: "one:id"},
		}},
}
