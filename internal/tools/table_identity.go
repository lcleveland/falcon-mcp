package tools

var idpRuleBrief = []string{"_id", "name", "enabled", "simulationMode", "ruleAction.action", "templateId"}

const idpMutationHelp = "; params mutation (the name), body its input object, e.g. {entityQuery: {samAccountNames: [\"jdoe\"], domains: [\"CORP.TLD\"]}}. " +
	"Query __schema or __type(name: \"<Input type>\") with investigate_entity for the input's fields. Entity queries must match at most 1000 entities."

var identityTools = []Tool{
	{Name: "falcon_identity", Group: "identity", Title: "Identity Protection",
		Description: "Falcon Identity Protection: users, endpoints and service accounts, their risk, and authentication activity, through its GraphQL API; and its policy rules.",
		Actions: []Action{
			{Name: "investigate_entity", Help: "run a GraphQL query document (query, optional variables), e.g. " +
				"{entities(types: [USER], first: 5) {nodes {primaryDisplayName riskScore}}}. Mutations are refused: use triage or tune.",
				Kind: Custom, Op: graphqlOp, Run: identityQuery, Inputs: []string{"query", "variables"}},
			{Name: "triage", Help: "run an Identity GraphQL mutation: addCommentToIncident, setIncidentState, addEntitiesToWatchList, removeEntitiesFromWatchList, markEntities or unmarkEntities" + idpMutationHelp,
				Kind: Write, Capability: "triage", Op: graphqlOp, Inputs: []string{"body"}, Params: []string{"mutation"}, Send: identityMutation("triage")},
			{Name: "tune", Help: "run an Identity GraphQL mutation that changes what is flagged: classifyUserEntities, classifyEndpointEntities, add/remove/clearUserEntityAuthorizers, add/removeManualAssociations, setEntityLinkedAccounts, add/removeFromTrafficInspectionExclusionList" + idpMutationHelp,
				Kind: Write, Capability: "detection-remove", Op: graphqlOp, Inputs: []string{"body"}, Params: []string{"mutation"}, Send: identityMutation("detection-remove")},

			{Name: "search_rules", Help: "Identity policy rules; params enabled, simulation_mode (true|false), name. Not paged: every match comes back.", Kind: Search, NoFilter: true,
				Op: "get_policy_rules_query", Hydrate: "get_policy_rules", Params: []string{"enabled", "simulation_mode", "name"}, Brief: idpRuleBrief},
			{Name: "get_rules", Help: "full Identity policy rules by id (ids): conditions, action, notifications.", Kind: Get, Op: "get_policy_rules"},
			// Rules gate access (block, MFA, allow), like firewall rule groups.
			{Name: "create_rule", Help: "create an Identity policy rule; body as get_rules returns one, without _id: {name, enabled, simulationMode, ruleConditions, ruleAction, emailNotification, indicatorNotification}. " +
				"Falcon has no rule update: to change a rule (e.g. simulationMode false to enforce), get it, create the changed copy, then delete_rules the old one.",
				Kind: Write, Capability: "fleet-config", Op: "post_policy_rules", Inputs: []string{"body"}, Brief: idpRuleBrief, Send: entity("", false, false)},
			{Name: "delete_rules", Help: "delete Identity policy rules by id (ids).",
				Kind: Write, Capability: "fleet-config", Op: "delete_policy_rules", Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(false)},
		}},
}
