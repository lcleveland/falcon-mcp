package tools

var identityTools = []Tool{
	{Name: "falcon_identity", Group: "identity", Title: "Identity Protection",
		Description: "Falcon Identity Protection: users, endpoints and service accounts, their risk, and authentication activity, through its GraphQL API.",
		Actions: []Action{
			{Name: "investigate_entity", Help: "run a GraphQL query document (query, optional variables), e.g. " +
				"{entities(types: [USER], first: 5) {nodes {primaryDisplayName riskScore}}}. Mutations are refused.",
				Kind: Custom, Op: "post_graphql", Run: identityQuery, Inputs: []string{"query", "variables"}},
		}},
}
