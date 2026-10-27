package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

const graphqlOp = "post_graphql"

// identityQuery runs a GraphQL query against Identity Protection. The route
// takes mutations too and its scope is a write scope, so anything but a
// query is refused here; mutations go through identityMutation.
func identityQuery(ctx context.Context, d Deps, in Input) (map[string]any, error) {
	if strings.TrimSpace(in.Query) == "" {
		return nil, errors.New("this action needs query, a GraphQL query document")
	}
	if op := graphqlWrite(in.Query); op != "" {
		return nil, fmt.Errorf("GraphQL %s documents are refused here: use the triage or tune actions", op)
	}
	body := map[string]any{"query": in.Query}
	if len(in.Variables) > 0 {
		body["variables"] = in.Variables
	}
	env, err := d.call(ctx, graphqlOp, falcon.Params{Body: body})
	if err != nil {
		return nil, err
	}
	out := capObject(times(env.Data))
	if err := graphqlErr(env); err != nil {
		out["errors"] = err.Error()
	}
	return out, nil
}

// graphqlErr is the errors a GraphQL reply carries with its 200.
func graphqlErr(env *envelope) error {
	if len(env.Errors) == 0 {
		return nil
	}
	msgs := make([]string, len(env.Errors))
	for i, e := range env.Errors {
		msgs[i] = e.Message
	}
	return fmt.Errorf("GraphQL: %s", strings.Join(msgs, "; "))
}

// Selections for the three result types Identity mutations return.
const (
	bulkResult     = "updatedEntities {entityId primaryDisplayName secondaryDisplayName watched markTime} failures {entityIds errorDetails {message}}"
	incidentResult = "incident {incidentId lifeCycleStage}"
	ipResult       = "ip status protocol port"
)

type mutation struct{ input, result string }

// Identity mutations by capability. Watchlist, marks and incidents are
// triage; classifications, authorizers, associations, linked accounts and
// traffic-inspection exclusions change what Identity Protection flags.
var identityMutations = map[string]map[string]mutation{
	"triage": {
		"addCommentToIncident":        {"AddCommentToIncidentInput", incidentResult},
		"setIncidentState":            {"SetStateIncidentInput", incidentResult},
		"addEntitiesToWatchList":      {"BulkEntityActionInput", bulkResult},
		"removeEntitiesFromWatchList": {"BulkEntityActionInput", bulkResult},
		"markEntities":                {"BulkEntityActionInput", bulkResult},
		"unmarkEntities":              {"BulkEntityActionInput", bulkResult},
	},
	"detection-remove": {
		"classifyUserEntities":                     {"ClassifyUserEntityInput", bulkResult},
		"classifyEndpointEntities":                 {"ClassifyEndpointEntityInput", bulkResult},
		"addUserEntityAuthorizers":                 {"AddUserEntityAuthorizerInput", bulkResult},
		"removeUserEntityAuthorizers":              {"RemoveUserEntityAuthorizerInput", bulkResult},
		"clearUserEntityAuthorizers":               {"BulkEntityActionInput", bulkResult},
		"addManualAssociations":                    {"AddManualAssociationsInput", bulkResult},
		"removeManualAssociations":                 {"RemoveManualAssociationsInput", bulkResult},
		"setEntityLinkedAccounts":                  {"SetEntityLinkedAccountInput", bulkResult},
		"addToTrafficInspectionExclusionList":      {"IpInfoList", ipResult},
		"removeFromTrafficInspectionExclusionList": {"IpList", ipResult},
	},
}

// idpRuleKeys is the rule creation format. get_rules returns another shape
// (ruleAction, ruleConditions), which Falcon refuses with a misleading
// "must be BLOCK"; and Falcon accepts any other condition (sourceUser
// accountType, say) and drops it silently, which can leave a rule matching
// everyone. So the body is checked here first.
var idpRuleKeys = []string{"name", "enabled", "simulationMode", "action", "trigger", "activity", "sourceUser", "sourceEndpoint", "destination"}

// idpRuleConditions are the conditions each creation-format key takes;
// every condition is {include: [...], exclude: [...]}.
var idpRuleConditions = map[string][]string{
	"activity":       {"accessType", "accessTypeCustom"},
	"sourceUser":     {"entityId", "groupMembership"},
	"sourceEndpoint": {"entityId", "groupMembership"},
	"destination":    {"entityId", "groupMembership"},
}

const idpRuleFormat = "{name, enabled, simulationMode, action (e.g. BLOCK, MFA, ALLOW), trigger (e.g. access), activity: {accessType, accessTypeCustom}, " +
	"sourceUser, sourceEndpoint, destination: each {entityId, groupMembership}, every condition {include: [...], exclude: [...]}}; " +
	"it has no notification fields, and no account-type or other condition: those exist only in the console"

func idpRuleCreate(w WriteCall) (falcon.Params, error) {
	b, err := object(w.Body)
	if err != nil {
		return falcon.Params{}, err
	}
	for k, v := range b {
		if !slices.Contains(idpRuleKeys, k) {
			return falcon.Params{}, fmt.Errorf("body key %q is not in the rule creation format, which differs from what get_rules returns; create_rule takes %s", k, idpRuleFormat)
		}
		conds, ok := idpRuleConditions[k]
		if !ok {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return falcon.Params{}, fmt.Errorf("body %s must be an object; create_rule takes %s", k, idpRuleFormat)
		}
		for c, cv := range m {
			if !slices.Contains(conds, c) {
				return falcon.Params{}, fmt.Errorf("%s.%s is not a condition the API can create (Falcon would drop it silently); %s takes only %s", k, c, k, strings.Join(conds, ", "))
			}
			leaf, ok := cv.(map[string]any)
			if !ok {
				return falcon.Params{}, fmt.Errorf("%s.%s must be {include: [...], exclude: [...]}", k, c)
			}
			for l := range leaf {
				if l != "include" && l != "exclude" {
					return falcon.Params{}, fmt.Errorf("%s.%s.%s: a condition takes only include and exclude", k, c, l)
				}
			}
		}
	}
	for _, k := range []string{"name", "action"} {
		if s, _ := b[k].(string); s == "" {
			return falcon.Params{}, fmt.Errorf("body needs %s, a string, in the rule creation format %s", k, idpRuleFormat)
		}
	}
	// An enforced rule that names no user, endpoint or destination acts on
	// every authentication its trigger and activity match.
	sim, _ := b["simulationMode"].(bool)
	if a := b["action"]; !sim && a != "ALLOW" && a != "ADD_TO_WATCH_LIST" && !slices.ContainsFunc([]string{"sourceUser", "sourceEndpoint", "destination"}, func(k string) bool {
		m, _ := b[k].(map[string]any)
		return len(m) > 0
	}) {
		return falcon.Params{}, fmt.Errorf("an enforced %v rule needs a sourceUser, sourceEndpoint or destination condition, or it applies to everyone; set simulationMode true to try it first", a)
	}
	return entity("", false, false)(w)
}

// identityMutation sends one listed mutation, params mutation, with body
// as its input. The document is built here, so no caller text reaches it
// but the input, which goes as a variable.
func identityMutation(capability string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		name := w.Values.Get("mutation")
		m, ok := identityMutations[capability][name]
		if !ok {
			return falcon.Params{}, fmt.Errorf("params mutation must be one of: %s", strings.Join(slices.Sorted(maps.Keys(identityMutations[capability])), ", "))
		}
		input, err := object(w.Body)
		if err != nil {
			return falcon.Params{}, err
		}
		doc := fmt.Sprintf("mutation($input: %s!) { %s(input: $input) { %s } }", m.input, name, m.result)
		return falcon.Params{Body: map[string]any{"query": doc, "variables": map[string]any{"input": input}}}, nil
	}
}

// graphqlWrite returns "mutation" or "subscription" if the document defines
// such an operation, else "". It reads keywords only outside every brace,
// bracket and parenthesis, skipping strings and comments; a document it
// cannot read cleanly counts as a write.
func graphqlWrite(doc string) string {
	depth := 0
	for i := 0; i < len(doc); i++ {
		switch c := doc[i]; {
		case c == '#':
			for i < len(doc) && doc[i] != '\n' {
				i++
			}
		case strings.HasPrefix(doc[i:], `"""`):
			end := -1
			for j := i + 3; j+3 <= len(doc); j++ {
				if doc[j] == '\\' && strings.HasPrefix(doc[j+1:], `"""`) {
					j += 3
					continue
				}
				if strings.HasPrefix(doc[j:], `"""`) {
					end = j
					break
				}
			}
			if end < 0 {
				return "mutation"
			}
			i = end + 2
		case c == '"':
			i++
			for i < len(doc) && doc[i] != '"' {
				if doc[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(doc) {
				return "mutation"
			}
		case c == '{' || c == '(' || c == '[':
			depth++
		case c == '}' || c == ')' || c == ']':
			if depth--; depth < 0 {
				return "mutation"
			}
		case depth == 0 && nameStart(c):
			j := i
			for j < len(doc) && (nameStart(doc[j]) || doc[j] >= '0' && doc[j] <= '9') {
				j++
			}
			if w := doc[i:j]; w == "mutation" || w == "subscription" {
				return w
			}
			i = j - 1
		}
	}
	return ""
}

func nameStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
