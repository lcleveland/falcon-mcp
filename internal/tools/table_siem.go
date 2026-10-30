package tools

import (
	"errors"
	"net/url"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

var (
	correlationRuleBrief = []string{"id", "rule_id", "name", "status", "state", "severity", "tactic", "technique", "created_on", "last_updated_on"}
	workflowDefBrief     = []string{"id", "name", "enabled", "version", "trigger.type", "trigger.name", "has_validation_errors", "last_modified_timestamp"}
	workflowExecBrief    = []string{"execution_id", "definition_id", "definition_name", "definition_version", "status", "start_timestamp", "end_timestamp", "trigger.ui_status"}
	scheduledReportBrief = []string{"id", "name", "type", "status", "description", "user_id", "last_execution.status", "last_execution.last_updated_on", "next_execution_on"}
	reportExecBrief      = []string{"id", "scheduled_report_id", "type", "status", "created_on", "last_updated_on", "expiration_on"}
)

var siemTools = []Tool{
	{Name: "falcon_ngsiem", Group: "siem", Title: "Next-Gen SIEM search",
		Description: "Next-Gen SIEM (LogScale) event search in CQL over Falcon and third-party data.",
		Actions: []Action{
			{Name: "search", Help: "run a CQL query (query) over repository between start and end, e.g. " +
				"#event_simpleName=ProcessRollup2 | groupBy([ComputerName]) | head(10). Waits up to about 25 s; " +
				"if the job is still running it returns done=false and next_cursor, which resumes waiting.",
				Kind: Custom, Op: "StartSearchV1", Run: ngsiemSearch, Guide: "falcon://ngsiem/search/cql-guide",
				Inputs: []string{"query", "repository", "start", "end", "cursor"}},
		}},
	{Name: "falcon_correlation_rule", Group: "siem", Title: "Correlation rules",
		Description: "Next-Gen SIEM correlation rules: scheduled detection searches with severity and MITRE mapping. " +
			"To create, update or delete a rule, call falcon_api with entities_rules_post_v1 (detection-add), entities_rules_patch_v1 or entities_rules_delete_v1 (detection-remove).",
		Actions: []Action{
			{Name: "search", Help: "correlation rules matching filter, e.g. status:'active'; add state:'published' for one row per rule; sort created_on|desc or last_updated_on|desc; params q (free text). One rule: filter rule_id:'...'.", Kind: Search,
				Op: "combined_rules_get_v2", Params: []string{"q"}, Brief: correlationRuleBrief, Guide: "falcon://correlation-rules/search/fql-guide"},
		}},
	{Name: "falcon_workflow", Group: "siem", Title: "Workflows",
		Description: "Falcon Fusion SOAR workflows: definitions and their execution history. Running a workflow is a separate, opt-in capability.",
		Actions: []Action{
			{Name: "search_definitions", Help: "workflow definitions matching filter; match names with name.raw, e.g. name.raw:*'*Contain*'; sort with a dot, e.g. last_modified_timestamp.desc (pipe is rejected). Records are large: narrow the filter.", Kind: Search,
				Op: "WorkflowDefinitionsCombined", Brief: workflowDefBrief, Guide: "falcon://fusion/workflow-definitions/fql-guide"},
			{Name: "export", Help: "one workflow definition as YAML text (ids: one definition id), the form import takes; params sanitize=true strips tenant-specific values.", Kind: Get,
				Op: "WorkflowDefinitionsExport", IDs: "one:id", Params: []string{"sanitize"}},
			{Name: "search_executions", Help: "workflow runs matching filter, e.g. ui_status:'Failed'+started_timestamp:>'now-7d'; sort e.g. started_timestamp.desc; params skip_fields (comma-joined: trigger,activities,flows,submodels) to shrink records.", Kind: Search,
				Op: "WorkflowExecutionsCombined", Params: []string{"skip_fields"}, Brief: workflowExecBrief, Guide: "falcon://fusion/workflow-executions/fql-guide"},
			{Name: "get_execution_results", Help: "one execution with every activity's result (ids: one execution id); params skip_fields (comma-joined) to shrink it.", Kind: Get,
				Op: "WorkflowExecutionResults", IDs: "one:ids", Params: []string{"skip_fields"}},
			{Name: "execute", Help: "run an on-demand workflow; params definition_id or name, and key (deduplicates runs); body is the trigger input the workflow expects. " +
				"It does whatever the workflow does, which may include containment. Workflows have no comment field: the reason is audit-logged only.",
				Kind: Write, Capability: "workflows", Op: "WorkflowExecute", Inputs: []string{"body"}, Params: []string{"definition_id", "name", "key"}, Send: workflowExecute},
			{Name: "import", Help: "create a workflow from a YAML definition (body: the YAML text, as an export returns it); params name (overrides the YAML's), validate_only. " +
				"validate_only=true skips saving but does not catch structural errors (an unknown trigger or action, a next naming a missing node): it returns resources [{parameters: null}] for valid and invalid definitions alike. The reliable check is a real import (imports arrive disabled), then enable it and inspect its first execution with search_executions and get_execution_results. " +
				"Falcon creates and edits workflows only as YAML. An imported workflow runs on its trigger if enabled.",
				Kind: Write, Capability: "workflows", Op: "WorkflowDefinitionsImport", Inputs: []string{"body"}, Params: []string{"name", "validate_only"}, Brief: workflowDefBrief, Send: workflowImport},
			{Name: "update", Help: "replace a workflow definition; body is the whole definition as JSON, with its id (as search_definitions returns it, fields id, name, description, trigger, actions, conditions, enabled); params validate_only. " +
				"validate_only=true skips saving but does not catch structural errors (an unknown trigger or action, a next naming a missing node): it returns resources [{parameters: null}] for valid and invalid definitions alike. The reliable check is to import the definition as a new workflow (it arrives disabled) and inspect its first execution. Fields left out are dropped from the workflow.",
				Kind: Write, Capability: "workflows", Op: "WorkflowDefinitionsUpdate", Inputs: []string{"body"}, Params: []string{"validate_only"}, Brief: workflowDefBrief, Send: workflowUpdate},
			{Name: "enable", Help: "enable workflow definitions by id (ids); they run on their next trigger event. Imports always arrive disabled.",
				Kind: Write, Capability: "workflows", Op: "WorkflowDefinitionsAction", Target: TargetIDs, Send: workflowAction("enable")},
			{Name: "disable", Help: "disable workflow definitions by id (ids); in-flight runs finish, new trigger events are ignored.",
				Kind: Write, Capability: "workflows", Op: "WorkflowDefinitionsAction", Target: TargetIDs, Send: workflowAction("disable")},
			{Name: "delete", Help: "delete workflow definitions, with every version, by id (ids). There is no undo: export first to keep a copy.",
				Kind: Write, Capability: "workflows", Op: "WorkflowDefinitionsDelete", Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(false)},
		}},
	{Name: "falcon_report", Group: "siem", Title: "Scheduled reports",
		Description: "Scheduled reports and scheduled searches, and their executions. Launching a report is a separate, opt-in capability.",
		Actions: []Action{
			{Name: "search", Help: "scheduled reports and searches matching filter, e.g. type:'event_search' or status:'ACTIVE'; sort e.g. last_execution_on|desc; params q (free text).", Kind: Search,
				Op: "scheduled_reports_query", Hydrate: "scheduled_reports_get", Params: []string{"q"}, Brief: scheduledReportBrief, Guide: "falcon://scheduled-reports/search/fql-guide"},
			{Name: "get", Help: "full scheduled reports by id (ids).", Kind: Get, Op: "scheduled_reports_get"},
			{Name: "search_executions", Help: "report executions matching filter, e.g. scheduled_report_id:'...'+status:'DONE'; sort e.g. created_on|desc; params q (free text).", Kind: Search,
				Op: "report_executions_query", Hydrate: "report_executions_get", Params: []string{"q"}, Brief: reportExecBrief, Guide: "falcon://scheduled-reports/executions/search/fql-guide"},
			{Name: "get_executions", Help: "full report executions by id (ids).", Kind: Get, Op: "report_executions_get"},
			{Name: "download_execution", Help: "the results of one DONE execution (ids: one execution id), as JSON or CSV text; PDF reports are refused.", Kind: Get,
				Op: "report_executions_download_get", IDs: "one:ids"},
			{Name: "launch", Help: "run scheduled report id now; the reason is audit-logged only.",
				Kind: Write, Capability: "workflows", Op: "scheduled_reports_launch", Inputs: []string{"id"}, Send: reportLaunch},
		}},
}

func workflowExecute(w WriteCall) (falcon.Params, error) {
	if w.Values.Get("definition_id") == "" && w.Values.Get("name") == "" {
		return falcon.Params{}, errors.New("this action needs params definition_id or name, the workflow to run")
	}
	body := w.Body
	if body == nil {
		body = map[string]any{}
	}
	return falcon.Params{Query: w.Values, Body: body}, nil
}

func workflowImport(w WriteCall) (falcon.Params, error) {
	yaml, _ := w.Body.(string)
	if strings.TrimSpace(yaml) == "" {
		return falcon.Params{}, errors.New("this action needs body: the workflow's YAML definition, as text")
	}
	return falcon.Params{Query: w.Values, Body: falcon.Multipart{FileName: "workflow.yaml", FilePart: "data_file", File: []byte(yaml)}}, nil
}

func workflowUpdate(w WriteCall) (falcon.Params, error) {
	def, _ := w.Body.(map[string]any)
	if id, _ := def["id"].(string); id == "" {
		return falcon.Params{}, errors.New("this action needs body: the whole workflow definition, with its id")
	}
	return falcon.Params{Query: w.Values, Body: def}, nil
}

func workflowAction(name string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		return falcon.Params{Query: url.Values{"action_name": {name}}, Body: map[string]any{"ids": w.Targets}}, nil
	}
}

func reportLaunch(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errors.New("this action needs id, the scheduled report id")
	}
	return falcon.Params{Body: []map[string]string{{"id": w.ID}}}, nil
}
