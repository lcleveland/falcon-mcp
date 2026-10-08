package tools

import (
	"errors"

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
		Description: "Next-Gen SIEM correlation rules: scheduled detection searches with severity and MITRE mapping.",
		Actions: []Action{
			{Name: "search", Help: "correlation rules matching filter, e.g. status:'active'; add state:'published' for one row per rule; sort created_on|desc or last_updated_on|desc; params q (free text). One rule: filter rule_id:'...'.", Kind: Search,
				Op: "combined_rules_get_v2", Params: []string{"q"}, Brief: correlationRuleBrief, Guide: "falcon://correlation-rules/search/fql-guide"},
		}},
	{Name: "falcon_workflow", Group: "siem", Title: "Workflows",
		Description: "Falcon Fusion SOAR workflows: definitions and their execution history. Running a workflow is a separate, opt-in capability.",
		Actions: []Action{
			{Name: "search_definitions", Help: "workflow definitions matching filter; match names with name.raw, e.g. name.raw:*'*Contain*'; sort with a dot, e.g. last_modified_timestamp.desc (pipe is rejected). Records are large: narrow the filter.", Kind: Search,
				Op: "WorkflowDefinitionsCombined", Brief: workflowDefBrief, Guide: "falcon://fusion/workflow-definitions/fql-guide"},
			{Name: "search_executions", Help: "workflow runs matching filter, e.g. ui_status:'Failed'+started_timestamp:>'now-7d'; sort e.g. started_timestamp.desc; params skip_fields (comma-joined: trigger,activities,flows,submodels) to shrink records.", Kind: Search,
				Op: "WorkflowExecutionsCombined", Params: []string{"skip_fields"}, Brief: workflowExecBrief, Guide: "falcon://fusion/workflow-executions/fql-guide"},
			{Name: "get_execution_results", Help: "one execution with every activity's result (ids: one execution id); params skip_fields (comma-joined) to shrink it.", Kind: Get,
				Op: "WorkflowExecutionResults", IDs: "one:ids", Params: []string{"skip_fields"}},
			{Name: "execute", Help: "run an on-demand workflow; params definition_id or name, and key (deduplicates runs); body is the trigger input the workflow expects. " +
				"It does whatever the workflow does, which may include containment. Workflows have no comment field: the reason is audit-logged only.",
				Kind: Write, Capability: "workflows", Op: "WorkflowExecute", Inputs: []string{"body"}, Params: []string{"definition_id", "name", "key"}, Send: workflowExecute},
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

func reportLaunch(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errors.New("this action needs id, the scheduled report id")
	}
	return falcon.Params{Body: []map[string]string{{"id": w.ID}}}, nil
}
