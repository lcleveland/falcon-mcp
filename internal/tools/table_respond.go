package tools

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

var (
	alertBrief      = []string{"composite_id", "product", "display_name", "status", "severity_name", "device.hostname", "host_names", "tactic", "technique", "created_timestamp"}
	caseBrief       = []string{"id", "name", "status", "severity", "assigned_to", "created_timestamp", "updated_timestamp"}
	sessionBrief    = []string{"id", "device_id", "hostname", "user_id", "origin", "created_at", "updated_at"}
	quarantineBrief = []string{"id", "sha256", "state", "hostname", "username", "paths", "date_created", "date_updated"}
)

var respondTools = []Tool{
	{Name: "falcon_alert", Group: "respond", Title: "Alerts",
		Description: "Falcon alerts (endpoint detections and other alert types), newest first by default.",
		Actions: []Action{
			{Name: "search", Help: "alerts matching filter; sort e.g. created_timestamp.desc.", Kind: Search,
				Op: "GetQueriesAlertsV2", Hydrate: "PostEntitiesAlertsV2", IDs: "body:composite_ids", Brief: alertBrief,
				Guide: "falcon://detections/search/fql-guide"},
			{Name: "get", Help: "full alerts by composite id (ids).", Kind: Get, Op: "PostEntitiesAlertsV2", IDs: "body:composite_ids"},
			{Name: "aggregate", Help: "counts and buckets; body is a list of aggregation requests [{field, type (terms|date_histogram|count|...), filter, size, name}].", Kind: Aggregate,
				Op: "PostAggregatesAlertsV2", Guide: "falcon://detections/search/fql-guide"},
			{Name: "update", Help: "update alerts by composite id (ids), or by filter with confirm=<count>. params: update_status (new|in_progress|reopened|closed), " +
				"assign_to_uuid, assign_to_user_id, assign_to_name, unassign (true), append_comment, add_tag, remove_tag (a tag or a list), remove_tags_by_prefix. " +
				"Resolve with a tag: true_positive, false_positive or ignored. The reason is added as a comment.",
				Kind: Write, Capability: "triage", Op: "PatchEntitiesAlertsV3", Target: TargetIDs, Resolve: "GetQueriesAlertsV2", MaxIDs: 1000,
				Params: alertParams, Guide: "falcon://detections/search/fql-guide", Send: alertUpdate},
		}},
	{Name: "falcon_case", Group: "respond", Title: "Cases",
		Description: "Falcon cases: the investigation records that group alerts, events and notes.",
		Actions: []Action{
			{Name: "search", Help: "cases matching filter.", Kind: Search,
				Op: "queries_cases_get_v1", Hydrate: "entities_cases_post_v2", IDs: "body:ids", Brief: caseBrief,
				Guide: "falcon://cases/search/fql-guide"},
			{Name: "get", Help: "full cases by id (ids).", Kind: Get, Op: "entities_cases_post_v2", IDs: "body:ids"},
			{Name: "list_templates", Help: "case templates matching filter.", Kind: Search,
				Op: "queries_templates_get_v1", Hydrate: "entities_templates_get_v1", Brief: []string{"id", "name", "description", "status"}},
			{Name: "aggregate_slas", Help: "SLA buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_slas_post_v1",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_templates", Help: "template buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_templates_post_v1",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_access_tags", Help: "access-tag buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_access_tags_post_v1",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_notification_groups", Help: "notification-group buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_notification_groups_post_v2",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_file_details", Help: "file buckets for case ids (ids); body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_file_details_post_v1", TakesIDs: true,
				Guide: "falcon://cases/file-aggregates/fql-guide"},
			{Name: "create", Help: "create a case (case writes have no comment field: the reason is audit-logged only); body {name, description, severity, status, assigned_to_user_uuid, tags, template: {id}, evidence: {alerts: [{id}], events: [{id}]}}.",
				Kind: Write, Capability: "triage", Op: "entities_cases_put_v2", Inputs: []string{"body"}, Send: caseCreate},
			{Name: "update", Help: "update case id; body is the fields to set {name, description, severity, status, assigned_to_user_uuid, remove_user_assignment, custom_fields, template}.",
				Kind: Write, Capability: "triage", Op: "entities_cases_patch_v2", Inputs: []string{"id", "body"}, Send: caseUpdate},
			{Name: "add_alert_evidence", Help: "attach alerts by composite id (ids) to case id.",
				Kind: Write, Capability: "triage", Op: "entities_alert_evidence_post_v1", Target: TargetIDs, Inputs: []string{"id"}, Send: caseEvidence("alerts")},
			{Name: "add_event_evidence", Help: "attach events by id (ids) to case id.",
				Kind: Write, Capability: "triage", Op: "entities_event_evidence_post_v1", Target: TargetIDs, Inputs: []string{"id"}, Send: caseEvidence("events")},
			{Name: "add_tags", Help: "add tags to case id.",
				Kind: Write, Capability: "triage", Op: "entities_case_tags_post_v1", Inputs: []string{"id", "tags"}, Send: caseTags(true)},
			{Name: "remove_tags", Help: "remove tags from case id.",
				Kind: Write, Capability: "triage", Op: "entities_case_tags_delete_v1", Inputs: []string{"id", "tags"}, Send: caseTags(false)},
		}},
	{Name: "falcon_rtr", Group: "respond", Title: "Real Time Response", Guides: []string{"falcon://rtr/workflows/investigation-guide"},
		Description: "Real Time Response sessions and their audit trail, and, when the operator allows, read-only commands on hosts (rtr-read) " +
			"and active-responder commands on one host at a time (rtr-respond). RTR admin, runscript and library uploads are never available. " +
			"RTR has no comment fields: the reason is audit-logged only. Commands run asynchronously: poll the status action with the cloud_request_id they return.",
		Actions: []Action{
			{Name: "search_sessions", Help: "RTR sessions matching filter.", Kind: Search,
				Op: "RTR_ListAllSessions", Hydrate: "RTR_ListSessions", IDs: "body:ids", Brief: sessionBrief,
				Guide: "falcon://rtr/sessions/search/fql-guide"},
			{Name: "search_audit_sessions", Help: "the RTR audit trail: sessions with who ran what, matching filter.", Kind: Search,
				Op: "RTRAuditSessions", Brief: sessionBrief, Guide: "falcon://rtr/audit/sessions/search/fql-guide"},
			{Name: "aggregate_sessions", Help: "session buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "RTR_AggregateSessions",
				Guide: "falcon://rtr/sessions/aggregate-guide"},
			{Name: "get_session", Help: "full sessions by id (ids).", Kind: Get, Op: "RTR_ListSessions", IDs: "body:ids"},

			{Name: "init_session", Help: "open an RTR session on host id (a device id); returns its session_id. Sessions close after 10 idle minutes.",
				Kind: Write, Capability: "rtr-read", Op: "RTR_InitSession", Inputs: []string{"id"}, Send: rtrHost, Brief: rtrSessionBrief},
			{Name: "pulse_session", Help: "keep the RTR session on host id (a device id) open.",
				Kind: Write, Capability: "rtr-read", Op: "RTR_PulseSession", Inputs: []string{"id"}, Send: rtrHost, Brief: rtrSessionBrief},
			{Name: "delete_session", Help: "close RTR session id.",
				Kind: Write, Capability: "rtr-read", Op: "RTR_DeleteSession", Inputs: []string{"id"}, Send: rtrDeleteSession},
			{Name: "run_command", Help: "run a read-only command in RTR session id; command is one of: " + strings.Join(rtrRead, ", ") + " (users on Mac and Linux only). " + rtrQuoting,
				Kind: Write, Capability: "rtr-read", Op: "RTR_ExecuteCommand", Inputs: []string{"id", "command"}, Send: rtrRun("session_id")},
			{Name: "check_command_status", Help: "a run_command's status and output: ids [cloud_request_id], params sequence_id (0, then the next chunk).",
				Kind: Get, Capability: "rtr-read", Op: "RTR_CheckCommandStatus", IDs: "one:cloud_request_id", Params: []string{"sequence_id"}},
			{Name: "list_files", Help: "files collected in an RTR session (by get): ids [session_id]. Falcon needs the RTR write scope for this.",
				Kind: Get, Capability: "rtr-read", Op: "RTR_ListFilesV2", IDs: "one:session_id"},
			{Name: "init_batch", Help: "open RTR sessions on hosts by device id (ids); returns batch_id and each host's session. There is no batch delete: close them with delete_session, or let them idle out after 10 minutes.",
				Kind: Write, Capability: "rtr-read", Op: "BatchInitSessions", Target: TargetIDs, Send: rtrBatchInit},
			{Name: "pulse_batch", Help: "keep batch id's sessions open.",
				Kind: Write, Capability: "rtr-read", Op: "BatchRefreshSessions", Inputs: []string{"id"}, Send: rtrBatchRefresh},
			{Name: "run_batch_command", Help: "run a read-only command on every host in batch id and wait for the output (up to 30s); same commands as run_command. " + rtrQuoting,
				Kind: Write, Capability: "rtr-read", Op: "BatchCmd", Inputs: []string{"id", "command"}, Send: rtrRun("batch_id")},

			{Name: "run_responder_command", Help: "run an active-responder command on one host id (a device id), confirm=<hostname>, in a new session (returned as session_id; it idles out after 10 minutes); command is one of: " +
				strings.Join(rtrRespond, ", ") + ". put takes a file already in the put-files library.",
				Kind: Write, Capability: "rtr-respond", Op: "RTR_ExecuteActiveResponderCommand", Target: TargetHost, Inputs: []string{"command"}, Send: rtrRespondRun},
			{Name: "check_responder_status", Help: "a run_responder_command's status and output: ids [cloud_request_id], params sequence_id (0, then the next chunk).",
				Kind: Get, Capability: "rtr-respond", Op: "RTR_CheckActiveResponderCommandStatus", IDs: "one:cloud_request_id", Params: []string{"sequence_id"}},
		}},
	{Name: "falcon_quarantine", Group: "respond", Title: "Quarantined files",
		Description: "Files the Falcon sensor quarantined on hosts.",
		Actions: []Action{
			{Name: "search", Help: "quarantined files matching filter.", Kind: Search,
				Op: "QueryQuarantineFiles", Hydrate: "GetQuarantineFiles", IDs: "body:ids", Brief: quarantineBrief,
				Guide: "falcon://quarantine/files/search/fql-guide"},
			{Name: "get", Help: "full quarantined files by id (ids).", Kind: Get, Op: "GetQuarantineFiles", IDs: "body:ids"},
			{Name: "preview_actions", Help: "how many files a release, unrelease or delete by filter would touch; filter required.", Kind: Aggregate,
				Op: "ActionUpdateCount", Guide: "falcon://quarantine/files/search/fql-guide"},
			{Name: "release", Help: "put quarantined files back on their hosts and allow them to run, by id (ids), or by filter with confirm=<count>. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "UpdateQuarantinedDetectsByIds", Target: TargetIDs, Resolve: "QueryQuarantineFiles",
				Guide: "falcon://quarantine/files/search/fql-guide", Send: quarantine("release")},
			{Name: "unrelease", Help: "quarantine released files again, by id (ids), or by filter with confirm=<count>. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "UpdateQuarantinedDetectsByIds", Target: TargetIDs, Resolve: "QueryQuarantineFiles",
				Guide: "falcon://quarantine/files/search/fql-guide", Send: quarantine("unrelease")},
			{Name: "delete", Help: "delete quarantined files for good, by id (ids), or by filter with confirm=<count>. Cannot be undone. The reason is sent as the comment.",
				Kind: Write, Capability: "destructive", Op: "UpdateQuarantinedDetectsByIds", Target: TargetIDs, Resolve: "QueryQuarantineFiles",
				Guide: "falcon://quarantine/files/search/fql-guide", Send: quarantine("delete")},
		}},
}

// alertParams are the alert action parameters triage may set, in the order
// they are sent; append_comment stays last. Suppression and show_in_ui belong to other capabilities.
var alertParams = []string{"update_status", "assign_to_uuid", "assign_to_user_id", "assign_to_name", "unassign",
	"add_tag", "remove_tag", "remove_tags_by_prefix", "append_comment"}

func alertUpdate(w WriteCall) (falcon.Params, error) {
	if len(w.Values) == 0 {
		return falcon.Params{}, errors.New("this action needs params: the updates to make")
	}
	// The caller's comments and the reason go as one comment.
	comment := append(w.Values["append_comment"], "Reason: "+w.Reason)
	if len(comment) == 1 {
		comment = []string{w.Reason}
	}
	var ap []map[string]string
	for _, name := range alertParams[:len(alertParams)-1] {
		for _, v := range w.Values[name] {
			ap = append(ap, map[string]string{"name": name, "value": v})
		}
	}
	ap = append(ap, map[string]string{"name": "append_comment", "value": strings.Join(comment, "\n\n")})
	return falcon.Params{Body: map[string]any{"composite_ids": w.Targets, "action_parameters": ap}}, nil
}

func caseCreate(w WriteCall) (falcon.Params, error) {
	b, err := object(w.Body)
	return falcon.Params{Body: b}, err
}

func caseUpdate(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errNeedsCase
	}
	b, err := object(w.Body)
	return falcon.Params{Body: map[string]any{"id": w.ID, "fields": b}}, err
}

func caseEvidence(kind string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		if w.ID == "" {
			return falcon.Params{}, errNeedsCase
		}
		ev := make([]map[string]string, len(w.Targets))
		for i, id := range w.Targets {
			ev[i] = map[string]string{"id": id}
		}
		return falcon.Params{Body: map[string]any{"id": w.ID, kind: ev}}, nil
	}
}

func caseTags(add bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		switch {
		case w.ID == "":
			return falcon.Params{}, errNeedsCase
		case len(w.Tags) == 0:
			return falcon.Params{}, errNeedsTags
		case add:
			return falcon.Params{Body: map[string]any{"id": w.ID, "tags": w.Tags}}, nil
		}
		return falcon.Params{Query: url.Values{"id": {w.ID}, "tag": w.Tags}}, nil
	}
}

var errNeedsCase = errors.New("this action needs id, the case id")

func quarantine(action string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		return falcon.Params{Body: map[string]any{"action": action, "ids": w.Targets, "comment": w.Reason}}, nil
	}
}

// Each RTR capability runs only its own commands. An entry of two words
// also pins the subcommand: reg query reads, reg set does not. Admin
// commands (run, runscript, put-and-run, falconscript) are on neither list.
var (
	// rtrRead matches the read-only commands Falcon offers a session (its
	// init scripts list), less eventlog export and backup, which write files.
	rtrRead    = []string{"cat", "cd", "env", "eventlog list", "eventlog view", "filehash", "getsid", "ipconfig", "ls", "mount", "netstat", "ps", "pwd", "reg query", "users"}
	rtrRespond = []string{"cp", "get", "kill", "memdump", "mkdir", "mv", "put", "reg delete", "reg load", "reg set", "reg unload", "rm", "umount", "xmemdump", "zip"}
)

// rtrSessionBrief drops the scripts list, ~10KB of command help, from a
// session's reply.
var rtrSessionBrief = []string{"session_id", "device_id", "platform", "pwd", "offline_queued", "existing_aid_sessions", "created_at"}

// rtrQuoting is help for RTR command lines: Falcon splits arguments on spaces.
const rtrQuoting = `Quote paths that contain spaces, e.g. reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" ProductName.`

// rtrCommand checks a command line against an allowlist and returns its
// base command. Control characters are refused: a second line must not
// ride in behind an allowed first one.
func rtrCommand(allow []string, command string) (string, error) {
	if strings.ContainsFunc(command, unicode.IsControl) {
		return "", errors.New("command must be one line, with no control characters")
	}
	f := strings.Fields(command)
	for _, e := range allow {
		if ef := strings.Fields(e); len(f) >= len(ef) && slices.Equal(f[:len(ef)], ef) {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("command %q is not allowed here; allowed: %s", strings.TrimSpace(command), strings.Join(allow, ", "))
}

func rtrHostParams(device string) falcon.Params {
	return falcon.Params{Body: map[string]any{"device_id": device, "origin": "falcon-mcp", "queue_offline": false}}
}

func rtrHost(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errors.New("this action needs id, the host's device id")
	}
	return rtrHostParams(w.ID), nil
}

func rtrDeleteSession(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errors.New("this action needs id, the session id")
	}
	return falcon.Params{Query: url.Values{"session_id": {w.ID}}}, nil
}

func rtrBatchInit(w WriteCall) (falcon.Params, error) {
	return falcon.Params{Body: map[string]any{"host_ids": w.Targets, "queue_offline": false}}, nil
}

func rtrBatchRefresh(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errors.New("this action needs id, the batch id")
	}
	return falcon.Params{Body: map[string]any{"batch_id": w.ID}}, nil
}

// rtrRun runs a read-only command in the session or batch named by id;
// key says which.
func rtrRun(key string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		base, err := rtrCommand(rtrRead, w.Command)
		if err != nil {
			return falcon.Params{}, err
		}
		if w.ID == "" {
			return falcon.Params{}, errors.New("this action needs id, the " + strings.TrimSuffix(key, "_id") + " id")
		}
		return falcon.Params{Body: map[string]any{key: w.ID, "base_command": base, "command_string": strings.TrimSpace(w.Command), "persist": false}}, nil
	}
}

// rtrRespondRun opens a session on the confirmed host and runs the command
// there, so the command cannot land on another host's session.
func rtrRespondRun(w WriteCall) (falcon.Params, error) {
	base, err := rtrCommand(rtrRespond, w.Command)
	if err != nil {
		return falcon.Params{}, err
	}
	host := w.Targets[0]
	env, err := w.get("RTR_InitSession", rtrHostParams(host))
	if err != nil {
		return falcon.Params{}, fmt.Errorf("opening an RTR session on %s: %w", host, err)
	}
	var session string
	if l := list(env.Resources); len(l) > 0 {
		m, _ := l[0].(map[string]any)
		session, _ = m["session_id"].(string)
	}
	if session == "" {
		return falcon.Params{}, fmt.Errorf("opening an RTR session on %s returned no session_id", host)
	}
	return falcon.Params{Body: map[string]any{"session_id": session, "device_id": host, "base_command": base, "command_string": strings.TrimSpace(w.Command), "persist": false}}, nil
}
