package tools

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lcleveland/falcon-mcp/internal/config"
)

const (
	rtrCommandPath = "/real-time-response/entities/command/v1"
	rtrResponder   = "/real-time-response/entities/active-responder-command/v1"
	rtrSessions    = "/real-time-response/entities/sessions/v1"
	rtrBatchCmd    = "/real-time-response/combined/batch-command/v1"
)

var adminCommands = []string{"runscript -Raw=```whoami```", "run C:\\x.exe", "put-and-run x.exe", "falconscript x", "runscript -CloudFile=x"}

func rtrFake() *fakeWrites {
	return &fakeWrites{replies: map[string]reply{
		"POST /devices/entities/devices/v2": {200, `{"resources":[{"device_id":"aid-1","hostname":"WS-0001"}]}`},
		"POST " + rtrSessions:               {201, `{"resources":[{"session_id":"s-9"}]}`},
	}}
}

// Each capability runs only the commands on its own allowlist; admin
// commands run under neither.
func TestRTRAllowlists(t *testing.T) {
	f := rtrFake()
	call, logs := writeSession(t, []string{"rtr-read", "rtr-respond"}, 0, f)
	run := func(command string) (bool, string) {
		_, isErr, text := call("falcon_rtr", map[string]any{"action": "run_command", "id": "s-1", "command": command, "reason": "triage"})
		return isErr, text
	}
	respond := func(command string) (bool, string) {
		_, isErr, text := call("falcon_rtr", map[string]any{"action": "run_responder_command", "id": "aid-1", "confirm": "WS-0001", "command": command, "reason": "contain"})
		return isErr, text
	}
	batch := func(command string) (bool, string) {
		_, isErr, text := call("falcon_rtr", map[string]any{"action": "run_batch_command", "id": "b-1", "command": command, "reason": "hunt"})
		return isErr, text
	}

	refused := append([]string{"history", "rm C:\\x", "reg set HKLM\\x", "get C:\\x", "kill 4", "eventlog backup Security C:\\x", "", "  ", "ls\nrm C:\\x", "ps\rkill 4"}, adminCommands...)
	for _, c := range refused {
		for name, fn := range map[string]func(string) (bool, string){"run_command": run, "run_batch_command": batch} {
			if isErr, text := fn(c); !isErr {
				t.Errorf("%s %q accepted: %s", name, c, text)
			}
		}
	}
	for _, c := range append([]string{"ls C:\\", "ps", "reg query HKLM\\x", "cat /etc/hosts"}, adminCommands...) {
		if isErr, text := respond(c); !isErr {
			t.Errorf("run_responder_command %q accepted: %s", c, text)
		}
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("sent %+v", w)
	}

	if isErr, text := run(`reg query HKLM\Software`); isErr {
		t.Fatal(text)
	}
	if isErr, text := batch("ps"); isErr {
		t.Fatal(text)
	}
	w := f.writes()
	if len(w) != 2 || w[0].Path != rtrCommandPath || w[1].Path != rtrBatchCmd {
		t.Fatalf("writes = %+v", w)
	}
	var body map[string]any
	json.Unmarshal([]byte(w[0].Body), &body)
	if body["session_id"] != "s-1" || body["base_command"] != "reg" || body["command_string"] != `reg query HKLM\Software` || body["persist"] != false {
		t.Errorf("run_command body = %s", w[0].Body)
	}
	json.Unmarshal([]byte(w[1].Body), &body)
	if body["batch_id"] != "b-1" || body["base_command"] != "ps" {
		t.Errorf("run_batch_command body = %s", w[1].Body)
	}
	if !strings.Contains(logs.String(), `"command":"ps"`) {
		t.Errorf("command not audit-logged: %s", logs)
	}
}

// A responder command needs one host, confirmed by hostname, and runs in a
// session opened on that host.
func TestRTRRespondOneHost(t *testing.T) {
	f := rtrFake()
	call, logs := writeSession(t, []string{"rtr-respond"}, 0, f)
	for _, args := range []map[string]any{
		{"id": "aid-1"},
		{"id": "aid-1", "confirm": "WS-0002"},
		{"ids": []string{"aid-1", "aid-2"}, "confirm": "WS-0001"},
	} {
		args["action"], args["command"], args["reason"] = "run_responder_command", "kill 4", "r"
		if _, isErr, _ := call("falcon_rtr", args); !isErr {
			t.Errorf("%v accepted", args)
		}
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("sent %+v", w)
	}
	if _, isErr, text := call("falcon_rtr", map[string]any{"action": "run_responder_command", "id": "aid-1", "confirm": "WS-0001", "command": `rm C:\evil.exe`, "reason": "malware"}); isErr {
		t.Fatal(text)
	}
	w := f.writes()
	if len(w) != 2 || w[0].Path != rtrSessions || w[1].Path != rtrResponder {
		t.Fatalf("writes = %+v", w)
	}
	var init, exec map[string]any
	json.Unmarshal([]byte(w[0].Body), &init)
	json.Unmarshal([]byte(w[1].Body), &exec)
	if init["device_id"] != "aid-1" || init["queue_offline"] != false {
		t.Errorf("init body = %s", w[0].Body)
	}
	if exec["session_id"] != "s-9" || exec["device_id"] != "aid-1" || exec["base_command"] != "rm" || exec["command_string"] != `rm C:\evil.exe` {
		t.Errorf("exec body = %s", w[1].Body)
	}
	if !strings.Contains(logs.String(), `"op":"RTR_InitSession"`) || !strings.Contains(logs.String(), `"reason":"malware"`) {
		t.Errorf("log = %s", logs)
	}
}

// Batch sessions take up to --max-bulk hosts and report per host.
func TestRTRBatchMaxBulk(t *testing.T) {
	f := &fakeWrites{replies: map[string]reply{
		"POST /real-time-response/combined/batch-init-session/v1": {201, `{"batch_id":"b-7","resources":{"aid-1":{"session_id":"s-1","complete":true},"aid-2":{"aid":"aid-2","session_id":"s-2"}}}`},
		"POST " + rtrBatchCmd: {201, `{"combined":{"resources":{"aid-1":{"aid":"aid-1","stdout":"x"}}}}`},
	}}
	call, _ := writeSession(t, []string{"rtr-read"}, 2, f)
	if _, isErr, _ := call("falcon_rtr", map[string]any{"action": "init_batch", "ids": []string{"a", "b", "c"}, "reason": "hunt"}); !isErr {
		t.Error("3 hosts with --max-bulk 2 accepted")
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("sent %+v", w)
	}
	out, isErr, text := call("falcon_rtr", map[string]any{"action": "init_batch", "ids": []string{"aid-1", "aid-2"}, "reason": "hunt"})
	if isErr {
		t.Fatal(text)
	}
	if w := f.writes(); len(w) != 1 || w[0].Body != `{"host_ids":["aid-1","aid-2"],"queue_offline":false}` {
		t.Errorf("writes = %+v", w)
	}
	res, _ := out["results"].(map[string]any)
	if out["batch_id"] != "b-7" || len(res) != 2 || res["aid-2"].(map[string]any)["session_id"] != "s-2" {
		t.Errorf("out = %v", out)
	}
	out, _, _ = call("falcon_rtr", map[string]any{"action": "run_batch_command", "id": "b-7", "command": "ps", "reason": "hunt"})
	if res, _ := out["results"].(map[string]any); len(res) != 1 || res["aid-1"].(map[string]any)["stdout"] != "x" {
		t.Errorf("batch command out = %v", out)
	}
}

// Commands are never retried; status checks are reads.
func TestRTRCommandsNotRetried(t *testing.T) {
	for _, path := range []string{rtrCommandPath, rtrResponder, rtrBatchCmd} {
		f := rtrFake()
		f.replies["POST "+path] = reply{http.StatusBadGateway, `{"errors":[{"code":502,"message":"busy"}]}`}
		call, _ := writeSession(t, []string{"rtr-read", "rtr-respond"}, 0, f)
		args := map[string]any{"action": "run_command", "id": "s-1", "command": "ps", "reason": "r"}
		switch path {
		case rtrResponder:
			args = map[string]any{"action": "run_responder_command", "id": "aid-1", "confirm": "WS-0001", "command": "kill 4", "reason": "r"}
		case rtrBatchCmd:
			args["action"] = "run_batch_command"
		}
		if _, isErr, _ := call("falcon_rtr", args); !isErr {
			t.Errorf("%s: no error", path)
		}
		n := 0
		for _, r := range f.requests() {
			if r.Path == path {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d attempts", path, n)
		}
	}

	f := &fakeWrites{replies: map[string]reply{"GET " + rtrCommandPath: {http.StatusBadGateway, `{}`}}}
	call, _ := writeSession(t, []string{"rtr-read"}, 0, f)
	call("falcon_rtr", map[string]any{"action": "check_command_status", "ids": []string{"req-1"}, "params": map[string]any{"sequence_id": 0}})
	if r := f.requests(); len(r) != 2 || r[0].Query != "cloud_request_id=req-1&sequence_id=0" {
		t.Errorf("status check: %+v", r)
	}
}

// RTR actions are hidden without their capabilities.
func TestRTRHiddenWithoutCapability(t *testing.T) {
	for _, c := range []struct {
		allow  []string
		hidden []string
	}{
		{nil, []string{"init_session", "run_command", "check_command_status", "list_files", "init_batch"}},
		{[]string{"rtr-read"}, []string{"run_responder_command", "check_responder_status"}},
	} {
		cfg := &config.Config{Allow: map[string]bool{}, MaxBulk: 1000}
		for _, a := range c.allow {
			cfg.Allow[a] = true
		}
		b, _ := json.Marshal(listTools(t, sessionWith(t, cfg, nil, http.StatusCreated, (&fakeWrites{}).ServeHTTP))["falcon_rtr"].InputSchema)
		for _, a := range c.hidden {
			if strings.Contains(string(b), `"`+a+`"`) {
				t.Errorf("%v: %s shown", c.allow, a)
			}
		}
	}
}

// init_session and pulse_session drop Falcon's scripts list.
func TestRTRSessionBrief(t *testing.T) {
	f := rtrFake()
	f.replies["POST "+rtrSessions] = reply{201, `{"resources":[{"session_id":"s-9","pwd":"C:\\","scripts":[{"command":"ls"}]}]}`}
	call, _ := writeSession(t, []string{"rtr-read"}, 0, f)
	out, isErr, text := call("falcon_rtr", map[string]any{"action": "init_session", "id": "aid-1", "reason": "triage"})
	if isErr {
		t.Fatal(text)
	}
	s := out["results"].([]any)[0].(map[string]any)
	if s["session_id"] != "s-9" || s["pwd"] != `C:\` || s["scripts"] != nil {
		t.Errorf("session = %v", s)
	}
	if isErr, text := func() (bool, string) {
		_, isErr, text := call("falcon_rtr", map[string]any{"action": "run_command", "id": "s-9", "command": "mount", "reason": "triage"})
		return isErr, text
	}(); isErr {
		t.Errorf("mount refused: %s", text)
	}
}
