// Package tools defines the MCP tools and registers the enabled ones.
package tools

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

type Deps struct {
	Client *falcon.Client
	Config *config.Config
	Probes *falcon.Probes // nil shows everything
	Log    *slog.Logger

	jobs *jobs // live NGSIEM searches
}

// Register adds every enabled tool and returns how many it added, and a
// func that stops what the tools left running (NGSIEM jobs) at shutdown.
func Register(s *mcp.Server, d Deps) (int, func()) {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	d.jobs = newJobs(d.Client, d.Log)
	registerStatus(s, d)
	registerGuides(s, d)
	n := 1
	for _, t := range Tools() {
		if as := d.actions(t); len(as) > 0 {
			must(t.Name, registerTool(s, d, t, as))
			n++
		}
	}
	return n, d.jobs.Close
}

// actions are the tool's actions this server shows: its group is on and the
// probe did not refuse the action's scope. A tool with none is not listed.
func (d Deps) actions(t Tool) []Action {
	if !d.Config.GroupOn(t.Group) {
		return nil
	}
	var as []Action
	for _, a := range t.Actions {
		if d.Probes.Allows(a.scope()) {
			as = append(as, a)
		}
	}
	return as
}

func registerTool(s *mcp.Server, d Deps, t Tool, as []Action) error {
	schema, err := jsonschema.For[Input](nil)
	if err != nil {
		return err
	}
	used := map[string]bool{"action": true, "fields": true}
	for _, a := range as {
		for _, in := range a.inputs(t.TypeParam) {
			used[in] = true
		}
	}
	for k := range schema.Properties {
		if !used[k] {
			delete(schema.Properties, k)
		}
	}
	schema.Properties["action"].Enum = anys(actionNames(as))
	if t.TypeParam != "" {
		schema.Properties[t.TypeParam].Enum = anys(types(as))
	}
	schema.Required = []string{"action"}
	if f := schema.Properties["filter"]; f != nil {
		var gs []string
		for _, a := range as {
			if g := a.Name + ": " + a.Guide; slices.Contains(a.inputs(t.TypeParam), "filter") && a.Guide != "" && !slices.Contains(gs, g) {
				gs = append(gs, g)
			}
		}
		f.Description = "FQL filter; the action's help gives examples"
		if len(gs) > 0 {
			f.Description += ". Read the guide before writing one: " + strings.Join(gs, "; ")
		}
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        t.Name,
		Title:       t.Title,
		Description: t.Description + help(t, as),
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in Input) (*mcp.CallToolResult, map[string]any, error) {
		a, err := pick(t, as, in)
		if err != nil {
			return nil, nil, err
		}
		out, err := d.read(ctx, t.Name, a, in)
		return nil, out, err
	})
	return nil
}

// pick finds the action named by in, and for a typed tool its variant.
func pick(t Tool, as []Action, in Input) (Action, error) {
	var named []Action
	for _, a := range as {
		if a.Name == in.Action {
			named = append(named, a)
		}
	}
	if len(named) == 0 {
		return Action{}, fmt.Errorf("action %q is not available on %s (available: %s)", in.Action, t.Name, strings.Join(actionNames(as), ", "))
	}
	if t.TypeParam == "" {
		return named[0], nil
	}
	typ := map[string]string{"policy_type": in.PolicyType, "exclusion_type": in.ExclusionType}[t.TypeParam]
	for _, a := range named {
		if a.Type == typ {
			return a, nil
		}
	}
	return Action{}, fmt.Errorf("%s %s needs %s, one of: %s", t.Name, in.Action, t.TypeParam, strings.Join(types(named), ", "))
}

func help(t Tool, as []Action) string {
	var b strings.Builder
	b.WriteString("\n\nActions:")
	for _, n := range actionNames(as) {
		var a Action
		var ts []string
		for _, x := range as {
			if x.Name == n {
				a = x
				ts = append(ts, x.Type)
			}
		}
		b.WriteString("\n- " + n)
		if t.TypeParam != "" {
			b.WriteString(" (" + t.TypeParam + ": " + strings.Join(ts, ", ") + ")")
		}
		b.WriteString(": " + a.Help)
		switch {
		case a.Guide != "" && a.NoFilter:
			b.WriteString(" Guide: " + a.Guide + ".")
		case a.Guide != "":
			b.WriteString(" Filter syntax: " + a.Guide + ".")
		}
	}
	b.WriteString("\n\n")
	if slices.ContainsFunc(as, func(a Action) bool { return a.Kind == Search }) {
		b.WriteString("Searches return brief items (pass fields for others), total when Falcon reports it, and next_cursor when there is more; " +
			"pass it back as cursor with the same query. ")
	}
	b.WriteString("Timestamps are RFC 3339 UTC.")
	return b.String()
}

// actionNames are the distinct action names, in table order.
func actionNames(as []Action) []string {
	var s []string
	for _, a := range as {
		if !slices.Contains(s, a.Name) {
			s = append(s, a.Name)
		}
	}
	return s
}

// types are the distinct variant types, in table order.
func types(as []Action) []string {
	var s []string
	for _, a := range as {
		if !slices.Contains(s, a.Type) {
			s = append(s, a.Type)
		}
	}
	return s
}

func anys(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

// must panics on a schema error: the tool set is static, so only a
// programming error lands here, and it fails every test.
func must(name string, err error) {
	if err != nil {
		panic(name + ": " + err.Error())
	}
}
