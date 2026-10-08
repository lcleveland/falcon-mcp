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
}

// Register adds every enabled tool and returns how many it added.
func Register(s *mcp.Server, d Deps) int {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	registerStatus(s, d)
	n := 1
	for _, t := range Tools() {
		if as := d.actions(t); len(as) > 0 {
			must(t.Name, registerTool(s, d, t, as))
			n++
		}
	}
	return n
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
	for _, n := range actionNames(as) {
		schema.Properties["action"].Enum = append(schema.Properties["action"].Enum, n)
	}
	schema.Required = []string{"action"}
	has := func(f func(Action) bool) bool { return slices.ContainsFunc(as, f) }
	drop := map[string]bool{
		"filter": !has(func(a Action) bool { return a.Kind != Get }),
		"sort":   !has(func(a Action) bool { return a.Kind == Search }),
		"limit":  !has(func(a Action) bool { return a.Kind == Search }),
		"cursor": !has(func(a Action) bool { return a.Kind == Search }),
		"ids":    !has(func(a Action) bool { return a.Kind == Get || a.TakesIDs }),
		"id":     !has(func(a Action) bool { return a.Param != "" }),
		"body":   !has(func(a Action) bool { return a.Kind == Aggregate }),
	}
	for k, gone := range drop {
		if gone {
			delete(schema.Properties, k)
		}
	}

	mcp.AddTool(s, &mcp.Tool{
		Name:        t.Name,
		Title:       t.Title,
		Description: t.Description + help(as),
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in Input) (*mcp.CallToolResult, map[string]any, error) {
		i := slices.IndexFunc(as, func(a Action) bool { return a.Name == in.Action })
		if i < 0 {
			return nil, nil, fmt.Errorf("action %q is not available on %s (available: %s)", in.Action, t.Name, strings.Join(actionNames(as), ", "))
		}
		out, err := d.read(ctx, t.Name, as[i], in)
		return nil, out, err
	})
	return nil
}

func help(as []Action) string {
	var b strings.Builder
	b.WriteString("\n\nActions:")
	for _, a := range as {
		b.WriteString("\n- " + a.Name + ": " + a.Help)
		if a.Guide != "" {
			b.WriteString(" Filter syntax: " + a.Guide + ".")
		}
	}
	b.WriteString("\n\nSearches return brief items (pass fields for others), total when Falcon reports it, and next_cursor when there is more; " +
		"pass it back as cursor with the same query. Timestamps are RFC 3339 UTC.")
	return b.String()
}

func actionNames(as []Action) []string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.Name
	}
	return s
}

// must panics on a schema error: the tool set is static, so only a
// programming error lands here, and it fails every test.
func must(name string, err error) {
	if err != nil {
		panic(name + ": " + err.Error())
	}
}
