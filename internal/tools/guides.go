package tools

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/guides"
)

// guides maps each visible guide's URI to the tools and actions it
// documents. A guide is visible when one of those actions is.
func (d Deps) guides() map[string][]string {
	g := map[string][]string{}
	for _, t := range Tools() {
		as := d.actions(t)
		for _, a := range as {
			if a.Guide != "" && !slices.Contains(g[a.Guide], t.Name+" "+a.Name) {
				g[a.Guide] = append(g[a.Guide], t.Name+" "+a.Name)
			}
		}
		if len(as) > 0 {
			for _, u := range t.Guides {
				g[u] = append(g[u], t.Name)
			}
		}
	}
	return g
}

func registerGuides(s *mcp.Server, d Deps) {
	for uri, users := range d.guides() {
		text, _ := guides.Text(uri)
		s.AddResource(&mcp.Resource{
			URI: uri, Name: strings.TrimPrefix(uri, "falcon://"), MIMEType: "text/markdown",
			Description: "Query guide for " + strings.Join(users, ", ") + ".",
		}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "text/markdown", Text: text}}}, nil
		})
	}
}

// guide serves a visible guide by name (its URI with or without falcon://).
func (d Deps) guide(name string) (string, error) {
	uri := "falcon://" + strings.TrimPrefix(name, "falcon://")
	vis := d.guides()
	if _, ok := vis[uri]; !ok {
		names := slices.Sorted(maps.Keys(vis))
		for i, u := range names {
			names[i] = strings.TrimPrefix(u, "falcon://")
		}
		return "", fmt.Errorf("no guide %q among the visible tools; guides: %s", name, strings.Join(names, ", "))
	}
	text, _ := guides.Text(uri)
	return text, nil
}
