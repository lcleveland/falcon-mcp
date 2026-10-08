package tools

import (
	"context"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// Tool is one tool: a set of actions over Falcon operations. Adding an
// operation is adding an Action; there is no per-action handler code.
type Tool struct {
	Name        string // falcon_<area>
	Group       string
	Title       string
	Description string // what it is; per-action help is appended
	// TypeParam names the input that picks an action's variant, e.g.
	// policy_type; each variant is its own Action with Type set.
	TypeParam string
	Actions   []Action
}

// Action is one action of a tool.
type Action struct {
	Name string
	Help string // one line: what it does and what it takes
	Kind Kind
	Op   string // the op called first: query, combined, entities or aggregate
	Type string // the TypeParam value this variant serves

	// Search.
	Hydrate  string // entities op fetching the ids Op returns; "" when Op is combined
	Paging   Paging
	MaxLimit int      // Falcon's own page maximum, when below ours
	Brief    []string // fields a search keeps unless fields is given; dotted paths reach nested ones
	Filter   string   // FQL always ANDed with the caller's filter
	Guide    string   // the guide for this action's filter

	// IDs says where an entities op takes its ids: the ids query parameter
	// when empty, "body:<key>" for a JSON body {<key>: [...]}, or
	// "query:<name>" for another query parameter ("one:<name>" when it takes
	// a single id). It applies to Hydrate for a
	// search and to Op for a get.
	IDs string

	Param    string              // query parameter filled from the id input, e.g. a host group id
	TakesIDs bool                // an aggregate that also takes ids
	Query    []string            // named query parameters taken from the params input, for APIs without FQL
	NoFilter bool                // the op takes no FQL filter or sort
	Set      map[string][]string // query parameters a search always sends, e.g. Spotlight facets

	// Custom: the handler, and the inputs it reads beyond action and fields.
	Run    func(context.Context, Deps, Input) (map[string]any, error)
	Inputs []string
}

// Kind is the shape of an action.
type Kind int

const (
	Search    Kind = iota // FQL filter, sort, limit, cursor; returns entities
	Get                   // entities by ids
	Aggregate             // one unpaged call: a POST body, or a GET with filter
	Custom                // Run does the work
)

// Paging is how a Falcon query pages. The model never sees it: every search
// takes cursor and returns next_cursor.
type Paging int

const (
	Offset Paging = iota // offset=<index>; meta.pagination.total
	After                // after=<token>; meta.pagination.after (or next)
)

// scope is the API scope an action needs: its first op's.
func (a Action) scope() string {
	op, _ := falcon.Lookup(a.Op)
	return op.Scope
}

// Tools is the whole tool table, in registration order.
func Tools() []Tool {
	var all []Tool
	for _, t := range [][]Tool{respondTools, hostsTools, preventTools, intelTools, siemTools, exposureTools, identityTools, aiTools} {
		all = append(all, t...)
	}
	return all
}
