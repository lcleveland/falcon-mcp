package tools

import "github.com/lcleveland/falcon-mcp/internal/falcon"

// Tool is one area tool: a set of actions over Falcon operations. Adding an
// operation is adding an Action; there is no per-action handler code.
type Tool struct {
	Name        string // falcon_<area>
	Group       string
	Title       string
	Description string // what it is; per-action help is appended
	Actions     []Action
}

// Action is one action of a tool.
type Action struct {
	Name string
	Help string // one line: what it does and what it takes
	Kind Kind
	Op   string // the op called first: query, combined, entities or aggregate

	// Search.
	Get      string   // hydrate the ids Op returns with this entities op; "" when Op is combined
	Paging   Paging   //
	MaxLimit int      // Falcon's own page maximum, when below ours
	Brief    []string // fields a search keeps unless fields is given; dotted paths reach nested ones
	Filter   string   // FQL always ANDed with the caller's filter
	Guide    string   // the guide for this action's filter

	// IDs says where an entities op takes its ids: the ids query parameter
	// when empty, else "body:<key>" for a JSON body {<key>: [...]}. It
	// applies to Get for a search and to Op for a get.
	IDs string

	Param    string // query parameter filled from the id input, e.g. a host group id
	TakesIDs bool   // an aggregate that also takes ids
}

// Kind is the shape of an action.
type Kind int

const (
	Search    Kind = iota // FQL filter, sort, limit, cursor; returns entities
	Get                   // entities by ids
	Aggregate             // one unpaged call: a POST body, or a GET with filter
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

// Tools is the whole area tool table, in registration order.
func Tools() []Tool {
	var all []Tool
	for _, t := range [][]Tool{respondTools, hostsTools} {
		all = append(all, t...)
	}
	return all
}
