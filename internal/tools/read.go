package tools

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

const (
	defaultLimit = 50
	maxItems     = 200
	maxBytes     = 60 << 10 // keeps a result inside a sensible slice of context
)

// Input is every tool's arguments; each tool's schema keeps only the
// fields its actions use.
type Input struct {
	Action string   `json:"action" jsonschema:"what to do; the tool description lists the actions"`
	Filter string   `json:"filter,omitempty" jsonschema:"FQL filter; read the action's guide before writing one"`
	Sort   string   `json:"sort,omitempty" jsonschema:"FQL sort, e.g. created_timestamp.desc"`
	Limit  int      `json:"limit,omitempty" jsonschema:"items per page: default 50, at most 200"`
	Fields []string `json:"fields,omitempty" jsonschema:"fields to return instead of the brief set; dotted paths reach nested fields (device.hostname)"`
	Cursor string   `json:"cursor,omitempty" jsonschema:"next_cursor from the previous call with the same query, unchanged"`
	IDs    []string `json:"ids,omitempty" jsonschema:"ids to fetch"`
	ID     string   `json:"id,omitempty" jsonschema:"the one id the action is scoped to"`
	Body   any      `json:"body,omitempty" jsonschema:"aggregation request body"`

	PolicyType    string         `json:"policy_type,omitempty" jsonschema:"which kind of policy; the tool description lists the types per action"`
	ExclusionType string         `json:"exclusion_type,omitempty" jsonschema:"which kind of exclusion; the tool description lists the types per action"`
	Params        map[string]any `json:"params,omitempty" jsonschema:"query parameters by name; the action's help lists the ones it takes"`

	Query      string         `json:"query,omitempty" jsonschema:"the query text: CQL for falcon_ngsiem, a GraphQL query document for falcon_identity"`
	Variables  map[string]any `json:"variables,omitempty" jsonschema:"GraphQL variables"`
	Repository string         `json:"repository,omitempty" jsonschema:"NGSIEM repository or view, e.g. search-all (the default) or investigate_view"`
	Start      string         `json:"start,omitempty" jsonschema:"search window start: RFC 3339 or relative (1h, 7d); default 1d"`
	End        string         `json:"end,omitempty" jsonschema:"search window end: RFC 3339 or relative; default now"`
}

// inputs are the Input fields an action reads, by JSON name, beyond action
// and fields.
func (a Action) inputs(typeParam string) []string {
	var in []string
	switch a.Kind {
	case Search:
		in = []string{"limit", "cursor"}
		if !a.NoFilter {
			in = append(in, "filter", "sort")
		}
		if a.Param != "" {
			in = append(in, "id")
		}
	case Get:
		in = []string{"ids"}
	case Aggregate:
		if !a.NoFilter {
			in = append(in, "filter")
		}
		if op, _ := falcon.Lookup(a.Op); op.Method != http.MethodGet {
			in = append(in, "body")
		}
		if a.TakesIDs {
			in = append(in, "ids")
		}
	case Custom:
		in = a.Inputs
	}
	if len(a.Params) > 0 {
		in = append(in, "params")
	}
	if a.Type != "" {
		in = append(in, typeParam)
	}
	return in
}

// params turns the params input into query parameters, refusing names the
// action does not take.
func params(a Action, in Input, q url.Values) error {
	for k, v := range in.Params {
		if !slices.Contains(a.Params, k) {
			if len(a.Params) == 0 {
				return fmt.Errorf("this action takes no params")
			}
			return fmt.Errorf("params: %q is not a parameter of this action (takes %s)", k, strings.Join(a.Params, ", "))
		}
		vs, ok := v.([]any)
		if !ok {
			vs = []any{v}
		}
		for _, x := range vs {
			switch x := x.(type) {
			case float64:
				q.Add(k, strconv.FormatFloat(x, 'f', -1, 64))
			case string, bool:
				q.Add(k, fmt.Sprint(x))
			default:
				return fmt.Errorf("params: %s must be a string, number, boolean or a list of them", k)
			}
		}
	}
	return nil
}

// envelope is Falcon's reply shape.
type envelope struct {
	Meta struct {
		Pagination struct {
			Total *int   `json:"total"`
			After string `json:"after"`
			Next  string `json:"next"`
		} `json:"pagination"`
	} `json:"meta"`
	Resources any `json:"resources"`
	Errors    []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (d Deps) call(ctx context.Context, op string, p falcon.Params) (*envelope, error) {
	raw, err := d.Client.Do(ctx, op, p)
	if err != nil {
		return nil, err
	}
	var env envelope
	if len(raw) > 0 && json.Unmarshal(raw, &env) != nil {
		// Some routes serve a file: a bare JSON array, or text such as CSV.
		var v any
		switch {
		case json.Unmarshal(raw, &v) == nil:
			env.Resources = v
		case utf8.Valid(raw) && !bytes.HasPrefix(raw, []byte("%PDF")):
			env.Resources = string(raw)
		default:
			return nil, fmt.Errorf("Falcon %s returned a binary file, which this server does not return", op)
		}
	}
	return &env, nil
}

// read runs one read action.
func (d Deps) read(ctx context.Context, tool string, a Action, in Input) (map[string]any, error) {
	if in.Cursor != "" && !slices.Contains(a.inputs(""), "cursor") {
		return nil, errors.New("cursor does not belong to this query: only search actions page")
	}
	if a.NoFilter && (in.Filter != "" || in.Sort != "") {
		return nil, errors.New("this action takes no filter or sort; its help lists the params it takes")
	}
	switch a.Kind {
	case Search:
		return d.search(ctx, tool, a, in)
	case Custom:
		return a.Run(ctx, d, in)
	case Get:
		if len(in.IDs) == 0 {
			return nil, errors.New("this action needs ids")
		}
		if len(in.IDs) > maxItems {
			return nil, fmt.Errorf("at most %d ids per call", maxItems)
		}
		if strings.HasPrefix(a.IDs, "one:") && len(in.IDs) != 1 {
			return nil, errors.New("this action takes exactly one id in ids")
		}
		p := idParams(a.IDs, in.IDs)
		if err := params(a, in, p.Query); err != nil {
			return nil, err
		}
		env, err := d.call(ctx, a.Op, p)
		if err != nil {
			return nil, err
		}
		if t, ok := env.Resources.(string); ok {
			return text(t), nil
		}
		return shape(list(env.Resources), in.Fields, "", noteGet, env), nil
	}
	return d.aggregate(ctx, a, in)
}

func (d Deps) search(ctx context.Context, tool string, a Action, in Input) (map[string]any, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxItems)
	if a.MaxLimit > 0 {
		limit = min(limit, a.MaxLimit)
	}
	filter := joinFilter(a.Filter, in.Filter)
	key := queryKey(tool, a.Name, a.Type, filter, in.Sort, in.ID, in.Fields, in.Params)
	pos, err := decodeCursor(key, in.Cursor)
	if err != nil {
		return nil, err
	}

	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if filter != "" {
		q.Set("filter", filter)
	}
	if in.Sort != "" {
		q.Set("sort", in.Sort)
	}
	if a.Param != "" {
		if in.ID == "" {
			return nil, errors.New("this action needs id")
		}
		q.Set(a.Param, in.ID)
	}
	if pos != "" {
		q.Set(map[Paging]string{Offset: "offset", After: "after"}[a.Paging], pos)
	}
	for k, v := range a.Set {
		q[k] = slices.Clone(v)
	}
	if err := params(a, in, q); err != nil {
		return nil, err
	}

	env, err := d.call(ctx, a.Op, falcon.Params{Query: q})
	if err != nil {
		return nil, err
	}
	items := list(env.Resources)
	got := len(items)
	ids := make([]string, 0, got)
	for _, x := range items {
		if s, ok := x.(string); ok {
			ids = append(ids, s)
		}
	}
	if a.Hydrate != "" && len(ids) > 0 {
		ents, err := d.call(ctx, a.Hydrate, idParams(a.IDs, ids))
		if err != nil {
			return nil, err
		}
		items = inOrder(ids, list(ents.Resources))
		env.Errors = append(env.Errors, ents.Errors...)
	}

	pg := env.Meta.Pagination
	next := ""
	switch a.Paging {
	case Offset:
		start, _ := strconv.Atoi(pos)
		end := start + got
		if (pg.Total != nil && (end < *pg.Total || a.TotalIsEnd && got == limit)) || (pg.Total == nil && got == limit) {
			next = strconv.Itoa(end)
		}
	case After:
		next = cmp.Or(pg.After, pg.Next)
	}
	if got == 0 {
		next = ""
	}
	fields := in.Fields
	if len(fields) == 0 {
		fields = a.Brief
	}
	out := shape(items, fields, encodeCursor(key, next), noteSearch, env)
	if pg.Total != nil {
		out["total"] = *pg.Total
	}
	return out, nil
}

// aggregate runs an unpaged call: a POST body, or a GET with a filter.
func (d Deps) aggregate(ctx context.Context, a Action, in Input) (map[string]any, error) {
	if op, _ := falcon.Lookup(a.Op); op.Method == http.MethodPost && in.Body == nil {
		return nil, errors.New("this action needs body")
	}
	q := url.Values{}
	if f := joinFilter(a.Filter, in.Filter); f != "" {
		q.Set("filter", f)
	}
	for _, id := range in.IDs {
		q.Add("ids", id)
	}
	if err := params(a, in, q); err != nil {
		return nil, err
	}
	env, err := d.call(ctx, a.Op, falcon.Params{Query: q, Body: in.Body})
	if err != nil {
		return nil, err
	}
	if t, ok := env.Resources.(string); ok {
		return text(t), nil
	}
	if l, ok := env.Resources.([]any); ok {
		return shape(l, in.Fields, "", noteGet, env), nil
	}
	if m, ok := env.Resources.(map[string]any); ok && len(in.Fields) > 0 {
		return capObject(times(project(m, in.Fields))), nil
	}
	return capObject(times(env.Resources)), nil
}

// idParams sends ids where an entities op takes them.
func idParams(where string, ids []string) falcon.Params {
	if key, ok := strings.CutPrefix(where, "body:"); ok {
		return falcon.Params{Body: map[string]any{key: ids}, Query: url.Values{}}
	}
	name, _ := strings.CutPrefix(where, "query:")
	name, _ = strings.CutPrefix(name, "one:")
	return falcon.Params{Query: url.Values{cmp.Or(name, "ids"): ids}}
}

// text caps a file served as text, such as a CSV report.
func text(t string) map[string]any {
	if len(t) <= maxBytes {
		return map[string]any{"results": t}
	}
	return map[string]any{"results": strings.ToValidUTF8(t[:maxBytes], ""),
		"_truncation": map[string]any{"returned_bytes": maxBytes, "of": len(t), "note": "file too large; narrow the request"}}
}

const (
	noteSearch = "result too large; repeat with a lower limit or pass fields"
	noteGet    = "result too large; pass fields or fewer ids"
)

// inOrder puts hydrated entities back in the order the query returned their
// ids, so the caller's sort survives. Entities with no matching id go last.
func inOrder(ids []string, ents []any) []any {
	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		pos[id] = i
	}
	rank := func(x any) int {
		m, _ := x.(map[string]any)
		for _, k := range []string{"id", "device_id", "composite_id", "aid", "uuid"} {
			if s, ok := m[k].(string); ok {
				if i, ok := pos[s]; ok {
					return i
				}
			}
		}
		return len(ids)
	}
	slices.SortStableFunc(ents, func(a, b any) int { return rank(a) - rank(b) })
	return ents
}

// shape projects, converts times and caps a list of items for the model.
// The cursor (empty for none) still points past the whole page when the
// byte cap trims items from the end.
func shape(items []any, fields []string, cursor, note string, env *envelope) map[string]any {
	for i, x := range items {
		x = times(x)
		if len(fields) > 0 {
			x = project(x, fields)
		}
		items[i] = x
	}
	out := map[string]any{}
	if kept := fit(items); kept < len(items) {
		out["_truncation"] = map[string]any{"returned": kept, "of": len(items), "note": note}
		items = items[:kept]
	}
	if len(items) == 1 && size(items[0]) > maxBytes {
		// Even one item is too big: name its fields instead.
		items[0] = capObject(items[0])
	}
	if items == nil {
		items = []any{}
	}
	out["results"] = items
	if cursor != "" {
		out["next_cursor"] = cursor
	}
	if env != nil && len(env.Errors) > 0 {
		msgs := make([]string, len(env.Errors))
		for i, e := range env.Errors {
			msgs[i] = e.Message
		}
		out["errors"] = msgs
	}
	return out
}

// fit returns how many leading items fit in maxBytes, at least one.
func fit(items []any) int {
	total := 2 // []
	for i, x := range items {
		total += size(x) + 1
		if total > maxBytes {
			return max(i, 1)
		}
	}
	return len(items)
}

// capObject replaces an oversized object with its keys.
func capObject(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{"results": v}
	}
	if n := size(m); n > maxBytes {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		return map[string]any{"_truncation": map[string]any{
			"note": "result too large (" + strconv.Itoa(n) + " bytes); pass fields to pick the parts you need"}, "fields": keys}
	}
	return map[string]any{"results": m}
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func joinFilter(fixed, user string) string {
	switch {
	case fixed == "":
		return user
	case user == "":
		return fixed
	}
	return fixed + "+" + user
}

// queryKey binds a cursor to the query that issued it.
func queryKey(parts ...any) string {
	b, _ := json.Marshal(parts)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

type cursor struct {
	Pos string `json:"p"`
	Key string `json:"k"`
}

func encodeCursor(key, pos string) string {
	if pos == "" {
		return ""
	}
	b, _ := json.Marshal(cursor{pos, key})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(key, s string) (string, error) {
	if s == "" {
		return "", nil
	}
	var c cursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.Key != key {
		return "", errors.New("cursor does not belong to this query; pass next_cursor only with the same action, filter, sort, id and fields that returned it")
	}
	return c.Pos, nil
}

// project keeps only the named fields; a dotted path keeps a nested one.
func project(v any, fields []string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := map[string]any{}
	for _, f := range fields {
		copyPath(m, out, strings.Split(strings.TrimSpace(f), "."))
	}
	return out
}

func copyPath(src, dst map[string]any, path []string) {
	x, ok := src[path[0]]
	if !ok {
		return
	}
	if len(path) == 1 {
		dst[path[0]] = x
		return
	}
	sub, ok := x.(map[string]any)
	if !ok {
		return
	}
	d, _ := dst[path[0]].(map[string]any)
	if d == nil {
		d = map[string]any{}
		dst[path[0]] = d
	}
	copyPath(sub, d, path[1:])
}

// times rewrites epoch timestamps under time-like keys to RFC 3339 UTC, and
// RFC 3339 strings with an offset to UTC. Falcon mostly sends RFC 3339
// already; a few APIs send epoch seconds or milliseconds.
func times(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if timeKey(k) {
				if s, ok := utc(x); ok {
					t[k] = s
					continue
				}
			}
			t[k] = times(x)
		}
	case []any:
		for i, x := range t {
			t[i] = times(x)
		}
	}
	return v
}

func timeKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"timestamp", "_at", "_on", "time", "date", "last_seen", "first_seen"} {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

func utc(x any) (string, bool) {
	switch t := x.(type) {
	case float64:
		switch {
		case t >= 1e9 && t < 1e10: // seconds, 2001..2286
			return time.Unix(0, int64(t*1e9)).UTC().Format(time.RFC3339), true
		case t >= 1e12 && t < 1e13: // milliseconds
			return time.UnixMilli(int64(t)).UTC().Format(time.RFC3339), true
		}
	case string:
		if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return ts.UTC().Format(time.RFC3339Nano), true
		}
	}
	return "", false
}

func size(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}
