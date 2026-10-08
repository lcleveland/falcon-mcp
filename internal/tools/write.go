package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// WriteCall is what a write's Send builds its call from, once the framework
// has checked it.
type WriteCall struct {
	Input
	Targets []string   // the ids the write acts on (TargetIDs, TargetHost)
	Reason  string     // trimmed, never empty
	Values  url.Values // the params input, checked against Action.Params

	// get runs a read, for a write that must send back state it has not
	// been given (a version, the rest of a record), or opens the RTR
	// session a responder command runs in. Nothing it calls is retried.
	get func(op string, p falcon.Params) (*envelope, error)
}

// sender builds a write's call from a checked WriteCall.
type sender func(WriteCall) (falcon.Params, error)

var errNeedsTags = errors.New("this action needs tags")

// write runs a write action. Every write goes through here, so the
// capability, reason, bulk cap, confirmation and audit log cannot be
// skipped. Nothing retries: the client never retries an op with the write
// bit, since Falcon takes no idempotency keys.
func (d Deps) write(ctx context.Context, tool string, a Action, in Input) (map[string]any, error) {
	if !d.Config.Allow[a.Capability] {
		return nil, fmt.Errorf("the %s capability is disabled by the operator", a.Capability)
	}
	w := WriteCall{Input: in, Reason: strings.TrimSpace(in.Reason), Values: url.Values{},
		get: func(op string, p falcon.Params) (*envelope, error) { return d.call(ctx, op, p) }}
	if w.Reason == "" {
		return nil, errors.New("reason is required for writes; say why, it is recorded in the audit log")
	}
	if err := params(a, in, w.Values); err != nil {
		return nil, err
	}
	var err error
	if w.Targets, err = d.targets(ctx, a, in); err != nil {
		return nil, err
	}
	p, err := a.Send(w)
	if err != nil {
		return nil, err
	}

	audit := []any{"tool", tool, "action", a.Name, "capability", a.Capability, "reason", w.Reason}
	if in.ID != "" {
		audit = append(audit, "id", in.ID)
	}
	if len(w.Targets) > 0 {
		audit = append(audit, "ids", w.Targets)
	}
	if in.Command != "" {
		audit = append(audit, "command", in.Command)
	}
	// Logged before sending too, so a write cut off mid-call still has a record.
	d.Log.Info("falcon write sending", audit...)
	env, err := d.call(ctx, a.Op, p)
	if err != nil {
		var ae *falcon.APIError
		if errors.As(err, &ae) {
			audit = append(audit, "status", ae.Status, "trace_id", ae.TraceID)
		}
		d.Log.Warn("falcon write failed", append(audit, "error", err.Error())...)
		return nil, err
	}
	d.Log.Info("falcon write", append(audit, "trace_id", env.Meta.TraceID)...)
	res := env.Resources
	if res == nil {
		res = env.Combined.Resources
	}
	out := shape(list(res), nil, "", noteGet, env)
	if m, ok := res.(map[string]any); ok { // RTR batches answer by host id
		maps.Copy(out, capObject(times(m)))
	}
	if env.BatchID != "" {
		out["batch_id"] = env.BatchID
	}
	if env.Meta.TraceID != "" {
		out["trace_id"] = env.Meta.TraceID
	}
	return out, nil
}

// targets checks and returns the ids a write acts on. Nothing is sent to
// Falcon but reads.
func (d Deps) targets(ctx context.Context, a Action, in Input) ([]string, error) {
	switch a.Target {
	case TargetHost:
		if len(in.IDs) > 0 || in.ID == "" {
			return nil, errors.New("this action takes one host per call: its device id as id")
		}
		name, err := d.hostname(ctx, in.ID)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(in.Confirm) != name {
			return nil, fmt.Errorf("confirm must be the host's hostname exactly; device %s is %q. Check this is the host you mean, then retry", in.ID, name)
		}
		return []string{in.ID}, nil
	case TargetIDs:
		limit := d.bulkCap(a)
		if in.Filter == "" {
			if len(in.IDs) == 0 {
				return nil, errors.New("this action needs ids")
			}
			if len(in.IDs) > limit {
				return nil, fmt.Errorf("%d ids is more than the limit of %d per write; split it", len(in.IDs), limit)
			}
			return in.IDs, nil
		}
		if a.Resolve == "" {
			return nil, errors.New("this action takes ids, not filter")
		}
		if len(in.IDs) > 0 {
			return nil, errors.New("pass ids or filter, not both")
		}
		ids, err := d.resolve(ctx, a.Resolve, in.Filter, limit)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, errors.New("filter matches nothing; nothing was sent")
		}
		if n := strconv.Itoa(len(ids)); strings.TrimSpace(in.Confirm) != n {
			return nil, fmt.Errorf("filter matches %s records; check that is what you mean, then repeat with confirm=%q", n, n)
		}
		return ids, nil
	}
	return nil, nil
}

// bulkCap is the most ids one write takes: --max-bulk, clamped to Falcon's
// own limit.
func (d Deps) bulkCap(a Action) int {
	if a.MaxIDs > 0 {
		return min(d.Config.MaxBulk, a.MaxIDs)
	}
	return d.Config.MaxBulk
}

// resolve turns a write's filter into the ids it matches, refusing more
// than limit.
func (d Deps) resolve(ctx context.Context, op, filter string, limit int) ([]string, error) {
	const page = 500
	var ids []string
	for offset := 0; ; {
		q := url.Values{"filter": {filter}, "limit": {strconv.Itoa(page)}, "offset": {strconv.Itoa(offset)}}
		env, err := d.call(ctx, op, falcon.Params{Query: q})
		if err != nil {
			return nil, fmt.Errorf("resolving filter: %w", err)
		}
		got := list(env.Resources)
		offset += len(got)
		for _, x := range got {
			if s, ok := x.(string); ok {
				ids = append(ids, s)
			}
		}
		total := env.Meta.Pagination.Total
		if n := max(len(ids), deref(total)); n > limit {
			return nil, fmt.Errorf("filter matches %d records, more than the limit of %d per write; narrow it", n, limit)
		}
		if len(got) < page || (total != nil && offset >= *total) {
			return ids, nil
		}
	}
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// hostname looks up a host so the caller's confirm can be checked.
func (d Deps) hostname(ctx context.Context, id string) (string, error) {
	env, err := d.call(ctx, "PostDeviceDetailsV2", idParams("body:ids", []string{id}))
	if err != nil {
		return "", fmt.Errorf("looking up host %s to confirm: %w", id, err)
	}
	for _, x := range list(env.Resources) {
		if m, _ := x.(map[string]any); m["device_id"] == id {
			if name, _ := m["hostname"].(string); name != "" {
				return name, nil
			}
			return "", fmt.Errorf("host %s has no hostname to confirm against", id)
		}
	}
	return "", fmt.Errorf("no host with device id %s", id)
}

// object is a body input that must be a JSON object.
func object(body any) (map[string]any, error) {
	m, ok := body.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, errors.New("this action needs body, an object of the fields to set")
	}
	return m, nil
}

// maxQueryIDs caps writes that send ids in the query string, which Falcon
// bounds only by URL length.
const maxQueryIDs = 100

// entity sends the body input as one record: with the reason as its
// comment when comment, the id input as its id when withID, and wrapped as
// {key: [record]} when key is set.
func entity(key string, withID, comment bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		b, err := object(w.Body)
		if err != nil {
			return falcon.Params{}, err
		}
		b = maps.Clone(b)
		if withID {
			if w.ID == "" {
				return falcon.Params{}, errors.New("this action needs id, the id of the record to update")
			}
			b["id"] = w.ID
		}
		if comment {
			b["comment"] = w.Reason
		}
		if key == "" {
			return falcon.Params{Body: b}, nil
		}
		return falcon.Params{Body: map[string]any{key: []any{b}}}, nil
	}
}

// deleteIDs deletes the targets by ids in the query, with the reason as
// the comment when the API takes one.
func deleteIDs(comment bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		q := url.Values{"ids": w.Targets}
		if comment {
			q.Set("comment", w.Reason)
		}
		return falcon.Params{Query: q}, nil
	}
}
