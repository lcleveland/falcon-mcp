package tools

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"
	"time"

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
	w := WriteCall{Input: in, Reason: strings.TrimSpace(in.Reason), Values: url.Values{}}
	w.get = func(op string, p falcon.Params) (*envelope, error) {
		if o, _ := falcon.Lookup(op); o.Write {
			d.Log.Info("falcon write sending", "tool", tool, "action", a.Name, "capability", a.Capability, "reason", w.Reason, "op", op, "id", in.ID)
		}
		return d.call(ctx, op, p)
	}
	if w.Reason == "" {
		return nil, errors.New("reason is required for writes; say why, it is recorded in the audit log")
	}
	if err := params(a, in, w.Values); err != nil {
		return nil, err
	}
	if a.Target == TargetIDs && in.Filter != "" && a.Resolve != "" && len(in.IDs) == 0 && d.Config.MaxJob > d.bulkCap(a) {
		n, err := d.count(ctx, a.Resolve, in.Filter)
		if err != nil {
			return nil, err
		}
		if n > d.bulkCap(a) {
			return d.job(ctx, tool, a, w, n)
		}
	}
	var err error
	if w.Targets, err = d.targets(ctx, a, in); err != nil {
		return nil, err
	}
	env, err := d.send(ctx, tool, a, w)
	if err != nil {
		return nil, err
	}
	if in.Raw {
		return rawReply(env), nil
	}
	if a.Op == graphqlOp {
		return capObject(times(env.Data)), nil
	}
	res := env.Resources
	if res == nil {
		res = env.Combined.Resources
	}
	out := shape(list(res), a.Brief, "", noteGet, env)
	m, isMap := res.(map[string]any)
	if isMap { // RTR batches answer by host id
		maps.Copy(out, capObject(times(m)))
	}
	// Some writes (custom IOA deletes, RTR session deletes) succeed with no
	// resources: name what the write was sent for, so success reads as such.
	if r, _ := out["results"].([]any); len(r) == 0 && !isMap && env.BatchID == "" {
		ids := w.Targets
		if len(ids) == 0 && in.ID != "" {
			ids = []string{in.ID}
		}
		if len(ids) > 0 {
			out["applied_to"] = ids
		}
	}
	if env.BatchID != "" {
		out["batch_id"] = env.BatchID
	}
	if env.Meta.TraceID != "" {
		out["trace_id"] = env.Meta.TraceID
	}
	return out, nil
}

// send builds and sends one write call, logging it before and after.
func (d Deps) send(ctx context.Context, tool string, a Action, w WriteCall) (*envelope, error) {
	p, err := a.Send(w)
	if err != nil {
		return nil, err
	}
	audit := []any{"tool", tool, "action", a.Name, "capability", a.Capability, "reason", w.Reason}
	if w.ID != "" {
		audit = append(audit, "id", w.ID)
	}
	if len(w.Targets) > 0 {
		audit = append(audit, "ids", w.Targets)
	}
	if w.Command != "" {
		audit = append(audit, "command", w.Command)
	}
	if a.Op == graphqlOp {
		audit = append(audit, "mutation", w.Values.Get("mutation"))
	}
	// Logged before sending too, so a write cut off mid-call still has a record.
	d.Log.Info("falcon write sending", audit...)
	env, err := d.callWrite(ctx, a.Op, p)
	if err == nil && a.Op == graphqlOp {
		err = graphqlErr(env)
	}
	if err != nil {
		var ae *falcon.APIError
		if errors.As(err, &ae) {
			audit = append(audit, "status", ae.Status, "trace_id", ae.TraceID)
		}
		d.Log.Warn("falcon write failed", append(audit, "error", err.Error())...)
		return nil, err
	}
	d.Log.Info("falcon write", append(audit, "trace_id", env.Meta.TraceID)...)
	return env, nil
}

// Batched filter writes: how long one call runs before it returns its
// progress, how many ids each query fetches beyond the batch (so updates
// the index has not caught up with yet are skipped, not resent), and how
// often a query that finds only those may be retried.
var (
	jobBudget = 4 * time.Minute
	jobLag    = 2 * time.Second
)

const (
	jobPageFactor = 5
	jobStalls     = 5
)

// job runs a filter write that matches more than one call may send, up to
// --max-job records, in batches of the per-call limit. Search APIs cannot
// page that far (alerts stop at 10,000), so it re-queries the filter from
// the start after each batch: the write must take records out of the
// filter (a status filter for a status change, a tag exclusion for a
// tag), and a query that keeps returning sent records stops the job.
func (d Deps) job(ctx context.Context, tool string, a Action, w WriteCall, total int) (map[string]any, error) {
	limit := d.bulkCap(a)
	switch {
	case total > d.Config.MaxJob:
		return nil, fmt.Errorf("filter matches %d records, more than --max-job %d; narrow it", total, d.Config.MaxJob)
	case strings.TrimSpace(w.Confirm) != strconv.Itoa(total):
		return nil, fmt.Errorf("filter matches %d records; this runs in batches of %d, re-querying the filter after each, so the write must take records out of the filter (e.g. status:'new' for a close). "+
			"Check that is what you mean, then repeat with confirm=%q", total, limit, strconv.Itoa(total))
	}
	start := time.Now()
	sent := map[string]bool{}
	done, batches, stalls := 0, 0, 0
	progress := func() map[string]any {
		out := map[string]any{"updated": done, "batches": batches, "matched_at_start": total}
		if n, err := d.count(ctx, a.Resolve, w.Filter); err == nil {
			out["remaining"] = n
			if n > 0 {
				out["next"] = fmt.Sprintf("records still match: repeat with the same filter and confirm=%q to continue", strconv.Itoa(n))
			}
		}
		return out
	}
	for done < total && time.Since(start) < jobBudget {
		q := url.Values{"filter": {w.Filter}, "limit": {strconv.Itoa(min(10000, limit*jobPageFactor))}}
		env, err := d.call(ctx, a.Resolve, falcon.Params{Query: q})
		if err != nil {
			return nil, fmt.Errorf("after %d records in %d batches, resolving filter: %w", done, batches, err)
		}
		var ids []string
		got := list(env.Resources)
		for _, x := range got {
			if s, ok := x.(string); ok && !sent[s] && len(ids) < min(limit, total-done) {
				ids = append(ids, s)
			}
		}
		if len(got) == 0 {
			break
		}
		if len(ids) == 0 {
			if stalls++; stalls > jobStalls {
				return nil, fmt.Errorf("after %d records in %d batches, the filter still matches only records already sent: the write does not take them out of the filter, so the job stopped. "+
					"Add a clause excluding the change (e.g. status:!'closed', tags:!'x') and run it again", done, batches)
			}
			if err := sleepCtx(ctx, jobLag); err != nil {
				return nil, err
			}
			continue
		}
		stalls = 0
		w.Targets = ids
		if _, err := d.send(ctx, tool, a, w); err != nil {
			return nil, fmt.Errorf("after %d records in %d batches, a batch failed: %w", done, batches, err)
		}
		for _, id := range ids {
			sent[id] = true
		}
		done += len(ids)
		batches++
	}
	return progress(), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// count is how many records filter matches, by one read.
func (d Deps) count(ctx context.Context, op, filter string) (int, error) {
	env, err := d.call(ctx, op, falcon.Params{Query: url.Values{"filter": {filter}, "limit": {"1"}}})
	if err != nil {
		return 0, fmt.Errorf("resolving filter: %w", err)
	}
	if t := env.Meta.Pagination.Total; t != nil {
		return *t, nil
	}
	return len(list(env.Resources)), nil
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
