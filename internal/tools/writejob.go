package tools

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// Write jobs: a filter write matching more than one call may send runs in
// the background in batches of the per-call limit. Search APIs cannot page
// that far (alerts stop at 10,000), so a job sends the first matches and
// queries again: the write must take records out of the filter. Jobs live
// in memory; a restart ends them, and rerunning the filter resumes.
var (
	jobLag     = 2 * time.Second  // wait for the index to catch up with a batch
	jobBackoff = 2 * time.Second  // first wait after a failed call, doubling
	jobMaxWait = 60 * time.Second // longest wait after a failed call
)

const (
	jobPageFactor = 5 // ids fetched per batch, so ids the index still lists are skipped, not resent
	jobStalls     = 5 // queries a batch may leave the match count unchanged before the job stops
	jobFailures   = 5 // failed calls in a row before the job fails
)

type writeJob struct {
	id, tool, action, filter string
	cancel                   context.CancelFunc

	mu                                     sync.Mutex
	state                                  string // running, done, failed, cancelled
	matched, processed, batches, remaining int
	lastErr                                string
	started, finished                      time.Time
}

func (j *writeJob) status() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := map[string]any{"job_id": j.id, "tool": j.tool, "action": j.action, "filter": j.filter, "state": j.state,
		"matched": j.matched, "processed": j.processed, "batches": j.batches, "remaining_estimate": j.remaining,
		"started": j.started.UTC().Format(time.RFC3339)}
	if j.lastErr != "" {
		out["last_error"] = j.lastErr
	}
	if !j.finished.IsZero() {
		out["finished"] = j.finished.UTC().Format(time.RFC3339)
	}
	return out
}

type writeJobs struct {
	mu sync.Mutex
	m  map[string]*writeJob
	wg sync.WaitGroup
}

func newWriteJobs() *writeJobs { return &writeJobs{m: map[string]*writeJob{}} }

// Close cancels every running job and waits for it to stop.
func (js *writeJobs) Close() {
	js.mu.Lock()
	for _, j := range js.m {
		j.cancel()
	}
	js.mu.Unlock()
	js.wg.Wait()
}

func (js *writeJobs) get(id string) (*writeJob, error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if j := js.m[id]; j != nil {
		return j, nil
	}
	return nil, fmt.Errorf("no write job %q: jobs live in memory and end when the server restarts; rerun the filter write to resume", id)
}

// list is every job this server has run, newest first.
func (js *writeJobs) list() []any {
	js.mu.Lock()
	all := slices.SortedFunc(maps.Values(js.m), func(a, b *writeJob) int { return b.started.Compare(a.started) })
	js.mu.Unlock()
	out := make([]any, len(all))
	for i, j := range all {
		out[i] = j.status()
	}
	return out
}

// startJob checks a filter write too large for one call and starts it in
// the background, returning at once.
func (d Deps) startJob(ctx context.Context, tool string, a Action, w WriteCall, total int) (map[string]any, error) {
	limit := d.bulkCap(a)
	js := d.writes
	js.mu.Lock()
	defer js.mu.Unlock()
	// Two jobs on one action could pick the same records and send them twice.
	for _, o := range js.m {
		if o.tool == tool && o.action == a.Name && o.status()["state"] == "running" {
			return nil, fmt.Errorf("write job %s is already running %s %s; wait for it or cancel it (falcon_status job_cancel)", o.id, tool, a.Name)
		}
	}
	switch {
	case total > d.Config.MaxJob:
		return nil, fmt.Errorf("filter matches %d records, more than --max-job %d; narrow it", total, d.Config.MaxJob)
	case strings.TrimSpace(w.Confirm) != strconv.Itoa(total):
		return nil, fmt.Errorf("filter matches %d records; this runs as a background job in batches of %d, re-querying the filter after each, so the write must take records out of the filter (e.g. status:'new' for a close). "+
			"Check that is what you mean, then repeat with confirm=%q", total, limit, strconv.Itoa(total))
	}
	jctx, cancel := context.WithCancel(context.Background())
	j := &writeJob{id: rand.Text()[:12], tool: tool, action: a.Name, filter: w.Filter, cancel: cancel,
		state: "running", matched: total, remaining: total, started: time.Now()}
	w.job = j.id
	js.m[j.id] = j
	js.wg.Add(1)
	d.Log.Info("falcon write job started", "job_id", j.id, "tool", tool, "action", a.Name, "capability", a.Capability, "reason", w.Reason, "filter", w.Filter, "matched", total)
	go func() {
		defer js.wg.Done()
		defer cancel()
		d.runJob(jctx, tool, a, w, j)
	}()
	return map[string]any{"job_id": j.id, "matched": total, "batches_planned": (total + limit - 1) / limit, "state": "running",
		"note": "runs in the background: falcon_status action=job_status job_id=" + j.id + " for progress, job_cancel to stop. " +
			"Jobs live in memory and end if the server restarts; rerun the same filter write to resume."}, nil
}

func (d Deps) runJob(ctx context.Context, tool string, a Action, w WriteCall, j *writeJob) {
	limit := d.bulkCap(a)
	sent := map[string]bool{}
	prev, stalls, failures := -1, 0, 0
	finish := func(state, msg string) {
		j.mu.Lock()
		j.state, j.finished = state, time.Now()
		if msg != "" {
			j.lastErr = msg
		}
		j.mu.Unlock()
		st := j.status()
		lvl := slog.LevelInfo
		if state == "failed" {
			lvl = slog.LevelWarn
		}
		d.Log.Log(context.Background(), lvl, "falcon write job finished", "job_id", j.id, "tool", tool, "action", a.Name, "reason", w.Reason,
			"state", state, "processed", st["processed"], "batches", st["batches"], "error", msg)
	}
	// fail counts a failed call: a cancelled job stops, a 429, 5xx or
	// network error waits and goes on, anything else fails the job.
	fail := func(err error) bool {
		if ctx.Err() != nil {
			finish("cancelled", "")
			return true
		}
		var ae *falcon.APIError
		if errors.As(err, &ae) && ae.Status != 429 && ae.Status < 500 {
			finish("failed", err.Error())
			return true
		}
		if failures++; failures >= jobFailures {
			finish("failed", fmt.Sprintf("%d failed calls in a row; last: %v", failures, err))
			return true
		}
		j.mu.Lock()
		j.lastErr = err.Error()
		j.mu.Unlock()
		if sleepCtx(ctx, min(jobBackoff<<(failures-1), jobMaxWait)) != nil {
			finish("cancelled", "")
			return true
		}
		return false
	}
	for {
		if ctx.Err() != nil {
			finish("cancelled", "")
			return
		}
		j.mu.Lock()
		processed := j.processed
		j.mu.Unlock()
		if processed >= j.matched { // never past the confirmed count
			if n, err := d.count(ctx, a.Resolve, w.Filter); err == nil {
				j.mu.Lock()
				j.remaining = n
				j.mu.Unlock()
			}
			finish("done", "")
			return
		}
		q := url.Values{"filter": {w.Filter}, "limit": {strconv.Itoa(min(10000, limit*jobPageFactor))}}
		env, err := d.call(ctx, a.Resolve, falcon.Params{Query: q})
		if err != nil {
			if fail(fmt.Errorf("resolving filter: %w", err)) {
				return
			}
			continue
		}
		got := list(env.Resources)
		total := len(got)
		if t := env.Meta.Pagination.Total; t != nil {
			total = *t
		}
		j.mu.Lock()
		j.remaining = total
		j.mu.Unlock()
		if len(got) == 0 {
			finish("done", "")
			return
		}
		var ids []string
		for _, x := range got {
			if s, ok := x.(string); ok && !sent[s] && len(ids) < min(limit, j.matched-processed) {
				ids = append(ids, s)
			}
		}
		// The last batch must have shrunk the match count; the index may
		// lag, so wait a little before calling it no progress.
		if len(ids) == 0 || prev >= 0 && total >= prev {
			if stalls++; stalls > jobStalls {
				finish("failed", "the last batch took nothing out of the filter, so the write does not change what it matches and the job would not end; "+
					"add a clause excluding the change (e.g. status:!'closed', tags:!'x') and run it again")
				return
			}
			if sleepCtx(ctx, jobLag) != nil {
				finish("cancelled", "")
				return
			}
			continue
		}
		stalls = 0
		w.Targets = ids
		if _, err := d.send(ctx, tool, a, w); err != nil {
			if fail(err) {
				return
			}
			continue
		}
		failures, prev = 0, total
		for _, id := range ids {
			sent[id] = true
		}
		j.mu.Lock()
		j.processed += len(ids)
		j.batches++
		j.lastErr = ""
		j.mu.Unlock()
	}
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
