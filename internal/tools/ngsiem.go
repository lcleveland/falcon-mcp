package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// NGSIEM query jobs run past one tool call: search polls for pollFor, then
// hands back a cursor for the job. Live jobs wait in a small table and are
// stopped when nobody resumes them within jobTTL, or at shutdown.
var (
	pollFor   = 25 * time.Second
	pollEvery = time.Second
	jobTTL    = 2 * time.Minute
)

const maxJobs = 16

type job struct {
	repo, id string
	born     time.Time
	timer    *time.Timer
}

type jobs struct {
	c   *falcon.Client
	log *slog.Logger
	mu  sync.Mutex
	m   map[string]*job // by job id

	closed bool
}

func newJobs(c *falcon.Client, log *slog.Logger) *jobs {
	return &jobs{c: c, log: log, m: map[string]*job{}}
}

// park keeps j for a later resume, evicting the oldest job when full.
func (js *jobs) park(j *job) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.closed {
		go js.stop(j)
		return
	}
	if len(js.m) >= maxJobs {
		var old *job
		for _, x := range js.m {
			if old == nil || x.born.Before(old.born) {
				old = x
			}
		}
		js.dropLocked(old)
	}
	var t *time.Timer
	t = time.AfterFunc(jobTTL, func() {
		js.mu.Lock()
		defer js.mu.Unlock()
		// A stale timer of a job taken and parked again must not drop it.
		if js.m[j.id] == j && j.timer == t {
			js.dropLocked(j)
		}
	})
	j.timer = t
	js.m[j.id] = j
}

// take removes a parked job so one caller polls it at a time.
func (js *jobs) take(id string) *job {
	js.mu.Lock()
	defer js.mu.Unlock()
	j := js.m[id]
	if j != nil {
		j.timer.Stop()
		delete(js.m, id)
	}
	return j
}

func (js *jobs) dropLocked(j *job) {
	j.timer.Stop()
	delete(js.m, j.id)
	go js.stop(j)
}

// stop asks Falcon to end a job; a job that already ended is no error.
func (js *jobs) stop(j *job) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := js.c.Do(ctx, "StopSearchV1", falcon.Params{Path: map[string]string{"repository": j.repo, "id": j.id}}); err != nil {
		js.log.Debug("stopping NGSIEM job", "error", err)
	}
}

// Close stops every parked job.
func (js *jobs) Close() {
	js.mu.Lock()
	all := make([]*job, 0, len(js.m))
	for _, j := range js.m {
		j.timer.Stop()
		all = append(all, j)
	}
	clear(js.m)
	js.closed = true
	js.mu.Unlock()
	var wg sync.WaitGroup
	for _, j := range all {
		wg.Go(func() { js.stop(j) })
	}
	wg.Wait()
}

type searchStatus struct {
	Done      bool           `json:"done"`
	Cancelled bool           `json:"cancelled"`
	Events    []any          `json:"events"`
	MetaData  map[string]any `json:"metaData"`
	Warnings  []any          `json:"warnings"`
}

func ngsiemSearch(ctx context.Context, d Deps, in Input) (map[string]any, error) {
	repo := in.Repository
	if repo == "" {
		repo = "search-all"
	}
	if strings.ContainsAny(repo, `/\%`) || repo == "." || repo == ".." || strings.TrimSpace(repo) == "" {
		return nil, fmt.Errorf("repository %q: pass a plain repository or view name, e.g. search-all", repo)
	}
	key := queryKey("falcon_ngsiem", "search", in.Query, repo, in.Start, in.End, in.Fields)
	id, err := decodeCursor(key, in.Cursor)
	if err != nil {
		return nil, err
	}

	var j *job
	if id != "" {
		if j = d.jobs.take(id); j == nil {
			return nil, errors.New("the search job behind this cursor has expired; run the search again without cursor")
		}
	} else {
		if strings.TrimSpace(in.Query) == "" {
			return nil, errors.New("this action needs query")
		}
		body := map[string]any{"queryString": in.Query, "start": when(in.Start, "1d"), "isLive": false}
		if in.End != "" {
			body["end"] = when(in.End, "")
		}
		raw, err := d.Client.Do(ctx, "StartSearchV1", falcon.Params{Path: map[string]string{"repository": repo}, Body: body})
		if err != nil {
			return nil, err
		}
		var started struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &started); started.ID == "" {
			return nil, errors.New("Falcon started no NGSIEM job (no id in the reply)")
		}
		j = &job{repo: repo, id: started.ID, born: time.Now()}
	}

	st, err := d.poll(ctx, j)
	if err != nil {
		go d.jobs.stop(j)
		return nil, err
	}
	meta := project(st.MetaData, []string{"eventCount", "processedEvents", "workDone", "totalWork", "isAggregate", "filterQuery.queryString"})
	progress := map[string]any{"meta": meta}
	if w := append(st.Warnings, list(st.MetaData["warnings"])...); len(w) > 0 {
		progress["warnings"] = w
	}
	if !st.Done {
		d.jobs.park(j)
		progress["done"] = false
		progress["next_cursor"] = encodeCursor(key, j.id)
		progress["note"] = "the search is still running; call again with this cursor and the same query to keep waiting"
		return progress, nil
	}
	out := shape(st.Events, in.Fields, "", "result too large; aggregate in the query (groupBy, head) or pass fields", nil)
	out["done"] = true
	out["job"] = progress
	if st.Cancelled {
		out["cancelled"] = true
	}
	return out, nil
}

// poll asks for the job's status until it is done or pollFor runs out.
func (d Deps) poll(ctx context.Context, j *job) (*searchStatus, error) {
	deadline := time.Now().Add(pollFor)
	for {
		raw, err := d.Client.Do(ctx, "GetSearchStatusV1", falcon.Params{Path: map[string]string{"repository": j.repo, "id": j.id}})
		if err != nil {
			return nil, err
		}
		var st searchStatus
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("decoding NGSIEM job status: %w", err)
		}
		if st.Done || st.Cancelled || time.Now().After(deadline) {
			return &st, nil
		}
		wait := pollEvery
		if ms, ok := st.MetaData["pollAfter"].(float64); ok && ms > 0 {
			wait = min(time.Duration(ms)*time.Millisecond, 5*time.Second)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// when sends an RFC 3339 time as epoch milliseconds and anything else (a
// relative time such as 1d) as given, for Falcon to judge.
func when(s, def string) any {
	if s == "" {
		return def
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UnixMilli()
	}
	return s
}
