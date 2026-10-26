// Package agh polls the AdGuard Home HTTP API on the router itself
// (default http://127.0.0.1:8888) and keeps a small snapshot of DNS
// filtering activity: query and block counts over AGH's stats window,
// the top blocked domains and the top clients by query volume.
//
// Authentication is preemptive HTTP Basic on every request — the
// mechanism AGH's own OpenAPI spec documents. Everything degrades to
// Available=false — the UI simply hides DNS when AGH is not configured
// or unreachable.
package agh

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// NameCount is one row of an AGH top list.
type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// State is the latest AGH snapshot.
type State struct {
	Available         bool        `json:"available"`         // API answered for the latest poll
	ProtectionEnabled bool        `json:"protection"`        // AGH filtering master switch
	Version           string      `json:"version,omitempty"` // AGH version, when reported
	Queries           int64       `json:"queries"`           // DNS queries in the stats window
	Blocked           int64       `json:"blocked"`           // filtered/blocked responses
	BlockedPct        float64     `json:"blocked_pct"`       // blocked / queries * 100
	IntervalHours     float64     `json:"interval_hours"`    // AGH stats window length; 0 = unknown
	TopBlocked        []NameCount `json:"top_blocked"`       // worst offenders, descending
	TopClients        []NameCount `json:"top_clients"`       // busiest clients, descending
	At                time.Time   `json:"-"`
}

// Config points the poller at an AGH instance.
type Config struct {
	URL  string // e.g. http://127.0.0.1:8888 (empty disables polling)
	User string // dedicated dashboard user — not the admin login
	Pass string
}

// Poller refreshes the AGH snapshot every 30 seconds. Stats move in
// minute-scale aggregates, so faster polling changes nothing.
//
// Authentication is preemptive HTTP Basic on every request — the
// mechanism AGH's own OpenAPI spec documents and what client libraries
// (adguard-client-go et al.) use. Stateless, no session to expire.
type Poller struct {
	cfg Config
	hc  *http.Client

	mu   sync.RWMutex
	st   State
	prev *State // last successful snapshot, for protection-change edges
	hook func(kind, sev, msg string)
}

// New returns a poller for cfg (nil or empty URL → disabled poller that
// always reports unavailable).
func New(cfg Config) *Poller {
	if cfg.URL == "" {
		return &Poller{}
	}
	return &Poller{
		cfg: cfg,
		hc:  &http.Client{Timeout: 5 * time.Second},
	}
}

// SetEventHook registers the events sink (called before Run).
func (p *Poller) SetEventHook(fn func(kind, sev, msg string)) { p.hook = fn }

// Snapshot returns the latest known AGH state.
func (p *Poller) Snapshot() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.st
}

// Run polls until ctx is done. The first snapshot is synchronous so the
// first UI load has data.
func (p *Poller) Run(ctx context.Context) {
	if p.cfg.URL == "" {
		return
	}
	p.poll()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.poll()
		}
	}
}

// poll fetches one snapshot. Auth is per-request Basic (see Poller), so
// there is no session to refresh; a disabled poller (empty URL) never
// touches the network.
func (p *Poller) poll() {
	if p.cfg.URL == "" || p.hc == nil {
		return
	}
	st, err := p.fetch()
	if err != nil {
		p.mu.Lock()
		prevAvail := p.st.Available
		p.st.Available = false
		p.mu.Unlock()
		if prevAvail && p.hook != nil {
			p.hook("dns", "warn", "AdGuard Home API stopped answering — DNS filtering continues, monitoring is blind")
		}
		return
	}
	p.record(st)
}

func (p *Poller) record(st State) {
	p.mu.Lock()
	prev := p.st
	st.At = time.Now()
	p.prev = &prev
	p.st = st
	p.mu.Unlock()
	if p.hook != nil && !prev.At.IsZero() {
		switch {
		case prev.Available && !st.Available:
			// handled in poll()
		case !prev.Available && st.Available:
			p.hook("dns", "ok", "AdGuard Home is answering again")
		case prev.Available && st.Available && prev.ProtectionEnabled && !st.ProtectionEnabled:
			p.hook("dns", "warn", "AdGuard Home protection was disabled — LAN DNS is no longer filtering ads and trackers")
		case prev.Available && st.Available && !prev.ProtectionEnabled && st.ProtectionEnabled:
			p.hook("dns", "ok", "AdGuard Home protection is back on")
		}
	}
}

// fetch gathers one snapshot: /control/status for protection and
// version, /control/stats for counts and top lists, /control/stats/config
// for the window length.
func (p *Poller) fetch() (State, error) {
	st := State{}
	var status struct {
		Version           string `json:"version"`
		ProtectionEnabled bool   `json:"protection_enabled"`
	}
	if err := p.getJSON("/control/status", &status); err != nil {
		return st, err
	}
	st.Available = true
	st.ProtectionEnabled = status.ProtectionEnabled
	st.Version = status.Version

	var stats struct {
		NumDNSQueries       int64       `json:"num_dns_queries"`
		NumBlockedFiltering int64       `json:"num_blocked_filtering"`
		NumReplacedSafesb   int64       `json:"num_replaced_safebrowsing"`
		NumReplacedParental int64       `json:"num_replaced_parental"`
		TopQueriedDomains   rawNameList `json:"top_queried_domains"`
		TopBlockedDomains   rawNameList `json:"top_blocked_domains"`
		TopClients          rawNameList `json:"top_clients"`
	}
	if err := p.getJSON("/control/stats", &stats); err != nil {
		return st, err
	}
	st.Queries = stats.NumDNSQueries
	st.Blocked = stats.NumBlockedFiltering + stats.NumReplacedSafesb + stats.NumReplacedParental
	if st.Queries > 0 {
		st.BlockedPct = float64(st.Blocked) / float64(st.Queries) * 100
	}
	st.TopBlocked = stats.TopBlockedDomains.canonical(5)
	st.TopClients = stats.TopClients.canonical(5)

	if info, err := p.statsIntervalHours(); err == nil {
		st.IntervalHours = info
	}
	return st, nil
}

// statsIntervalHours reads the statistics-retention window and normalises
// AGH's version-dependent encodings. AGH ≥0.107.45 exposes it as
// /control/stats/config with interval in milliseconds (24 h default =
// 86,400,000); older builds serve /control/stats/info where ≤90 means
// days (old API), larger values are seconds or nanoseconds — both
// unambiguous against the 90-day ceiling.
func (p *Poller) statsIntervalHours() (float64, error) {
	var cfg struct {
		Interval float64 `json:"interval"`
	}
	if err := p.getJSON("/control/stats/config", &cfg); err == nil && cfg.Interval > 0 {
		return cfg.Interval / 3.6e6, nil // ms → hours
	}
	var info struct {
		Interval json.Number `json:"interval"`
	}
	if err := p.getJSON("/control/stats/info", &info); err != nil {
		return 0, err
	}
	n, err := strconv.ParseFloat(info.Interval.String(), 64)
	if err != nil || n <= 0 {
		return 0, errStatus("stats-info", 0)
	}
	switch {
	case n <= 90:
		return n * 24, nil
	case n <= 90*24*3600:
		return n / 3600, nil
	default:
		return n / 3.6e12, nil
	}
}

func (p *Poller) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, p.cfg.URL+path, nil)
	if err != nil {
		return err
	}
	// Preemptive Basic auth — AGH accepts it on every /control endpoint.
	req.SetBasicAuth(p.cfg.User, p.cfg.Pass)
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errStatus(path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// rawNameList absorbs both AGH encodings: modern [["name",count],…]
// arrays and the legacy {"name":count} objects. It defers decoding by
// keeping the raw bytes — RawMessage semantics, re-declared because a
// defined type does not inherit RawMessage's method set.
type rawNameList json.RawMessage

func (r *rawNameList) UnmarshalJSON(b []byte) error {
	*r = rawNameList(append([]byte(nil), b...))
	return nil
}

func (r rawNameList) canonical(limit int) []NameCount {
	if len(r) == 0 {
		return nil
	}
	var pairs [][2]any
	if err := json.Unmarshal(r, &pairs); err == nil {
		out := make([]NameCount, 0, len(pairs))
		for _, pr := range pairs {
			name, ok := pr[0].(string)
			if !ok {
				continue
			}
			out = append(out, NameCount{Name: name, Count: toInt64(pr[1])})
		}
		sortByCount(out)
		return capList(out, limit)
	}
	var objs []map[string]int64
	if err := json.Unmarshal(r, &objs); err == nil {
		// AGH ≥0.107.45: [{"name":count},{name2:count2},…]
		out := make([]NameCount, 0, len(objs))
		for _, o := range objs {
			for name, count := range o {
				out = append(out, NameCount{Name: name, Count: count})
			}
		}
		sortByCount(out)
		return capList(out, limit)
	}
	var m map[string]int64
	if err := json.Unmarshal(r, &m); err != nil {
		return nil
	}
	out := make([]NameCount, 0, len(m))
	for k, v := range m {
		out = append(out, NameCount{Name: k, Count: v})
	}
	sortByCount(out)
	return capList(out, limit)
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case string:
		x, _ := strconv.ParseInt(n, 10, 64)
		return x
	}
	return 0
}

func sortByCount(l []NameCount) {
	sort.Slice(l, func(i, j int) bool { return l[i].Count > l[j].Count })
}

func capList(l []NameCount, n int) []NameCount {
	if len(l) > n {
		return l[:n]
	}
	return l
}
