package agh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// fakeAGH mimics the AdGuard Home API surface the poller uses: Basic
// auth on every request, status, stats (modern array top lists) and
// stats info.
type fakeAGH struct {
	srv        *httptest.Server
	badCreds   atomic.Bool // every /control request answers 403
	statusBody atomic.Value
	statsBody  string
	infoBody   string
}

func newFakeAGH(t *testing.T, statsBody string) *fakeAGH {
	t.Helper()
	f := &fakeAGH{statsBody: statsBody, infoBody: `{"interval":86400}`}
	f.statusBody.Store(`{"version":"0.107.57","protection_enabled":true}`)
	gate := func(w http.ResponseWriter) bool {
		if f.badCreds.Load() {
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/control/status", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok || !gate(w) {
			return
		}
		w.Write([]byte(f.statusBody.Load().(string)))
	})
	mux.HandleFunc("/control/stats", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok || !gate(w) {
			return
		}
		w.Write([]byte(f.statsBody))
	})
	mux.HandleFunc("/control/stats/info", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok || !gate(w) {
			return
		}
		w.Write([]byte(f.infoBody))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

const modernStats = `{
  "num_dns_queries": 48213,
  "num_blocked_filtering": 8671,
  "num_replaced_safebrowsing": 3,
  "num_replaced_parental": 0,
  "top_queried_domains": [["example.com", 900], ["ads.example.net", 400]],
  "top_blocked_domains": [["doubleclick.net", 300], ["tracker.io", 150], ["ads.example.net", 40]],
  "top_clients": [["192.168.1.104", 12000], ["192.168.1.5", 8000]]
}`

func TestPollerSnapshot(t *testing.T) {
	f := newFakeAGH(t, modernStats)
	p := New(Config{URL: f.srv.URL, User: "dash", Pass: "pw"})
	p.poll()
	st := p.Snapshot()
	if !st.Available || !st.ProtectionEnabled {
		t.Fatalf("snapshot not healthy: %+v", st)
	}
	if st.Version != "0.107.57" {
		t.Errorf("version not picked up: %q", st.Version)
	}
	if st.Queries != 48213 {
		t.Errorf("queries = %d", st.Queries)
	}
	// Blocked sums filtering + safebrowsing + parental.
	if st.Blocked != 8674 {
		t.Errorf("blocked = %d, want 8674", st.Blocked)
	}
	if st.IntervalHours != 24 {
		t.Errorf("interval_hours = %v, want 24 (86400 s)", st.IntervalHours)
	}
	if len(st.TopBlocked) != 3 || st.TopBlocked[0].Name != "doubleclick.net" || st.TopBlocked[0].Count != 300 {
		t.Errorf("top blocked wrong: %+v", st.TopBlocked)
	}
	if len(st.TopClients) != 2 || st.TopClients[0].Name != "192.168.1.104" {
		t.Errorf("top clients wrong: %+v", st.TopClients)
	}
	if st.At.IsZero() {
		t.Error("snapshot timestamp not set")
	}
}

func TestPollerBadCredentials(t *testing.T) {
	f := newFakeAGH(t, modernStats)
	p := New(Config{URL: f.srv.URL, User: "dash", Pass: "pw"})
	p.poll()
	if !p.Snapshot().Available {
		t.Fatal("first poll with good creds should succeed")
	}

	// Credentials stop working (password rotated in AGH): the snapshot
	// must report unavailable, not panic or keep stale availability.
	f.badCreds.Store(true)
	p.poll()
	if p.Snapshot().Available {
		t.Error("with rejected credentials the snapshot must report unavailable")
	}
}

func TestPollerProtectionEdgeEvents(t *testing.T) {
	f := newFakeAGH(t, modernStats)
	p := New(Config{URL: f.srv.URL, User: "dash", Pass: "pw"})
	var events []string
	p.SetEventHook(func(kind, sev, msg string) { events = append(events, kind+":"+sev) })
	p.poll() // baseline; no edges on the first snapshot

	f.statusBody.Store(`{"protection_enabled":false}`)
	p.poll()
	if !hasEvent(events, "dns:warn") {
		t.Errorf("protection-off edge must raise a warn event: %v", events)
	}

	f.statusBody.Store(`{"protection_enabled":true}`)
	p.poll()
	if !hasEvent(events, "dns:ok") {
		t.Errorf("protection-on recovery must raise an ok event: %v", events)
	}
}

func TestPollerUnreachableEdgeEvents(t *testing.T) {
	f := newFakeAGH(t, modernStats)
	p := New(Config{URL: f.srv.URL, User: "dash", Pass: "pw"})
	var events []string
	p.SetEventHook(func(kind, sev, msg string) { events = append(events, kind+":"+sev) })
	p.poll()
	url := f.srv.URL
	f.srv.Close() // AGH process gone
	p.cfg.URL = url
	p.poll()
	if !hasEvent(events, "dns:warn") {
		t.Errorf("unreachable edge must raise a warn event: %v", events)
	}
}

func TestLegacyMapTopLists(t *testing.T) {
	legacy := rawNameList([]byte(`{"doubleclick.net": 5, "ads.example.net": 10}`))
	got := legacy.canonical(2)
	if len(got) != 2 || got[0].Name != "ads.example.net" || got[0].Count != 10 {
		t.Errorf("legacy map decode/sort wrong: %+v", got)
	}
}

func TestDisabledPoller(t *testing.T) {
	p := New(Config{})
	if p.Snapshot().Available {
		t.Error("unconfigured poller must report unavailable")
	}
	p.poll() // must not panic or touch the network
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Run(ctx) // must return immediately, no panic
}

// Aggressive login attempts must not trip AGH's login rate limiter: the
// poller uses Basic auth per request, never the /control/login POST.
// (Documented here because the old cookie flow could lock the dashboard
// user out of the web UI; the basic-auth flow cannot.)

func hasEvent(events []string, want string) bool {
	for _, e := range events {
		if e == want {
			return true
		}
	}
	return false
}
