package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type add struct{ kind, sev, msg string }

// summary is the comparable part of an Event (At is wall-clock dependent).
type summary struct {
	Kind, Sev, Msg string
	Count          int
}

func summarize(evs []Event) []summary {
	out := make([]summary, len(evs))
	for i, e := range evs {
		out[i] = summary{e.Kind, e.Sev, e.Msg, e.Count}
	}
	return out
}

func equalSummaries(a, b []summary) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func seedFile(t *testing.T, evs []Event) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.json")
	b, err := json.Marshal(evs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAddCollapsesRepeats(t *testing.T) {
	tests := []struct {
		name string
		adds []add
		want []summary // newest first
	}{
		{
			name: "distinct events stay separate, newest first",
			adds: []add{{"wan", "crit", "PPPoE down"}, {"wan", "ok", "PPPoE up"}},
			want: []summary{{"wan", "ok", "PPPoE up", 1}, {"wan", "crit", "PPPoE down", 1}},
		},
		{
			name: "identical event within window becomes counted flap",
			adds: []add{{"warp", "warn", "tunnel down"}, {"warp", "warn", "tunnel down"}, {"warp", "warn", "tunnel down"}},
			want: []summary{{"warp", "warn", "tunnel down", 3}},
		},
		{
			name: "same message with different severity is not merged",
			adds: []add{{"probe", "warn", "bloat B"}, {"probe", "crit", "bloat B"}},
			want: []summary{{"probe", "crit", "bloat B", 1}, {"probe", "warn", "bloat B", 1}},
		},
		{
			name: "monitor restarts merge even with different messages",
			adds: []add{{"monitor", "info", "started v1"}, {"monitor", "info", "started v2"}},
			want: []summary{{"monitor", "info", "started v2", 2}},
		},
		{
			name: "only a leading run merges",
			adds: []add{{"warp", "warn", "down"}, {"wan", "ok", "up"}, {"warp", "warn", "down"}},
			want: []summary{{"warp", "warn", "down", 1}, {"wan", "ok", "up", 1}, {"warp", "warn", "down", 1}},
		},
		{
			name: "monitor does not merge into other kinds",
			adds: []add{{"reboot", "warn", "router rebooted"}, {"monitor", "info", "started"}},
			want: []summary{{"monitor", "info", "started", 1}, {"reboot", "warn", "router rebooted", 1}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New(filepath.Join(t.TempDir(), "events.json"))
			for _, a := range tc.adds {
				s.Add(a.kind, a.sev, a.msg)
			}
			got := summarize(s.List(100))
			if !equalSummaries(got, tc.want) {
				t.Errorf("List() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAddFlapWindow(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name      string
		seed      Event
		wantLen   int
		wantCount int
	}{
		{"recent identical event merges", Event{At: now - 60, Kind: "warp", Sev: "warn", Msg: "down", Count: 4}, 1, 5},
		{"legacy entry without count counts as one", Event{At: now - 60, Kind: "warp", Sev: "warn", Msg: "down"}, 1, 2},
		{"identical event older than ten minutes does not merge", Event{At: now - 601, Kind: "warp", Sev: "warn", Msg: "down", Count: 4}, 2, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New(seedFile(t, []Event{tc.seed}))
			s.Add("warp", "warn", "down")
			got := s.List(10)
			if len(got) != tc.wantLen {
				t.Fatalf("len(List) = %d, want %d: %+v", len(got), tc.wantLen, got)
			}
			if got[0].Count != tc.wantCount {
				t.Errorf("newest Count = %d, want %d", got[0].Count, tc.wantCount)
			}
			if got[0].At < now {
				t.Errorf("newest At = %d, want >= %d (time of the latest occurrence)", got[0].At, now)
			}
		})
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	s := New(path)
	s.Add("wan", "crit", "PPPoE down")
	s.Add("wan", "ok", "PPPoE up")
	s.Add("wan", "ok", "PPPoE up")

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: stat err = %v", err)
	}
	var onDisk []Event
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("store did not persist: %v", err)
	}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatalf("persisted file is not valid JSON: %v", err)
	}

	reloaded := New(path).List(100)
	want := s.List(100)
	if len(reloaded) != len(want) || len(onDisk) != len(want) {
		t.Fatalf("reloaded %d / on disk %d events, want %d", len(reloaded), len(onDisk), len(want))
	}
	for i := range want {
		if reloaded[i] != want[i] {
			t.Errorf("reloaded[%d] = %+v, want %+v", i, reloaded[i], want[i])
		}
	}
}

func TestNewLoadsAndCompactsHistory(t *testing.T) {
	now := time.Now().Unix()
	seed := []Event{ // newest first, as persisted
		{At: now - 10, Kind: "monitor", Sev: "info", Msg: "started v3", Count: 1},
		{At: now - 20, Kind: "monitor", Sev: "info", Msg: "started v2"}, // legacy, no count
		{At: now - 9000, Kind: "monitor", Sev: "info", Msg: "started v1", Count: 5},
		{At: now - 9100, Kind: "warp", Sev: "warn", Msg: "down", Count: 1},
		{At: now - 9200, Kind: "warp", Sev: "warn", Msg: "down", Count: 2},
		{At: now - 20000, Kind: "warp", Sev: "warn", Msg: "down", Count: 1}, // too far apart
		{At: now - 30000, Kind: "reboot", Sev: "warn", Msg: "router rebooted"},
	}
	loaded := New(seedFile(t, seed)).List(100)
	got := summarize(loaded)
	// Merged entries keep the newest occurrence's message, as Add does.
	want := []summary{
		{"monitor", "info", "started v3", 7},
		{"warp", "warn", "down", 3},
		{"warp", "warn", "down", 1},
		{"reboot", "warn", "router rebooted", 1},
	}
	if !equalSummaries(got, want) {
		t.Fatalf("loaded = %+v, want %+v", got, want)
	}
	// ...and the newest occurrence's time, so the feed shows when it last
	// happened and the flap window keeps running from there.
	wantAt := []int64{now - 10, now - 9100, now - 20000, now - 30000}
	for i, at := range wantAt {
		if loaded[i].At != at {
			t.Errorf("loaded[%d].At = now%+d, want now%+d", i, loaded[i].At-now, at-now)
		}
	}
}

func TestReloadedFlapKeepsMerging(t *testing.T) {
	// A flap run as Add persists it: one counted entry stamped with the
	// latest occurrence. Reloading must neither move its time back nor
	// break the next merge.
	now := time.Now().Unix()
	seed := []Event{
		{At: now - 30, Kind: "warp", Sev: "warn", Msg: "down", Count: 3},
		{At: now - 500, Kind: "warp", Sev: "warn", Msg: "down", Count: 1},  // adjacent, within window
		{At: now - 1050, Kind: "warp", Sev: "warn", Msg: "down", Count: 1}, // 550s after the previous one
	}
	path := seedFile(t, seed)
	s := New(path)
	got := s.List(10)
	if len(got) != 1 || got[0].Count != 5 || got[0].At != now-30 {
		t.Fatalf("loaded = %+v, want one entry Count 5 At now-30", got)
	}
	if again := New(path).List(10); len(again) != 1 || again[0] != got[0] {
		// path was not rewritten yet; reload of the same file is stable
		t.Errorf("second load = %+v, want %+v", again, got)
	}
	s.Add("warp", "warn", "down")
	got = s.List(10)
	if len(got) != 1 || got[0].Count != 6 || got[0].At < now {
		t.Fatalf("after Add = %+v, want one entry Count 6 stamped now", got)
	}
	if reloaded := New(path).List(10); len(reloaded) != 1 || reloaded[0] != got[0] {
		t.Errorf("after restart = %+v, want %+v", reloaded, got)
	}
}

func TestNewToleratesMissingOrCorruptFile(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ name, path string }{
		{"missing file", filepath.Join(dir, "nope.json")},
		{"corrupt file", corrupt},
		{"in-memory store", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.path)
			if n := len(s.List(10)); n != 0 {
				t.Fatalf("List() has %d events, want 0", n)
			}
			s.Add("config", "info", "settings saved")
			if got := s.List(10); len(got) != 1 || got[0].Msg != "settings saved" {
				t.Errorf("after Add, List() = %+v", got)
			}
		})
	}
}

func TestRingCapKeepsNewest(t *testing.T) {
	s := New("") // no persistence: keeps 1000+ adds fast
	const total = ringCap + 25
	for i := 0; i < total; i++ {
		s.Add("probe", "info", "probe "+strconv.Itoa(i))
	}
	got := s.List(total)
	if len(got) != ringCap {
		t.Fatalf("len(List) = %d, want %d", len(got), ringCap)
	}
	if got[0].Msg != "probe "+strconv.Itoa(total-1) {
		t.Errorf("newest = %q, want the last added", got[0].Msg)
	}
	if want := "probe " + strconv.Itoa(total-ringCap); got[ringCap-1].Msg != want {
		t.Errorf("oldest kept = %q, want %q", got[ringCap-1].Msg, want)
	}
}

func TestListBoundsAndIsolation(t *testing.T) {
	s := New("")
	for _, m := range []string{"a", "b", "c"} {
		s.Add("wan", "info", m)
	}
	tests := []struct {
		n    int
		want []string
	}{
		{0, []string{}},
		{2, []string{"c", "b"}},
		{3, []string{"c", "b", "a"}},
		{50, []string{"c", "b", "a"}},
	}
	for _, tc := range tests {
		got := s.List(tc.n)
		if len(got) != len(tc.want) {
			t.Errorf("List(%d) len = %d, want %d", tc.n, len(got), len(tc.want))
			continue
		}
		for i := range got {
			if got[i].Msg != tc.want[i] {
				t.Errorf("List(%d)[%d] = %q, want %q", tc.n, i, got[i].Msg, tc.want[i])
			}
		}
	}

	out := s.List(1)
	out[0].Msg = "mutated"
	if s.List(1)[0].Msg != "c" {
		t.Error("List returned a slice aliasing the store's internal ring")
	}
}

func TestCountSince(t *testing.T) {
	now := time.Now().Unix()
	seed := []Event{
		{At: now - 100, Kind: "wan", Sev: "crit", Msg: "down a"},
		{At: now - 3600, Kind: "warp", Sev: "warn", Msg: "drop"},
		{At: now - 7200, Kind: "wan", Sev: "crit", Msg: "down b"},
		{At: now - 90000, Kind: "wan", Sev: "crit", Msg: "down c"},
	}
	s := New(seedFile(t, seed))
	tests := []struct {
		kind  string
		since int64
		want  int
	}{
		{"wan", now - 86400, 2},
		{"wan", now - 7*86400, 3},
		{"wan", now - 7200, 2}, // boundary is inclusive
		{"warp", now - 86400, 1},
		{"reboot", 0, 0},
		{"wan", now + 1, 0},
	}
	for _, tc := range tests {
		if got := s.CountSince(tc.kind, tc.since); got != tc.want {
			t.Errorf("CountSince(%q, now%+d) = %d, want %d", tc.kind, tc.since-now, got, tc.want)
		}
	}
}

func TestHookRunsOutsideLock(t *testing.T) {
	s := New("")
	type call struct{ kind, sev, msg string }
	var calls []call
	s.SetHook(func(kind, sev, msg string) {
		// Re-entering the store would deadlock if the hook ran under s.mu.
		_ = s.List(1)
		calls = append(calls, call{kind, sev, msg})
	})

	done := make(chan struct{})
	go func() {
		s.Add("warp", "crit", "tunnel down")
		s.Add("warp", "crit", "tunnel down") // collapsed, but hook still fires
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Add deadlocked: hook appears to run while the store lock is held")
	}
	want := []call{{"warp", "crit", "tunnel down"}, {"warp", "crit", "tunnel down"}}
	if len(calls) != len(want) {
		t.Fatalf("hook called %d times, want %d", len(calls), len(want))
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("hook call %d = %+v, want %+v", i, calls[i], want[i])
		}
	}
}

func TestConcurrentAddAndRead(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "events.json"))
	const writers, perWriter = 4, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				s.Add("probe", "info", "w"+strconv.Itoa(w)+"-"+strconv.Itoa(i))
			}
		}(w)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				_ = s.List(10)
				_ = s.CountSince("probe", 0)
			}
		}()
	}
	wg.Wait()
	if got := s.CountSince("probe", 0); got != writers*perWriter {
		t.Errorf("CountSince after concurrent adds = %d, want %d", got, writers*perWriter)
	}
}
