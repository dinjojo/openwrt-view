package server

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/alerts"
	"github.com/dinjojo/openwrt-view/pkg/events"
	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/usage"
)

func TestBuildEventMetrics(t *testing.T) {
	loc := time.FixedZone("ICT", 7*3600)
	at := func(day, h, m int) int64 { return time.Date(2026, 10, day, h, m, 0, 0, loc).Unix() }
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, loc)
	// Newest first, as the store returns them.
	evs := []events.Event{
		{At: at(22, 11, 0), Kind: "satellite", Sev: "warn", Msg: "RBS50 went offline"}, // open: 60 min to now
		{At: at(22, 9, 0), Kind: "probe", Sev: "crit", Msg: "Speed check worse", Count: 2},
		{At: at(22, 8, 0), Kind: "probe", Sev: "ok", Msg: "fine"},
		{At: at(21, 23, 30), Kind: "monitor", Sev: "info", Msg: "Monitor restarted"}, // closes the WAN outage
		{At: at(21, 23, 0), Kind: "wan", Sev: "crit", Msg: "WAN session dropped"},
		{At: at(21, 6, 30), Kind: "wifi", Sev: "info", Msg: "RBS50 is back online"}, // legacy kind
		{At: at(21, 6, 0), Kind: "wifi", Sev: "warn", Msg: "RBS50 went offline"},
		{At: at(21, 1, 12), Kind: "wan", Sev: "ok", Msg: "WAN session re-established"},
		{At: at(20, 23, 48), Kind: "wan", Sev: "crit", Msg: "WAN session dropped"},  // spans midnight
		{At: at(20, 12, 0), Kind: "monitor", Sev: "info", Msg: "Monitor restarted"}, // oldest = coverage start
	}
	wins := dayWindows(4, now)
	days := make([]ReportDay, len(wins))
	for i, w := range wins {
		days[i].Date = w.date
	}
	buildEventMetrics(days, wins, evs, now.Unix())

	if wins[0].date != "2026-10-19" || wins[3].date != "2026-10-22" || wins[3].end != now.Unix() {
		t.Fatalf("windows = %+v", wins)
	}
	if days[0].WANUpPct != nil {
		t.Errorf("Oct 19 is before any history; want null, got %v", *days[0].WANUpPct)
	}
	// Oct 20: observed 12:00–24:00 (43200 s), down 12 min (720 s) → 98.3 %.
	if p := days[1].WANUpPct; p == nil || *p != 98.3 {
		t.Errorf("Oct 20 wan_up_pct = %v, want 98.3", p)
	}
	// Oct 21: down 00:00–01:12 (72 min) + 23:00–23:30 (30 min) = 102 min of 1440 → 92.9 %.
	if p := days[2].WANUpPct; p == nil || *p != 92.9 {
		t.Errorf("Oct 21 wan_up_pct = %v, want 92.9", p)
	}
	if p := days[3].WANUpPct; p == nil || *p != 100 {
		t.Errorf("Oct 22 wan_up_pct = %v, want 100", p)
	}
	if p := days[2].SatelliteOfflineMin; p == nil || *p != 30 {
		t.Errorf("Oct 21 satellite minutes = %v, want 30", p)
	}
	if p := days[3].SatelliteOfflineMin; p == nil || *p != 60 {
		t.Errorf("Oct 22 satellite minutes = %v, want 60", p)
	}
	if p := days[2].BufferingEvents; p == nil || *p != 0 {
		t.Errorf("Oct 21 buffering = %v, want 0", p)
	}
	if p := days[3].BufferingEvents; p == nil || *p != 2 {
		t.Errorf("Oct 22 buffering = %v, want 2", p)
	}
	// Oct 19 is before the event store began: no data is null, not 0.
	if days[0].BufferingEvents != nil || days[0].SatelliteOfflineMin != nil {
		t.Errorf("Oct 19 buffering/satellite = %v / %v, want null / null", days[0].BufferingEvents, days[0].SatelliteOfflineMin)
	}
	b, err := json.Marshal(days[0])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"date":"2026-10-19","wan_up_pct":null,"latency_avg_ms":null,"latency_p95_ms":null,"buffering_events":null,"satellite_offline_min":null,"wan_rx_gb":null,"wan_tx_gb":null}`
	if string(b) != want {
		t.Errorf("uncovered day JSON = %s, want %s", b, want)
	}
}

func TestDayWindowsTZ(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	cases := []struct {
		name      string
		now       time.Time // instant (UTC)
		loc       *time.Location
		today     string
		yesterday string
		todayFrom time.Time // start of today's window
	}{
		// 20:00 UTC on Oct 21 is already 01:30 on Oct 22 in IST.
		{"ist after local midnight", time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC), ist,
			"2026-10-22", "2026-10-21", time.Date(2026, 10, 21, 18, 30, 0, 0, time.UTC)},
		{"utc same instant", time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC), time.UTC,
			"2026-10-21", "2026-10-20", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)},
		// 03:00 UTC Oct 22 = 08:30 IST Oct 22; the IST day began 18:30 UTC Oct 21.
		{"ist morning", time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC), ist,
			"2026-10-22", "2026-10-21", time.Date(2026, 10, 21, 18, 30, 0, 0, time.UTC)},
		// 18:29 UTC = 23:59 IST: still the same IST day.
		{"ist one minute before midnight", time.Date(2026, 10, 22, 18, 29, 0, 0, time.UTC), ist,
			"2026-10-22", "2026-10-21", time.Date(2026, 10, 21, 18, 30, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wins := dayWindows(2, c.now.In(c.loc))
			if wins[1].date != c.today || wins[0].date != c.yesterday {
				t.Errorf("dates = %s, %s; want %s, %s", wins[0].date, wins[1].date, c.yesterday, c.today)
			}
			if wins[1].start != c.todayFrom.Unix() || wins[1].end != c.now.Unix() {
				t.Errorf("today window = [%d, %d), want [%d, %d)", wins[1].start, wins[1].end, c.todayFrom.Unix(), c.now.Unix())
			}
			if wins[0].end != wins[1].start || wins[1].start-wins[0].start != 86400 {
				t.Errorf("yesterday window = [%d, %d) not adjacent 24 h", wins[0].start, wins[0].end)
			}
		})
	}
}

func TestReportUsesServerLocation(t *testing.T) {
	s := New("127.0.0.1:0", time.Second, 10, "", "test", orbi.New("", "", "", nil))
	// A zone far from any test host's so a wrong zone shows up as a wrong date
	// for most of the day.
	loc := time.FixedZone("TEST", 13*3600+45*60)
	s.SetLocation(loc)
	var rep Report
	_, b := get(t, s, "/api/report?days=1")
	if err := json.Unmarshal(b, &rep); err != nil || len(rep.Days) != 1 {
		t.Fatalf("report: %s (%v)", b, err)
	}
	if want := time.Now().In(loc).Format("2006-01-02"); rep.Days[0].Date != want {
		t.Errorf("report date = %s, want %s (server zone)", rep.Days[0].Date, want)
	}
	if rep.Days[0].BufferingEvents != nil || rep.Days[0].SatelliteOfflineMin != nil {
		t.Errorf("no events, no VM: want null buffering/satellite, got %s", b)
	}
}

func TestEpisodeCount(t *testing.T) {
	w := dayWindow{date: "2026-10-22", start: 1000, end: 2000}
	eps := []Incident{{Start: 999}, {Start: 1000}, {Start: 1500}, {Start: 2000}}
	cases := []struct {
		name         string
		eps          []Incident
		probeSamples int
		eventCovered bool
		want         *int
	}{
		{"episodes inside window", eps, 3, false, ip(2)},
		{"probe data, no episodes", nil, 5, false, ip(0)},
		{"event history only", nil, 0, true, ip(0)},
		{"passive episode only", []Incident{{Start: 1200, Source: "passive"}}, 0, false, ip(1)},
		{"nothing covers the day", nil, 0, false, nil},
		{"episodes outside window only", []Incident{{Start: 2500}}, 0, false, nil},
	}
	for _, c := range cases {
		got := episodeCount(c.eps, w, c.probeSamples, c.eventCovered)
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%s: got %v, want %v", c.name, deref(got), deref(c.want))
		}
	}
}

func ip(v int) *int { return &v }

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func get(t *testing.T, s *Server, path string) (string, []byte) {
	t.Helper()
	resp, err := s.app.Test(httptest.NewRequest("GET", path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: HTTP %d %s", path, resp.StatusCode, b)
	}
	return resp.Header.Get("Content-Type"), b
}

func TestNewEndpointsUnconfigured(t *testing.T) {
	s := New("127.0.0.1:0", time.Second, 10, "", "test", orbi.New("", "", "", nil))
	s.SetUsageStore(usage.New(t.TempDir()))

	cases := map[string]string{
		"/api/config": `{"alerts":{"enabled":false}}`,
		"/api/radio":  `{"ok":false,"iface":"","err":"radio interface not configured","bands":[],"neighbours":[],"at":0}`,
		"/api/usage":  `{"days":[],"days_total":7}`,
	}
	for path, want := range cases {
		if _, b := get(t, s, path); string(b) != want {
			t.Errorf("%s = %s, want %s", path, b, want)
		}
	}

	var orb map[string]json.RawMessage
	_, b := get(t, s, "/api/orbi")
	if err := json.Unmarshal(b, &orb); err != nil || string(orb["radioenv"]) != "[]" {
		t.Errorf("/api/orbi radioenv = %s (%v), want []", orb["radioenv"], err)
	}

	var rep Report
	_, b = get(t, s, "/api/report?days=40")
	if err := json.Unmarshal(b, &rep); err != nil || len(rep.Days) != 30 || rep.Alerts.Enabled {
		t.Errorf("/api/report?days=40: %d days, err %v", len(rep.Days), err)
	}

	if ct, b := get(t, s, "/manifest.webmanifest"); ct != "application/manifest+json" || len(b) == 0 {
		t.Errorf("manifest content-type %q len %d", ct, len(b))
	}
	if ct, b := get(t, s, "/icon-512.png"); ct != "image/png" || len(b) < 8 || string(b[1:4]) != "PNG" {
		t.Errorf("icon content-type %q", ct)
	}

	n, _ := alerts.New("https://ntfy.sh/topic", "")
	s.SetAlerts(n)
	if _, b := get(t, s, "/api/config"); string(b) != `{"alerts":{"enabled":true,"target":"ntfy"}}` {
		t.Errorf("/api/config with alerts = %s", b)
	}
}
