package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// ── fake VictoriaMetrics ─────────────────────────────────────────────

type vmSample struct {
	ts  int64
	val string
}

type vmSeries struct {
	labels map[string]string
	points []vmSample // one point for instant vectors, many for matrices
}

// fakeVM answers /api/v1/query and /api/v1/query_range from canned series.
// Instant answers are keyed by exact query; raw (range-selector) instant
// queries are keyed by the selector before the trailing "[Ns]". Anything
// unknown is an empty success.
type fakeVM struct {
	mu      sync.Mutex
	instant map[string][]vmSeries // exact query → vector
	raw     map[string][]vmSeries // selector prefix → matrix (QueryRaw)
	rng     map[string][]vmSeries // exact query → matrix (QueryRange)
	seen    []string
}

func newFakeVM() *fakeVM {
	return &fakeVM{instant: map[string][]vmSeries{}, raw: map[string][]vmSeries{}, rng: map[string][]vmSeries{}}
}

func (f *fakeVM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("query")
	f.mu.Lock()
	f.seen = append(f.seen, r.URL.Path+" "+q)
	f.mu.Unlock()

	type res struct {
		Metric map[string]string `json:"metric"`
		Value  []interface{}     `json:"value,omitempty"`
		Values [][]interface{}   `json:"values,omitempty"`
	}
	resultType, result := "vector", []res{}
	addMatrix := func(ss []vmSeries) {
		resultType = "matrix"
		for _, s := range ss {
			rr := res{Metric: s.labels}
			for _, p := range s.points {
				rr.Values = append(rr.Values, []interface{}{p.ts, p.val})
			}
			result = append(result, rr)
		}
	}
	switch r.URL.Path {
	case "/api/v1/query":
		if ss, ok := f.instant[q]; ok {
			for _, s := range ss {
				result = append(result, res{Metric: s.labels, Value: []interface{}{s.points[0].ts, s.points[0].val}})
			}
		} else if i := strings.LastIndex(q, "["); i > 0 && strings.HasSuffix(q, "s]") {
			if ss, ok := f.raw[q[:i]]; ok {
				addMatrix(ss)
			}
		}
	case "/api/v1/query_range":
		if ss, ok := f.rng[q]; ok {
			addMatrix(ss)
		}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   map[string]interface{}{"resultType": resultType, "result": result},
	})
}

func inst(labels map[string]string, val float64) vmSeries {
	return vmSeries{labels: labels, points: []vmSample{{ts: 1766000000, val: fmt.Sprint(val)}}}
}

func matrix(labels map[string]string, ts []int64, vals ...float64) vmSeries {
	s := vmSeries{labels: labels}
	for i, v := range vals {
		t := int64(1766000000 + i*120)
		if ts != nil {
			t = ts[i]
		}
		s.points = append(s.points, vmSample{ts: t, val: fmt.Sprint(v)})
	}
	return s
}

func lbl(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// ── percentile ───────────────────────────────────────────────────────

func TestPercentile(t *testing.T) {
	hundred := make([]float64, 100)
	for i := range hundred {
		hundred[i] = float64(100 - i) // reversed: percentile must sort
	}
	cases := []struct {
		name string
		vals []float64
		p    float64
		want float64
	}{
		{"empty", nil, 50, 0},
		{"single p50", []float64{7}, 50, 7},
		{"single p99", []float64{7}, 99, 7},
		{"1..100 p50", hundred, 50, 50.5},  // rank 49.5 → between 50 and 51
		{"1..100 p95", hundred, 95, 95.05}, // rank 94.05
		{"1..100 p99", hundred, 99, 99.01}, // rank 98.01
		{"1..100 p0", hundred, 0, 1},       // clamps to min
		{"1..100 p100", hundred, 100, 100}, // clamps to max
		{"two values p25", []float64{10, 20}, 25, 12.5},
	}
	for _, c := range cases {
		if got := percentile(c.vals, c.p); !approx(got, c.want) {
			t.Errorf("%s: percentile = %v, want %v", c.name, got, c.want)
		}
	}
	if hundred[0] != 100 {
		t.Errorf("percentile mutated its input")
	}
}

// ── parseTrendWindow ─────────────────────────────────────────────────

func TestParseTrendWindowPresets(t *testing.T) {
	const now = int64(1766000000)
	want := map[string]int64{"6h": 6, "12h": 12, "24h": 24, "3d": 72, "7d": 168, "14d": 336, "30d": 720, "90d": 2160}
	if len(trendPresets) != len(want) {
		t.Errorf("trendPresets has %d entries, want %d", len(trendPresets), len(want))
	}
	for rng, h := range want {
		w, err := parseTrendWindow(rng, "", "", now)
		if err != nil {
			t.Errorf("%s: %v", rng, err)
			continue
		}
		if w.Label != rng || w.End != now || w.Start != now-h*3600 {
			t.Errorf("%s: got %+v, want start %d end %d", rng, w, now-h*3600, now)
		}
	}
	for _, bad := range []string{"bogus", "", "1h", "48h"} {
		if _, err := parseTrendWindow(bad, "", "", now); err == nil {
			t.Errorf("range %q: expected error", bad)
		}
	}
}

func TestParseTrendWindowCustom(t *testing.T) {
	const now = int64(1766000000)
	i64 := func(v int64) string { return fmt.Sprint(v) }
	cases := []struct {
		name         string
		start, end   string
		wantErr      bool
		wStart, wEnd int64
	}{
		{"happy path", i64(now - 2*86400), i64(now - 86400), false, now - 2*86400, now - 86400},
		{"end in future clamps to now", i64(now - 3600*5), i64(now + 86400), false, now - 3600*5, now},
		{"missing end defaults to now", i64(now - 7200), "", false, now - 7200, now},
		{"garbage end ignored", i64(now - 7200), "abc", false, now - 7200, now},
		{"exactly 1h ok", i64(now - 3600), i64(now), false, now - 3600, now},
		{"exactly 90d ok", i64(now - 90*86400), i64(now), false, now - 90*86400, now},
		{"under 1h", i64(now - 3599), i64(now), true, 0, 0},
		{"over 90d", i64(now - 90*86400 - 1), i64(now), true, 0, 0},
		{"end before start", i64(now - 3600), i64(now - 7200), true, 0, 0},
		{"invalid start", "yesterday", i64(now), true, 0, 0},
		{"zero start", "0", i64(now), true, 0, 0},
		{"negative start", "-5", i64(now), true, 0, 0},
	}
	for _, c := range cases {
		// The preset is ignored whenever start is given.
		w, err := parseTrendWindow("bogus", c.start, c.end, now)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got %+v", c.name, w)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if w.Label != "custom" || w.Start != c.wStart || w.End != c.wEnd {
			t.Errorf("%s: got %+v, want custom %d..%d", c.name, w, c.wStart, c.wEnd)
		}
	}
}

// ── selector / step helpers ──────────────────────────────────────────

func TestDurStr(t *testing.T) {
	cases := map[int64]string{
		86400:     "1d",
		7 * 86400: "7d",
		7200:      "2h",
		3600:      "1h",
		25 * 3600: "25h",
		5400:      "1h30m",
		3660:      "1h1m",
		3601:      "1h1s",
		3661:      "1h1m1s",
		5430:      "1h30m30s",
	}
	for sec, want := range cases {
		if got := durStr(sec); got != want {
			t.Errorf("durStr(%d) = %q, want %q", sec, got, want)
		}
	}
}

func TestTrendWindowSel(t *testing.T) {
	cases := []struct {
		w    trendWindow
		want string
	}{
		{trendWindow{Start: 1766000000 - 86400, End: 1766000000}, "[1d] @ 1766000000"},
		{trendWindow{Start: 1765000000 - 7200, End: 1765000000}, "[2h] @ 1765000000"},
		{trendWindow{Start: 1765000000 - 5400, End: 1765000000}, "[1h30m] @ 1765000000"},
	}
	for _, c := range cases {
		if got := c.w.sel(); got != c.want {
			t.Errorf("sel(%+v) = %q, want %q", c.w, got, c.want)
		}
	}
}

func TestTrendWindowStep(t *testing.T) {
	const end = int64(1766000000)
	cases := []struct {
		hours    int64
		step     string
		expected float64
	}{
		{1, "120s", 30},
		{24, "120s", 720},
		{25, "900s", 100},
		{168, "900s", 672},
		{169, "3600s", 169},
		{2160, "3600s", 2160},
	}
	for _, c := range cases {
		w := trendWindow{Start: end - c.hours*3600, End: end}
		if got := w.step(); got != c.step {
			t.Errorf("%dh: step = %q, want %q", c.hours, got, c.step)
		}
		if got := w.expectedSamples(); !approx(got, c.expected) {
			t.Errorf("%dh: expectedSamples = %v, want %v", c.hours, got, c.expected)
		}
	}
}

// ── addTrends with a fake VM ─────────────────────────────────────────

func newTrendServer(t *testing.T, f *fakeVM) *Server {
	t.Helper()
	s := New("127.0.0.1:0", time.Second, 10, "", "test", orbi.New("", "", "", nil))
	if f != nil {
		ts := httptest.NewServer(f)
		t.Cleanup(ts.Close)
		s.vmc = vm.New(ts.URL)
	}
	return s
}

func TestAddTrends(t *testing.T) {
	const end = int64(1766000000)
	w := trendWindow{Label: "24h", Start: end - 86400, End: end}
	sel := w.sel()
	f := newFakeVM()

	// Latency: two ping targets.
	q := func(format string) string { return fmt.Sprintf(format, sel) }
	f.instant[q(`quantile_over_time(0.99, collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 40), inst(lbl("ping", "8.8.8.8"), 60)}
	f.instant[q(`quantile_over_time(0.95, collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 20), inst(lbl("ping", "8.8.8.8"), 30)}
	f.instant[q(`quantile_over_time(0.50, collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 10), inst(lbl("ping", "8.8.8.8"), 15)}
	f.instant[q(`count_over_time(collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 500), inst(lbl("ping", "8.8.8.8"), 700)}
	f.instant[q(`avg(avg_over_time(collectd_ping_ping_stddev%s))`)] = []vmSeries{inst(nil, 2.5)}

	// Shaper: upload has throughput + ceiling; download has only a ceiling.
	upTx := []float64{100e6, 200e6, 300e6, 380e6, 390e6}
	f.rng[`sum(rate(collectd_sqm_bytes{type="tx",sqm="eth0"}[5m]))*8`] = []vmSeries{matrix(nil, nil, upTx...)}
	f.instant[`max(collectd_sqm_gauge{type="configured_bw_bps",sqm="eth0"})`] = []vmSeries{inst(nil, 50000000)}
	f.instant[`max(collectd_sqm_gauge{type="configured_bw_bps",sqm="ifb4eth0"})`] = []vmSeries{inst(nil, 100000000)}

	// AQM: tin-t0 series per direction, plus a non-t0 tin that must be ignored.
	f.instant[q(`sum by (type, sqm) (increase(collectd_sqm_gauge{type=~"ecn_marks|drops",sqm=~"(eth0|ifb4eth0)-tin.*"}%s))`)] = []vmSeries{
		inst(lbl("type", "ecn_marks", "sqm", "eth0-tin-t0"), 11),
		inst(lbl("type", "drops", "sqm", "eth0-tin-t0"), 3),
		inst(lbl("type", "ecn_marks", "sqm", "ifb4eth0-tin-t0"), 42),
		inst(lbl("type", "drops", "sqm", "ifb4eth0-tin-t0"), 7),
		inst(lbl("type", "drops", "sqm", "ifb4eth0-tin-t1"), 999),
	}
	// The query itself divides by 1000 (µs → ms); VM returns ms.
	f.instant[q(`quantile_over_time(0.95, collectd_sqm_gauge{type="peak_delay_us",sqm=~"(eth0|ifb4eth0)-tin.*"}%s)/1000`)] = []vmSeries{
		inst(lbl("sqm", "eth0-tin-t0"), 4.2),
		inst(lbl("sqm", "ifb4eth0-tin-t0"), 12.5),
	}
	f.instant[`max(collectd_sqm_gauge{type="target_us"})/1000`] = []vmSeries{inst(nil, 5.5)}

	// Bufferbloat: two local days of down-direction probes, one negative.
	day1 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.Local).Unix()
	day2 := time.Date(2026, 10, 21, 10, 0, 0, 0, time.Local).Unix()
	f.raw[`probe_bloat_ms{direction="down"}`] = []vmSeries{
		matrix(nil, []int64{day1, day1 + 3600, day1 + 7200, day2}, 20, -3, 13, -5)}
	f.raw[`probe_bloat_grade{direction="down"}`] = []vmSeries{
		matrix(lbl("grade", "B"), []int64{day1}, 1),
		matrix(lbl("grade", "A"), []int64{day1 + 3600, day2}, 1, 1)}

	// Reliability.
	f.instant[q(`quantile_over_time(0.99, collectd_ping_ping_droprate%s)`)] = []vmSeries{inst(nil, 0.02)}
	f.instant[q(`changes(wan_session_up%s)`)] = []vmSeries{inst(nil, 4)}

	s := newTrendServer(t, f)
	var out PercentileReport
	s.addTrends(context.Background(), &out, w)
	tr := out.Trends
	if tr == nil {
		t.Fatal("Trends not set")
	}
	if tr.Range != "24h" {
		t.Errorf("Range = %q", tr.Range)
	}

	// Latency: sorted by sample count, most samples first.
	wantLat := []TrendPair{
		{Name: "8.8.8.8", P50: 15, P95: 30, P99: 60, Samples: 700},
		{Name: "1.1.1.1", P50: 10, P95: 20, P99: 40, Samples: 500},
	}
	if len(tr.Latency) != len(wantLat) {
		t.Fatalf("Latency = %+v, want %+v", tr.Latency, wantLat)
	}
	for i := range wantLat {
		if tr.Latency[i] != wantLat[i] {
			t.Errorf("Latency[%d] = %+v, want %+v", i, tr.Latency[i], wantLat[i])
		}
	}
	if tr.Stddev != 2.5 {
		t.Errorf("Stddev = %v, want 2.5", tr.Stddev)
	}

	// Shaper.
	up, ok := tr.Shaper["up"]
	if !ok {
		t.Fatalf("Shaper[up] missing: %+v", tr.Shaper)
	}
	if !approx(up.CeilingMbps, 400) {
		t.Errorf("up ceiling = %v, want 400 (50e6 B/s × 8)", up.CeilingMbps)
	}
	if want := percentile(upTx, 95) / 1e6; !approx(up.P95Mbps, want) {
		t.Errorf("up p95 = %v, want %v", up.P95Mbps, want)
	}
	if up.Samples != len(upTx) {
		t.Errorf("up samples = %d, want %d", up.Samples, len(upTx))
	}
	if !approx(up.PinnedPct, 40) { // 380 and 390 ≥ 0.9×400
		t.Errorf("up pinned = %v, want 40", up.PinnedPct)
	}
	if _, ok := tr.Shaper["down"]; ok {
		t.Errorf("Shaper[down] present without throughput samples: %+v", tr.Shaper["down"])
	}

	// AQM.
	wantAQM := map[string]AQMTrend{
		"up":   {Marks: 11, Drops: 3, PeakDelayP95: 4.2, TargetMs: 5.5},
		"down": {Marks: 42, Drops: 7, PeakDelayP95: 12.5, TargetMs: 5.5},
	}
	for k, want := range wantAQM {
		if got := tr.AQM[k]; got != want {
			t.Errorf("AQM[%s] = %+v, want %+v", k, got, want)
		}
	}

	// No headroom / Wi-Fi series → absent, not zeros.
	if tr.Headroom != nil || tr.WifiClients != nil || len(tr.WifiDevices) != 0 {
		t.Errorf("headroom/wifi should be empty: %+v %+v %+v", tr.Headroom, tr.WifiClients, tr.WifiDevices)
	}

	// Bufferbloat: negatives clamped to 0.
	down := tr.Bloat["down"]
	if len(down) != 2 {
		t.Fatalf("Bloat[down] = %+v, want 2 days", down)
	}
	if d := down[0]; d.Day != "2026-10-20" || d.MaxMS != 20 || !approx(d.AvgMS, 11) || d.Runs != 3 ||
		strings.Join(d.Grades, ",") != "B,A" {
		t.Errorf("day 1 = %+v, want max 20 avg 11 runs 3 grades B,A", d)
	}
	if d := down[1]; d.Day != "2026-10-21" || d.MaxMS != 0 || d.AvgMS != 0 || d.Runs != 1 {
		t.Errorf("day 2 = %+v, want all-negative day clamped to max 0 avg 0", d)
	}
	for _, d := range down {
		if d.MaxMS < 0 || d.AvgMS < 0 {
			t.Errorf("negative bloat leaked: %+v", d)
		}
	}
	if _, ok := tr.Bloat["up"]; ok {
		t.Errorf("Bloat[up] present without data")
	}

	if tr.WanChanges != 4 {
		t.Errorf("WanChanges = %d, want 4", tr.WanChanges)
	}
	if tr.WanP99Loss != 0.02 {
		t.Errorf("WanP99Loss = %v, want 0.02", tr.WanP99Loss)
	}
}

func TestAddTrendsLatencyUnion(t *testing.T) {
	const end = int64(1766000000)
	w := trendWindow{Label: "24h", Start: end - 86400, End: end}
	q := func(format string) string { return fmt.Sprintf(format, w.sel()) }
	f := newFakeVM()
	// "only99" has no p95 answer, the default (empty-label) target only a
	// count; both must still get a row.
	f.instant[q(`quantile_over_time(0.99, collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 40), inst(lbl("ping", "only99"), 90)}
	f.instant[q(`quantile_over_time(0.95, collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 20)}
	f.instant[q(`quantile_over_time(0.50, collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 10)}
	f.instant[q(`count_over_time(collectd_ping%s)`)] = []vmSeries{
		inst(lbl("ping", "1.1.1.1"), 500), inst(nil, 300)}

	s := newTrendServer(t, f)
	var out PercentileReport
	s.addTrends(context.Background(), &out, w)
	want := []TrendPair{
		{Name: "1.1.1.1", P50: 10, P95: 20, P99: 40, Samples: 500},
		{Name: "wan", Samples: 300},
		{Name: "only99", P99: 90},
	}
	got := out.Trends.Latency
	if len(got) != len(want) {
		t.Fatalf("Latency = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Latency[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestAddTrendsWifiPresentClamped(t *testing.T) {
	const end = int64(1766000000)
	// 2h window at a 120s step → 60 expected samples per series.
	w := trendWindow{Label: "custom", Start: end - 7200, End: end}
	f := newFakeVM()
	over := make([]float64, 70) // more points than the window nominally holds
	for i := range over {
		over[i] = -50
	}
	half := make([]float64, 30)
	for i := range half {
		half[i] = -60
	}
	f.rng[`orbi_client_signal`] = []vmSeries{
		matrix(lbl("mac", "aa", "name", "phone", "band", "5G"), nil, over...),
		matrix(lbl("mac", "bb", "name", "tv", "band", "2.4G"), nil, half...),
	}
	s := newTrendServer(t, f)
	var out PercentileReport
	s.addTrends(context.Background(), &out, w)
	devs := out.Trends.WifiDevices
	if len(devs) != 2 {
		t.Fatalf("WifiDevices = %+v", devs)
	}
	if devs[0].MAC != "aa" || devs[0].PresentPct != 100 {
		t.Errorf("devs[0] = %+v, want aa clamped to 100%%", devs[0])
	}
	if devs[1].MAC != "bb" || !approx(devs[1].PresentPct, 50) {
		t.Errorf("devs[1] = %+v, want bb at 50%%", devs[1])
	}
}

func TestAddTrendsEmptyVM(t *testing.T) {
	s := newTrendServer(t, newFakeVM())
	var out PercentileReport
	w := trendWindow{Label: "custom", Start: 1766000000 - 7200, End: 1766000000}
	s.addTrends(context.Background(), &out, w)
	tr := out.Trends
	if tr == nil || tr.Range != "custom" {
		t.Fatalf("Trends = %+v", tr)
	}
	if len(tr.Latency) != 0 || len(tr.Shaper) != 0 || len(tr.AQM) != 0 || len(tr.Bloat) != 0 ||
		tr.Headroom != nil || tr.WifiClients != nil || tr.WanChanges != 0 {
		t.Errorf("empty VM produced data: %+v", tr)
	}
	b, _ := json.Marshal(tr)
	if string(b) != `{"range":"custom","wan_changes":0,"wan_p99_loss":0}` {
		t.Errorf("empty trends JSON = %s", b)
	}
}

// ── /api/percentiles end to end ──────────────────────────────────────

func getStatus(t *testing.T, s *Server, path string) (int, []byte) {
	t.Helper()
	status, _, b := getResp(t, s, path)
	return status, b
}

func getResp(t *testing.T, s *Server, path string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := s.app.Test(httptest.NewRequest("GET", path, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func TestHandleAPIPercentilesTrends(t *testing.T) {
	f := newFakeVM()
	// Trend selectors are anchored at time.Now(), so only the legacy range
	// query (keyed without a timestamp) gets canned data here.
	f.rng[`collectd_ping`] = []vmSeries{matrix(lbl("ping", "1.1.1.1"), nil, 10, 20, 30)}
	s := newTrendServer(t, f)
	now := time.Now().Unix()

	type resp struct {
		Range   string             `json:"range"`
		Targets []PercentileTarget `json:"targets"`
		Trends  *TrendReport       `json:"trends"`
	}
	cases := []struct {
		name      string
		path      string
		status    int
		wantRange string
	}{
		{"default range", "/api/percentiles", 200, "24h"},
		{"preset 24h", "/api/percentiles?range=24h", 200, "24h"},
		{"preset 7d", "/api/percentiles?range=7d", 200, "7d"},
		{"bogus range", "/api/percentiles?range=bogus", 400, ""},
		{"custom window", fmt.Sprintf("/api/percentiles?start=%d&end=%d", now-2*86400, now-86400), 200, "custom"},
		{"custom open end", fmt.Sprintf("/api/percentiles?start=%d", now-7200), 200, "custom"},
		{"tiny window", fmt.Sprintf("/api/percentiles?start=%d&end=%d", now-600, now), 400, ""},
		{"bad start", "/api/percentiles?start=abc", 400, ""},
	}
	for _, c := range cases {
		status, hdr, b := getResp(t, s, c.path)
		if status != c.status {
			t.Errorf("%s: HTTP %d, want %d (%s)", c.name, status, c.status, b)
			continue
		}
		if status != 200 {
			if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s: Content-Type %q, want application/json", c.name, ct)
			}
			var e map[string]string
			if err := json.Unmarshal(b, &e); err != nil || e["error"] == "" {
				t.Errorf("%s: error body %s not JSON with error (%v)", c.name, b, err)
			}
			continue
		}
		var r resp
		if err := json.Unmarshal(b, &r); err != nil {
			t.Errorf("%s: %v (%s)", c.name, err, b)
			continue
		}
		if r.Range != c.wantRange || r.Trends == nil || r.Trends.Range != c.wantRange {
			t.Errorf("%s: range %q trends %+v, want %q", c.name, r.Range, r.Trends, c.wantRange)
		}
		if len(r.Targets) != 1 || r.Targets[0].Name != "1.1.1.1" || r.Targets[0].P50 != 20 || r.Targets[0].Samples != 3 {
			t.Errorf("%s: targets = %+v", c.name, r.Targets)
		}
	}

	// The custom window must reach VM as the requested start/end.
	f.mu.Lock()
	defer f.mu.Unlock()
	wantSel := fmt.Sprintf("[1d] @ %d", now-86400)
	found := false
	for _, q := range f.seen {
		if strings.Contains(q, "changes(wan_session_up"+wantSel+")") {
			found = true
		}
	}
	if !found {
		t.Errorf("no changes(wan_session_up%s) query seen", wantSel)
	}
}

func TestHandleAPIPercentilesNoVM(t *testing.T) {
	s := newTrendServer(t, nil)
	status, hdr, b := getResp(t, s, "/api/percentiles?range=24h")
	if status != 503 {
		t.Errorf("HTTP %d (%s), want 503", status, b)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
	var e map[string]string
	if err := json.Unmarshal(b, &e); err != nil || e["error"] != "victoriametrics not configured" {
		t.Errorf("503 body %s (%v)", b, err)
	}
}
