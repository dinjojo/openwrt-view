package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/types"
	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// sample is one value for the fake VictoriaMetrics: labels, timestamp and
// value. For range/raw queries several samples with the same labels form
// one series.
type sample struct {
	labels map[string]string
	ts     int64
	val    float64
}

// fakeVM answers /api/v1/query and /api/v1/query_range from a table keyed
// by query string (range-vector selectors like `x[123s]` are keyed by the
// bare selector `x`). Unknown queries return an empty result. A query
// mapped to nil samples with key in fail returns an API error.
type fakeVM struct {
	data map[string][]sample
	rng  map[string][]sample // when non-nil, replaces data for /api/v1/query_range
	fail map[string]bool
}

func (f *fakeVM) client(t *testing.T) *vm.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return vm.New(srv.URL)
}

func (f *fakeVM) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("query")
	key := q
	raw := false
	if i := strings.LastIndex(q, "["); i > 0 && strings.HasSuffix(q, "s]") && r.URL.Path == "/api/v1/query" {
		key, raw = q[:i], true
	}
	if f.fail[key] {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "error", "error": "boom"})
		return
	}
	samples := f.data[key]
	if r.URL.Path == "/api/v1/query_range" && f.rng != nil {
		samples = f.rng[key]
	}
	var result []any
	if r.URL.Path == "/api/v1/query_range" || raw {
		// group into series by label set
		order := []string{}
		series := map[string]map[string]any{}
		for _, s := range samples {
			lk, _ := json.Marshal(s.labels)
			k := string(lk)
			if series[k] == nil {
				series[k] = map[string]any{"metric": s.labels, "values": []any{}}
				order = append(order, k)
			}
			series[k]["values"] = append(series[k]["values"].([]any), []any{s.ts, strconv.FormatFloat(s.val, 'f', -1, 64)})
		}
		for _, k := range order {
			result = append(result, series[k])
		}
	} else {
		for _, s := range samples {
			result = append(result, map[string]any{"metric": s.labels, "value": []any{s.ts, strconv.FormatFloat(s.val, 'f', -1, 64)}})
		}
	}
	if result == nil {
		result = []any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "vector", "result": result},
	})
}

func v(val float64) []sample { return []sample{{ts: time.Now().Unix(), val: val}} }

func lv(label, value string, val float64) sample {
	return sample{labels: map[string]string{label: value}, ts: time.Now().Unix(), val: val}
}

func TestEvalWANLatency(t *testing.T) {
	const (
		rtt    = `collectd_ping`
		rttTCP = `wan_connect_rtt_ms`
		loss   = `collectd_ping_ping_droprate`
		base   = `avg_over_time(collectd_ping[1h] offset 1w)`
	)
	pings := func(a, b float64) []sample { return []sample{lv("ping", "1.1.1.1", a), lv("ping", "8.8.8.8", b)} }
	cases := []struct {
		name string
		vm   *fakeVM
		w    want
	}{
		{"query error", &fakeVM{fail: map[string]bool{rtt: true}},
			want{state: StateUnknown, value: "—", contains: []string{"ping query failed"}}},
		{"no ping data", &fakeVM{}, want{state: StateWarn, value: "—", contains: []string{"RTT monitor"}}},
		{"tcp rtt preferred", &fakeVM{data: map[string][]sample{rtt: pings(100, 100), rttTCP: []sample{lv("target", "8.8.8.8", 5)}}},
			want{state: StateOK, value: "5.0 ms avg", contains: []string{"8.8.8.8"}}},
		{"healthy", &fakeVM{data: map[string][]sample{rtt: pings(10, 20), loss: v(0)}},
			want{state: StateOK, value: "15.0 ms avg", contains: []string{"20.0 ms to 8.8.8.8, 0.0% loss"}}},
		{"slow host warns", &fakeVM{data: map[string][]sample{rtt: pings(10, 60)}},
			want{state: StateWarn, contains: []string{"60.0 ms to 8.8.8.8"}}},
		{"very slow is crit", &fakeVM{data: map[string][]sample{rtt: pings(150, 20)}},
			want{state: StateCrit, contains: []string{"150.0 ms to 1.1.1.1"}}},
		{"light loss warns", &fakeVM{data: map[string][]sample{rtt: pings(10, 10), loss: v(0.02)}},
			want{state: StateWarn, contains: []string{"2.0% loss"}}},
		{"heavy loss is crit", &fakeVM{data: map[string][]sample{rtt: pings(10, 10), loss: v(0.1)}},
			want{state: StateCrit, contains: []string{"10.0% loss"}}},
		{"same as usual", &fakeVM{data: map[string][]sample{rtt: pings(10, 20), base: v(14)}},
			want{state: StateOK, contains: []string{"same as usual", "typically 14.0 ms"}}},
		{"unusually slow vs last week", &fakeVM{data: map[string][]sample{rtt: pings(35, 45), base: v(10)}},
			want{state: StateWarn, contains: []string{"unusually slow", "40.0 ms now vs a typical 10.0 ms"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalWANLatency(context.Background(), c.vm.client(t))
			checkCommon(t, got, "Internet response time", c.w)
		})
	}
	checkCommon(t, evalWANLatency(context.Background(), nil), "Internet response time", want{state: StateUnknown})
}

func TestEvalSystem(t *testing.T) {
	const (
		temp = `max(collectd_thermal_temperature)`
		load = `node_load1`
		mem  = `100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`
	)
	sys := func(tc, l, m float64) *fakeVM {
		return &fakeVM{data: map[string][]sample{temp: v(tc), load: v(l), mem: v(m)}}
	}
	cases := []struct {
		name string
		vm   *fakeVM
		w    want
	}{
		{"thermal query error", &fakeVM{fail: map[string]bool{temp: true}},
			want{state: StateUnknown, value: "—", contains: []string{"thermal query failed"}}},
		{"healthy", sys(52, 0.42, 63),
			want{state: StateOK, value: "52°C", contains: []string{"SoC 52°C, load 0.42, 63% RAM free"}, absent: []string{"check cooling"}}},
		{"warm", sys(78, 1, 60), want{state: StateWarn, contains: []string{"check cooling"}}},
		{"hot", sys(88, 1, 60), want{state: StateCrit}},
		{"low memory", sys(50, 1, 15), want{state: StateWarn}},
		{"memory exhausted", sys(50, 1, 5), want{state: StateCrit}},
		{"missing memory metric assumes free", &fakeVM{data: map[string][]sample{temp: v(50)}},
			want{state: StateOK, contains: []string{"100% RAM free"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkCommon(t, evalSystem(context.Background(), c.vm.client(t)), "Temperature & memory", c.w)
		})
	}
	checkCommon(t, evalSystem(context.Background(), nil), "Temperature & memory", want{state: StateUnknown})
}

func TestEvalCPU(t *testing.T) {
	const cpuQ = `100 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100`
	// 40 Mbit shaper: 2.5e6 B/s = 50% load.
	half := []types.CakeStats{{Interface: "eth0", Bandwidth: "40Mbit", TxBytesPerS: 2.5e6}, {Interface: "ifb4eth0", Bandwidth: "400Mbit", TxBytesPerS: 1e6}}
	idle := []types.CakeStats{{Interface: "eth0", Bandwidth: "40Mbit", TxBytesPerS: 1e4}}
	cases := []struct {
		name string
		cpu  []sample
		live []types.CakeStats
		w    want
	}{
		{"no data", nil, half, want{state: StateUnknown, value: "—", contains: []string{"node-exporter"}}},
		{"headroom", v(20), half, want{state: StateOK, value: "20%", contains: []string{"plenty of headroom"}}},
		{"busy while shaping", v(80), half, want{state: StateWarn, value: "80%", contains: []string{"shaping 50%"}}},
		{"cpu bottleneck", v(95), half, want{state: StateCrit, contains: []string{"bottleneck"}}},
		{"busy for other reasons", v(95), idle, want{state: StateOK, contains: []string{"something else"}}},
		{"no cake interfaces", v(95), nil, want{state: StateOK, contains: []string{"something else"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeVM{data: map[string][]sample{cpuQ: c.cpu}}
			checkCommon(t, evalCPU(context.Background(), f.client(t), c.live), "Router CPU", c.w)
		})
	}
	checkCommon(t, evalCPU(context.Background(), nil, half), "Router CPU", want{state: StateUnknown})
}

func TestEvalWANLink(t *testing.T) {
	const wanDev = `device=~"(wan|pppoe|eth0).*"`
	infoQ := `count(node_network_info{` + wanDev + `}) by (device)`
	errsQ := `sum(increase(node_network_receive_errs_total{` + wanDev + `}[1h]))
		+ sum(increase(node_network_transmit_errs_total{` + wanDev + `}[1h]))
		+ sum(increase(node_network_transmit_carrier_total{` + wanDev + `}[1h]))`
	dropsQ := `sum(increase(node_network_receive_drop_total{` + wanDev + `}[1h]))
		+ sum(increase(node_network_transmit_drop_total{` + wanDev + `}[1h]))`
	info := []sample{lv("device", "pppoe-wan", 1), lv("device", "eth0", 1)}
	hist := func(vals ...float64) []sample {
		out := make([]sample, len(vals))
		for i, x := range vals {
			out[i] = sample{ts: int64(1000 + i*3600), val: x}
		}
		return out
	}
	// dropsQ is queried twice: instant (last hour, data) and as a 24h
	// range for the baseline (rng).
	cases := []struct {
		name string
		data map[string][]sample
		rng  map[string][]sample
		fail map[string]bool
		w    want
	}{
		{"query error", nil, nil, map[string]bool{infoQ: true}, want{state: StateUnknown, contains: []string{"WAN interface query failed"}}},
		{"no wan interface", map[string][]sample{}, nil, nil, want{state: StateCrit, value: "no WAN"}},
		{"no counters", map[string][]sample{infoQ: info}, nil, nil,
			want{state: StateOK, value: "pppoe-wan, eth0", contains: []string{"no error counters"}}},
		{"physical errors", map[string][]sample{infoQ: info, errsQ: v(7), dropsQ: v(3)}, nil, nil,
			want{state: StateWarn, value: "10/hr", contains: []string{"7 link errors", "pppoe-wan, eth0"}}},
		{"usual background trickle", map[string][]sample{infoQ: info, errsQ: v(0), dropsQ: v(14)}, map[string][]sample{dropsQ: hist(12, 11, 12, 13)}, nil,
			want{state: StateOK, value: "pppoe-wan, eth0", contains: []string{"background trickle (~12/hr)"}}},
		{"drop spike vs baseline", map[string][]sample{infoQ: info, errsQ: v(0), dropsQ: v(1000)}, map[string][]sample{dropsQ: hist(10, 10, 1000, 10, 10)}, nil,
			want{state: StateWarn, value: "1000 drops/hr", contains: []string{"spiking", "usual 10/hr"}}},
		{"zero baseline is clean", map[string][]sample{infoQ: info, errsQ: v(0), dropsQ: v(0)}, map[string][]sample{dropsQ: hist(0, 0, 0)}, nil,
			want{state: StateOK, contains: []string{"counters are clean"}}},
		{"no baseline, port drops", map[string][]sample{infoQ: info, errsQ: v(0), dropsQ: v(5)}, map[string][]sample{}, nil,
			want{state: StateWarn, value: "5 drops/hr", contains: []string{"dropped at the port"}}},
		{"no baseline, clean", map[string][]sample{infoQ: info, errsQ: v(0), dropsQ: v(0)}, map[string][]sample{}, nil,
			want{state: StateOK, contains: []string{"counters are clean"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeVM{data: c.data, rng: c.rng, fail: c.fail}
			checkCommon(t, evalWANLink(context.Background(), f.client(t)), "Internet line", c.w)
		})
	}
	checkCommon(t, evalWANLink(context.Background(), nil), "Internet line", want{state: StateUnknown})
}

// withScheduleHour pins the schedule zone so that "now" reads as hour:05
// inside it, making the bufferbloat freshness logic deterministic.
func withScheduleHour(t *testing.T, hour int) time.Time {
	t.Helper()
	old := scheduleLoc.Load()
	t.Cleanup(func() { scheduleLoc.Store(old) })
	now := time.Now().UTC()
	// offset so that local time = hour:05 (±minutes of the current UTC time)
	off := (hour*60+5)*60 - (now.Hour()*60+now.Minute())*60
	for off > 14*3600 {
		off -= 24 * 3600
	}
	for off < -12*3600 {
		off += 24 * 3600
	}
	SetLocation(time.FixedZone("TEST", off))
	return time.Now().In(schedLoc())
}

func TestEvalBufferbloat(t *testing.T) {
	const (
		down   = `probe_bloat_ms{direction="down"}`
		up     = `probe_bloat_ms{direction="up"}`
		dGrade = `probe_bloat_grade{direction="down"}`
		uGrade = `probe_bloat_grade{direction="up"}`
		speed  = `probe_burst_speed_bps{direction="down"}`
	)
	now := withScheduleHour(t, 15)
	recent := now.Add(-4 * time.Minute).Unix()
	at := func(val float64) []sample { return []sample{{ts: recent, val: val}} }
	grade := func(g string) []sample {
		return []sample{{labels: map[string]string{"grade": g}, ts: recent, val: 1}}
	}
	shaper := []types.CakeStats{{Interface: "ifb4eth0", Direction: "ingress", Bandwidth: "400Mbit"}, {Interface: "eth0", Direction: "egress", Bandwidth: "40Mbit"}}

	cases := []struct {
		name string
		data map[string][]sample
		fail map[string]bool
		live []types.CakeStats
		w    want
	}{
		{"query error", nil, map[string]bool{down: true}, shaper,
			want{state: StateUnknown, contains: []string{"probe query failed"}}},
		{"no probe in lookback", map[string][]sample{}, nil, shaper,
			want{state: StateUnknown, contains: []string{"no probe result in the last 26 h"}}},
		{"stale probe", map[string][]sample{down: {{ts: now.Add(-5 * time.Hour).Unix(), val: 1}}}, nil, shaper,
			want{state: StateWarn, value: "stale", contains: []string{"check cron entry"}}},
		{"fresh A grades, line loaded", map[string][]sample{
			down: at(1.5), up: at(0.5), dGrade: grade("A"), uGrade: grade("A+"), speed: at(380e6)}, nil, shaper,
			want{state: StateOK, value: "+1.5 ms (A)",
				contains: []string{"latency rises +1.5 ms under download, +0.5 ms under upload", "probe reached 380 Mbps down", "95% of the 400 Mbit/s shaper"},
				absent:   []string{"best case", "unverified"}}},
		{"line not fully loaded hedges", map[string][]sample{
			down: at(1), up: at(1), dGrade: grade("A"), uGrade: grade("A"), speed: at(200e6)}, nil, shaper,
			want{state: StateOK, contains: []string{"50% of the 400 Mbit/s shaper", "grade is a best case"}}},
		{"no speed measurement", map[string][]sample{down: at(1), dGrade: grade("B")}, nil, shaper,
			want{state: StateOK, contains: []string{"n/a under upload", "grade unverified"}}},
		{"no ingress shaper: no speed caveat", map[string][]sample{down: at(1), dGrade: grade("B")}, nil, nil,
			want{state: StateOK, absent: []string{"unverified", "shaper"}}},
		{"bad download grade is crit", map[string][]sample{down: at(80), up: at(2), dGrade: grade("D"), uGrade: grade("A")}, nil, shaper,
			want{state: StateCrit, value: "+80.0 ms (D)"}},
		{"bad upload grade escalates", map[string][]sample{down: at(1), up: at(25), dGrade: grade("A"), uGrade: grade("C")}, nil, shaper,
			want{state: StateWarn}},
		{"upload crit beats download warn", map[string][]sample{down: at(20), up: at(90), dGrade: grade("C"), uGrade: grade("F")}, nil, shaper,
			want{state: StateCrit}},
		{"negative jitter clamped", map[string][]sample{down: at(-0.4), up: at(-1), dGrade: grade("A+"), uGrade: grade("A+")}, nil, nil,
			want{state: StateOK, value: "+0.0 ms (A+)", absent: []string{"-0."}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeVM{data: c.data, fail: c.fail}
			got := evalBufferbloat(context.Background(), f.client(t), c.live)
			checkCommon(t, got, "Latency under load", c.w)
			if again := evalBufferbloat(context.Background(), f.client(t), c.live); again.State != got.State || again.Value != got.Value {
				t.Errorf("not stable: %+v vs %+v", got, again)
			}
		})
	}
	checkCommon(t, evalBufferbloat(context.Background(), nil, shaper), "Latency under load", want{state: StateUnknown})
}

// VM-backed checks echo transport errors into Detail. Credentials in the
// VictoriaMetrics URL must never reach the dashboard.
func TestVMErrorsDoNotLeakCredentials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens: every query fails with a dial error

	const secret = "s3cr3t-vm-password"
	c := vm.New("http://monitor:" + secret + "@" + addr)
	c.HTTP.Timeout = 2 * time.Second
	ctx := context.Background()
	checks := []Check{
		evalWANLatency(ctx, c),
		evalSystem(ctx, c),
		evalWANLink(ctx, c),
		evalBufferbloat(ctx, c, nil),
		evalCPU(ctx, c, nil),
	}
	for _, ch := range checks {
		if ch.State != StateUnknown {
			t.Errorf("%s: state %q on unreachable VM, want unknown", ch.Name, ch.State)
		}
		if strings.Contains(ch.Detail, secret) || strings.Contains(ch.Value, secret) {
			t.Errorf("%s leaks the VM password: %q", ch.Name, ch.Detail)
		}
		if ch.Detail == "" {
			t.Errorf("%s: empty detail", ch.Name)
		}
	}
}
