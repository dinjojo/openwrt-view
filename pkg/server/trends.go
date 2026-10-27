package server

// Trends extend the percentiles report with range-aggregated views of the
// data VictoriaMetrics already holds: latency percentiles, shaper
// utilisation, AQM (CAKE) marks and drops, router headroom, Wi-Fi quality,
// bufferbloat grade history and the reliability ledger. Everything here is a
// read over existing series — no new collectors except wan_session_up, which
// the poller pushes once a minute.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// TrendPair is p50/p95/p99 of one measurement over the selected range.
type TrendPair struct {
	Name    string  `json:"name,omitempty"` // ping target label, when known
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Max     float64 `json:"max,omitempty"`
	Samples int     `json:"samples"`
}

// ShaperTrend is utilisation of one shaped direction over the range.
type ShaperTrend struct {
	P95Mbps     float64 `json:"p95_mbps"`     // p95 transfer rate through the shaper
	CeilingMbps float64 `json:"ceiling_mbps"` // configured CAKE rate
	PinnedPct   float64 `json:"pinned_pct"`   // % of samples above 90% of the ceiling
	Samples     int     `json:"samples"`
}

// AQMTrend is CAKE congestion-management activity for one direction.
type AQMTrend struct {
	Marks        float64 `json:"marks"`          // ECN marks over the range
	Drops        float64 `json:"drops"`          // packets dropped over the range
	PeakDelayP95 float64 `json:"peak_delay_p95"` // p95 of per-sample peak queue delay, ms
	TargetMs     float64 `json:"target_ms"`      // CAKE target, ms
}

// HeadroomTrend is router resource headroom over the range.
type HeadroomTrend struct {
	CPUP95       float64 `json:"cpu_p95"`
	TempMax      float64 `json:"temp_max"`
	ConntrackP95 float64 `json:"conntrack_p95"`
	LoadP95      float64 `json:"load_p95"`
}

// WifiDeviceTrend is one client's signal quality over the range.
type WifiDeviceTrend struct {
	Name       string  `json:"name"`
	MAC        string  `json:"mac"`
	Band       string  `json:"band"`
	SignalP50  float64 `json:"signal_p50"`
	SignalP95  float64 `json:"signal_p95"` // p95 WORST signal (5th percentile of RSSI)
	LinkP95    float64 `json:"link_p95"`   // p95 link rate, Mbit/s
	PresentPct float64 `json:"present_pct"`
}

// BloatDay is one day of bufferbloat probe results for one direction.
type BloatDay struct {
	Day    string   `json:"day"` // YYYY-MM-DD
	MaxMS  float64  `json:"max_ms"`
	AvgMS  float64  `json:"avg_ms"`
	Runs   int      `json:"runs"`
	Grades []string `json:"grades,omitempty"`
}

// TrendReport is everything /api/percentiles returns beyond the legacy fields.
type TrendReport struct {
	Range       string                 `json:"range"`
	Latency     []TrendPair            `json:"latency,omitempty"` // per ping target
	Stddev      float64                `json:"stddev_ms,omitempty"`
	Shaper      map[string]ShaperTrend `json:"shaper,omitempty"` // down | up
	AQM         map[string]AQMTrend    `json:"aqm,omitempty"`    // down | up
	Headroom    *HeadroomTrend         `json:"headroom,omitempty"`
	WifiClients *TrendPair             `json:"wifi_clients,omitempty"`
	WifiDevices []WifiDeviceTrend      `json:"wifi_devices,omitempty"`
	Bloat       map[string][]BloatDay  `json:"bloat,omitempty"` // down | up
	WanChanges  int                    `json:"wan_changes"`
	WanP99Loss  float64                `json:"wan_p99_loss"`
}

// trendWindow is the parsed query window behind a trends report: either a
// named preset (24h, 7d, 30d, …) or an explicit start/end pair from the UI's
// custom time picker.
type trendWindow struct {
	Label string // preset key or "custom", echoed back to the UI
	Start int64  // unix seconds
	End   int64  // unix seconds
}

func (w trendWindow) dur() int64 { return w.End - w.Start }

// sel is the MetricsQL bracket expression for instant queries, anchored at
// End so windows that end in the past still evaluate over the right interval.
func (w trendWindow) sel() string {
	return fmt.Sprintf("[%s] @ %d", durStr(w.dur()), w.End)
}

// step picks a range-query step coarse enough to keep long windows cheap.
func (w trendWindow) step() string {
	switch h := w.dur() / 3600; {
	case h <= 24:
		return "120s"
	case h <= 168:
		return "900s"
	default:
		return "3600s"
	}
}

// expectedSamples is how many step points a full window should hold.
func (w trendWindow) expectedSamples() float64 {
	st := map[string]float64{"120s": 120, "900s": 900, "3600s": 3600}[w.step()]
	if st == 0 {
		return 1
	}
	return float64(w.dur()) / st
}

// trendPresets are the named windows, in whole hours.
var trendPresets = map[string]int64{
	"6h": 6, "12h": 12, "24h": 24, "3d": 72, "7d": 168, "14d": 336, "30d": 720, "90d": 2160,
}

// parseTrendWindow resolves the percentiles request's window from either
// range=<preset> or start=<unix>&end=<unix>. Custom windows are clamped to
// [1h, 90d] and to the recent past.
func parseTrendWindow(rng, startQ, endQ string, now int64) (trendWindow, error) {
	if startQ == "" {
		h, ok := trendPresets[rng]
		if !ok {
			return trendWindow{}, fmt.Errorf("range must be one of 6h,12h,24h,3d,7d,14d,30d,90d — or pass start/end")
		}
		return trendWindow{Label: rng, End: now, Start: now - h*3600}, nil
	}
	start, err := strconv.ParseInt(startQ, 10, 64)
	if err != nil || start <= 0 {
		return trendWindow{}, fmt.Errorf("start must be a unix timestamp")
	}
	end := now
	if endQ != "" {
		if e, perr := strconv.ParseInt(endQ, 10, 64); perr == nil && e > 0 {
			end = e
		}
	}
	if end > now {
		end = now
	}
	if end-start < 3600 {
		return trendWindow{}, fmt.Errorf("window must be at least 1 hour")
	}
	if end-start > 90*24*3600 {
		return trendWindow{}, fmt.Errorf("window must be at most 90 days")
	}
	return trendWindow{Label: "custom", Start: start, End: end}, nil
}

// durStr renders a duration the way MetricsQL selectors want it: whole days
// as "Nd", whole hours as "Nh", otherwise a compound "NhMmSs".
func durStr(sec int64) string {
	if sec%3600 == 0 {
		if d := sec / 86400; d != 0 && sec%86400 == 0 {
			return fmt.Sprintf("%dd", d)
		}
		return fmt.Sprintf("%dh", sec/3600)
	}
	s := ""
	if r := sec % 60; r != 0 {
		s = fmt.Sprintf("%ds", r)
		sec -= r
	}
	if r := (sec % 3600) / 60; r != 0 {
		s = fmt.Sprintf("%dm%s", r, s)
		sec -= sec % 3600
	}
	if h := sec / 3600; h != 0 {
		s = fmt.Sprintf("%dh%s", h, s)
	}
	return s
}

// addTrends fills the trend fields of the percentiles response. Every query
// is best-effort: a failed or empty series leaves the field absent and the
// UI renders an honest "no data" note instead of zeros.
func (s *Server) addTrends(ctx context.Context, out *PercentileReport, w trendWindow) {
	tr := TrendReport{Range: w.Label, Shaper: map[string]ShaperTrend{}, AQM: map[string]AQMTrend{}, Bloat: map[string][]BloatDay{}}

	// ── Latency percentiles per target ────────────────────────────────
	// TCP-connect RTT first (honest under load on this ISP — the
	// interceptor answers raw pings); fall back to ICMP for windows that
	// predate the connect monitor.
	rttMetric := `wan_connect_rtt_ms`
	rttLabel := "target"
	{
		probe, _ := s.vmc.Query(ctx, fmt.Sprintf(`count_over_time(%s%s)`, rttMetric, w.sel()))
		if len(probe) == 0 {
			rttMetric, rttLabel = `collectd_ping`, "ping"
		}
	}
	p99s, _ := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.99, %s%s)`, rttMetric, w.sel()))
	p95s, _ := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.95, %s%s)`, rttMetric, w.sel()))
	p50s, _ := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.50, %s%s)`, rttMetric, w.sel()))
	counts, _ := s.vmc.Query(ctx,
		fmt.Sprintf(`count_over_time(%s%s)`, rttMetric, w.sel()))
	// Normalise the label once: collectd leaves it empty for the default
	// target, and every lookup must use the same key.
	norm := func(pts []vm.Point) map[string]vm.Point {
		m := make(map[string]vm.Point, len(pts))
		for _, pt := range pts {
			name := pt.Labels[rttLabel]
			if name == "" {
				name = "wan"
			}
			m[name] = pt
		}
		return m
	}
	p99By, p50By, p95By, cntBy := norm(p99s), norm(p50s), norm(p95s), norm(counts)
	// A target present in any of the four answers gets a row; missing
	// quantiles stay zero rather than dropping the target entirely.
	names := map[string]struct{}{}
	for _, m := range []map[string]vm.Point{p99By, p95By, p50By, cntBy} {
		for name := range m {
			names[name] = struct{}{}
		}
	}
	for name := range names {
		tp := TrendPair{Name: name}
		if v, ok := p95By[name]; ok {
			tp.P95 = v.Val
		}
		if v, ok := p50By[name]; ok {
			tp.P50 = v.Val
		}
		if v, ok := p99By[name]; ok {
			tp.P99 = v.Val
		}
		if v, ok := cntBy[name]; ok {
			tp.Samples = int(v.Val)
		}
		tr.Latency = append(tr.Latency, tp)
	}
	sort.Slice(tr.Latency, func(i, j int) bool {
		if tr.Latency[i].Samples != tr.Latency[j].Samples {
			return tr.Latency[i].Samples > tr.Latency[j].Samples
		}
		return tr.Latency[i].Name < tr.Latency[j].Name
	})
	// Stddev of the ping probe across all targets, not just whichever
	// target's series happens to sort last.
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`avg(avg_over_time(collectd_ping_ping_stddev%s))`, w.sel())); err == nil && len(se) > 0 {
		tr.Stddev = se[0].Val
	}

	// ── Shaper utilisation per direction ─────────────────────────────
	// Throughput: the "tx" byte counter on the whole-interface series.
	for _, dir := range []struct{ key, iface string }{{"down", "ifb4eth0"}, {"up", "eth0"}} {
		st := ShaperTrend{}
		if se, err := s.vmc.Query(ctx,
			fmt.Sprintf(`max(collectd_sqm_gauge{type="configured_bw_bps",sqm="%s"})`, dir.iface)); err == nil && len(se) > 0 {
			// tc reports cake's bandwidth option in bytes/s — convert to Mbit/s.
			st.CeilingMbps = se[0].Val * 8 / 1e6
		}
		if se, err := s.vmc.QueryRange(ctx,
			fmt.Sprintf(`sum(rate(collectd_sqm_bytes{type="tx",sqm="%s"}[5m]))*8`, dir.iface),
			w.Start, w.End, w.step()); err == nil && len(se) > 0 {
			st.P95Mbps = percentile(se[0].Val, 95) / 1e6
			st.Samples = len(se[0].Val)
			if st.CeilingMbps > 0 {
				// % of samples pinned above 90% of the ceiling.
				pinned := 0
				for _, v := range se[0].Val {
					if v/1e6 >= 0.9*st.CeilingMbps {
						pinned++
					}
				}
				st.PinnedPct = 100 * float64(pinned) / float64(len(se[0].Val))
			}
		}
		if st.P95Mbps > 0 && st.CeilingMbps > 0 && st.Samples > 0 {
			tr.Shaper[dir.key] = st
		}
	}

	// ── AQM marks / drops per direction ──────────────────────────────
	// CAKE gauges live on the per-tin series: eth0-tin-t0 (upload),
	// ifb4eth0-tin-t0 (download).
	aqm, _ := s.vmc.Query(ctx,
		fmt.Sprintf(`sum by (type, sqm) (increase(collectd_sqm_gauge{type=~"ecn_marks|drops",sqm=~"(eth0|ifb4eth0)-tin.*"}%s))`,
			w.sel()))
	aqmBy := func(typ, iface string) float64 {
		for _, pt := range aqm {
			if pt.Labels["type"] == typ && pt.Labels["sqm"] == iface+"-tin-t0" {
				return pt.Val
			}
		}
		return 0
	}
	peakP95, _ := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.95, collectd_sqm_gauge{type="peak_delay_us",sqm=~"(eth0|ifb4eth0)-tin.*"}%s)/1000`,
			w.sel()))
	targetMs, _ := s.vmc.Query(ctx, `max(collectd_sqm_gauge{type="target_us"})/1000`)
	target := 5.0
	if len(targetMs) > 0 {
		target = targetMs[0].Val
	}
	peakBy := func(iface string) float64 {
		for _, pt := range peakP95 {
			if pt.Labels["sqm"] == iface+"-tin-t0" {
				return pt.Val
			}
		}
		return 0
	}
	for _, dir := range []struct{ key, iface string }{{"down", "ifb4eth0"}, {"up", "eth0"}} {
		a := AQMTrend{
			Marks:        aqmBy("ecn_marks", dir.iface),
			Drops:        aqmBy("drops", dir.iface),
			PeakDelayP95: peakBy(dir.iface),
			TargetMs:     target,
		}
		if a.Marks > 0 || a.Drops > 0 || a.PeakDelayP95 > 0 {
			tr.AQM[dir.key] = a
		}
	}

	// ── Router headroom ──────────────────────────────────────────────
	h := HeadroomTrend{}
	// CPU busy %: collectd reports per-core, per-type percentages, so busy
	// is 100 minus the per-core idle average across the range.
	if se, err := s.vmc.QueryRange(ctx, `100 - avg(collectd_cpu_percent{type="idle"})`, w.Start, w.End, w.step()); err == nil && len(se) > 0 {
		h.CPUP95 = percentile(se[0].Val, 95)
	}
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`max_over_time(collectd_thermal_temperature%s)`, w.sel())); err == nil && len(se) > 0 {
		for _, pt := range se {
			if pt.Val > h.TempMax {
				h.TempMax = pt.Val
			}
		}
	}
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.95, collectd_conntrack{conntrack=""}%s)`, w.sel())); err == nil && len(se) > 0 {
		h.ConntrackP95 = se[0].Val
	}
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.95, collectd_load_0%s)`, w.sel())); err == nil && len(se) > 0 {
		h.LoadP95 = se[0].Val
	}
	if h.CPUP95 > 0 || h.TempMax > 0 || h.ConntrackP95 > 0 {
		tr.Headroom = &h
	}

	// ── Wi-Fi quality ────────────────────────────────────────────────
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.95, orbi_wifi_clients%s)`, w.sel())); err == nil && len(se) > 0 {
		tr.WifiClients = &TrendPair{P95: se[0].Val}
	}
	if se, err := s.vmc.QueryRange(ctx, `orbi_client_signal`, w.Start, w.End, w.step()); err == nil {
		type dev struct {
			name, band, mac string
			vals            []float64
			link            []float64
			series          int // signal series seen for this MAC (can span bands)
		}
		byMac := map[string]*dev{}
		for _, series := range se {
			mac := series.Labels["mac"]
			if mac == "" {
				continue
			}
			d := byMac[mac]
			if d == nil {
				d = &dev{name: series.Labels["name"], band: series.Labels["band"], mac: mac}
				byMac[mac] = d
			}
			for _, v := range series.Val {
				if v != 0 {
					d.vals = append(d.vals, v)
				}
			}
			d.series++
		}
		if ls, err := s.vmc.QueryRange(ctx, `orbi_client_linkspeed`, w.Start, w.End, w.step()); err == nil {
			for _, series := range ls {
				if d := byMac[series.Labels["mac"]]; d != nil {
					d.link = append(d.link, series.Val...)
				}
			}
		}
		devices := make([]WifiDeviceTrend, 0, len(byMac))
		for _, d := range byMac {
			if len(d.vals) < 3 {
				continue
			}
			sorted := append([]float64(nil), d.vals...)
			sort.Float64s(sorted)
			wt := TrendPair{P50: percentile(sorted, 50)}
			// Signal is negative dBm: the p95 WORST signal is the 5th
			// percentile of the sorted values.
			wt.P95 = percentile(sorted, 5)
			wt.Samples = len(sorted)
			// A MAC seen on several bands contributes several series, so
			// the denominator scales with the series count; clamp anyway
			// because VM can return a point or two more than the nominal
			// window holds.
			present := 100 * float64(len(d.vals)) / (float64(d.series) * w.expectedSamples())
			if present > 100 {
				present = 100
			}
			wd := WifiDeviceTrend{
				Name: d.name, MAC: d.mac, Band: d.band,
				SignalP50: wt.P50, SignalP95: wt.P95,
				PresentPct: present,
			}
			if len(d.link) > 0 {
				wd.LinkP95 = percentile(d.link, 95)
			}
			devices = append(devices, wd)
		}
		sort.Slice(devices, func(i, j int) bool { return devices[i].PresentPct > devices[j].PresentPct })
		if len(devices) > 6 {
			devices = devices[:6]
		}
		tr.WifiDevices = devices
	}

	// ── Bufferbloat grade history (daily buckets over the window) ─────
	hStart := w.Start
	for _, dir := range []struct{ key, label string }{{"down", "down"}, {"up", "up"}} {
		raw, err := s.vmc.QueryRaw(ctx,
			fmt.Sprintf(`probe_bloat_ms{direction="%s"}`, dir.label), hStart, w.End)
		if err != nil {
			continue
		}
		grades, _ := s.vmc.QueryRaw(ctx,
			fmt.Sprintf(`probe_bloat_grade{direction="%s"}`, dir.label), hStart, w.End)
		gradeByDay := map[string][]string{}
		for _, se := range grades {
			for _, ts := range se.TS {
				day := time.Unix(ts, 0).In(s.loc).Format("2006-01-02")
				if g := se.Labels["grade"]; g != "" {
					gradeByDay[day] = append(gradeByDay[day], g)
				}
			}
		}
		days := map[string]*BloatDay{}
		var order []string
		for _, se := range raw {
			for i, v := range se.Val {
				day := time.Unix(se.TS[i], 0).In(s.loc).Format("2006-01-02")
				// loaded RTT can sit a hair below idle from jitter; that is
				// noise, not negative bloat.
				if v < 0 {
					v = 0
				}
				d := days[day]
				if d == nil {
					d = &BloatDay{Day: day}
					days[day] = d
					order = append(order, day)
				}
				if v > d.MaxMS {
					d.MaxMS = v
				}
				d.AvgMS += v
				d.Runs++
			}
		}
		out := make([]BloatDay, 0, len(order))
		sort.Strings(order)
		for _, day := range order {
			d := days[day]
			d.AvgMS /= float64(d.Runs)
			d.Grades = gradeByDay[day]
			out = append(out, *d)
		}
		if len(out) > 0 {
			tr.Bloat[dir.key] = out
		}
	}

	// ── Reliability ledger ───────────────────────────────────────────
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`quantile_over_time(0.99, collectd_ping_ping_droprate%s)`, w.sel())); err == nil && len(se) > 0 {
		tr.WanP99Loss = se[0].Val
	}
	if se, err := s.vmc.Query(ctx,
		fmt.Sprintf(`changes(wan_session_up%s)`, w.sel())); err == nil && len(se) > 0 {
		tr.WanChanges = int(se[0].Val)
	}

	out.Trends = &tr
}
