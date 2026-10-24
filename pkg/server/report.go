package server

// /api/report — per-calendar-day availability report (today is partial).
//
// Day boundaries are calendar days in the server's zone (Server.loc, the
// -tz flag / OPENWRT_VIEW_TZ, default the process local zone). On the router the
// process otherwise runs on UTC, which made "days" run 05:30→05:30 IST.
// /api/usage uses the same zone for its days.
//
// Metric definitions (all per calendar day, rounded to 0.1):
//
//   wan_up_pct      WAN (PPPoE session) availability. The monitor polls
//                   `ubus call network.interface.wan status` every 15 s and
//                   persists the up/down edges as "wan" events (crit
//                   "dropped" / ok "re-established"). An outage runs from a
//                   crit "wan" event to the next ok "wan" event, or to the
//                   next "monitor" restart event (state across a monitor
//                   restart is unknown and the poller does not re-emit
//                   edges after a restart), or to now if still open.
//                   wan_up_pct = 100 × (1 − outage time / observed time),
//                   where observed time is the part of the day after the
//                   oldest event still held in the persistent ring (and
//                   before now). null when the day is not covered at all.
//   latency_avg_ms  Mean and 95th percentile of the internet-probe RTT
//   latency_p95_ms  (collectd ping to 1.1.1.1 / 8.8.8.8, averaged across
//                   targets) sampled every 60 s from VictoriaMetrics.
//                   null when VM is not configured or has no samples.
//   buffering_events Number of bufferbloat episodes that START in the day,
//                   from bufferingEpisodes (analytics.go) — the SAME
//                   aggregation the episodes panel (/api/incidents) counts:
//                   active-probe episodes in both directions plus passive
//                   RTT-under-load episodes. Keep the two in sync: change
//                   the episode rules in bufferingEpisodes only.
//                   When VictoriaMetrics is unavailable it falls back to
//                   the count of "probe" (and the reserved "bloat") events
//                   with sev warn or crit, collapsed repeats included (one
//                   event per probe run and direction).
//                   null when nothing covers the day: no probe samples,
//                   no episode and no event-store history (e.g. days
//                   before the event store began).
//   satellite_offline_min Minutes any mesh satellite was offline, from
//                   "satellite" events ("<name> went offline" → "<name> is
//                   back online"; legacy "wifi" events with the same
//                   messages from before v2.7 are included). Same
//                   monitor-restart / still-open rules as WAN outages.
//                   Summed across satellites. null when the event store
//                   does not cover the day.
//   wan_rx_gb       increase(node_network_receive/transmit_bytes_total
//   wan_tx_gb       {device="pppoe-wan"}) over the day, decimal GB, from
//                   VictoriaMetrics; null when unavailable.

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	fiber "github.com/gofiber/fiber/v3"

	"github.com/dinjojo/openwrt-view/pkg/alerts"
	"github.com/dinjojo/openwrt-view/pkg/events"
)

// ReportDay is one row of /api/report. Pointer fields are null when no
// source data covers the day.
type ReportDay struct {
	Date                string   `json:"date"`
	WANUpPct            *float64 `json:"wan_up_pct"`
	LatencyAvgMS        *float64 `json:"latency_avg_ms"`
	LatencyP95MS        *float64 `json:"latency_p95_ms"`
	BufferingEvents     *int     `json:"buffering_events"`      // null = no coverage (never omitted)
	SatelliteOfflineMin *float64 `json:"satellite_offline_min"` // null = no coverage (never omitted)
	WANRxGB             *float64 `json:"wan_rx_gb"`
	WANTxGB             *float64 `json:"wan_tx_gb"`
}

// Report is the /api/report body. Days are oldest first, ending today.
type Report struct {
	Days   []ReportDay   `json:"days"`
	Alerts alerts.Config `json:"alerts"`
}

type dayWindow struct {
	date       string
	start, end int64 // [start, end) unix seconds; end = now for today
}

// dayWindows returns the last n calendar days in now's zone, oldest first.
// Callers pass now already converted to the report zone (Server.loc).
func dayWindows(n int, now time.Time) []dayWindow {
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	out := make([]dayWindow, 0, n)
	for i := n - 1; i >= 0; i-- {
		s := today.AddDate(0, 0, -i)
		e := s.AddDate(0, 0, 1)
		if e.After(now) {
			e = now
		}
		out = append(out, dayWindow{date: s.Format("2006-01-02"), start: s.Unix(), end: e.Unix()})
	}
	return out
}

type interval struct{ start, end int64 }

// overlap returns the seconds of iv inside [start, end).
func overlap(ivs []interval, start, end int64) int64 {
	var sum int64
	for _, iv := range ivs {
		s, e := max(iv.start, start), min(iv.end, end)
		if e > s {
			sum += e - s
		}
	}
	return sum
}

// chronological returns events oldest first (the store is newest first).
func chronological(evs []events.Event) []events.Event {
	out := make([]events.Event, len(evs))
	for i, e := range evs {
		out[len(evs)-1-i] = e
	}
	return out
}

// wanOutages derives WAN outage intervals from oldest-first events.
func wanOutages(evs []events.Event, now int64) []interval {
	var out []interval
	open := int64(-1)
	for _, e := range evs {
		switch {
		case e.Kind == "wan" && e.Sev == "crit":
			if open < 0 {
				open = e.At
			}
		case open >= 0 && ((e.Kind == "wan" && e.Sev == "ok") || e.Kind == "monitor"):
			out = append(out, interval{open, e.At})
			open = -1
		}
	}
	if open >= 0 {
		out = append(out, interval{open, now})
	}
	return out
}

const (
	satOfflineSuffix = " went offline"
	satOnlineSuffix  = " is back online"
)

// satelliteOutages derives per-satellite offline intervals (flattened)
// from oldest-first events.
func satelliteOutages(evs []events.Event, now int64) []interval {
	var out []interval
	open := map[string]int64{}
	closeAll := func(at int64) {
		for name, t := range open {
			out = append(out, interval{t, at})
			delete(open, name)
		}
	}
	for _, e := range evs {
		if e.Kind == "monitor" {
			closeAll(e.At)
			continue
		}
		if e.Kind != alerts.ExcludedKind && e.Kind != "wifi" {
			continue
		}
		switch {
		case strings.HasSuffix(e.Msg, satOfflineSuffix):
			name := strings.TrimSuffix(e.Msg, satOfflineSuffix)
			if _, ok := open[name]; !ok {
				open[name] = e.At
			}
		case strings.HasSuffix(e.Msg, satOnlineSuffix):
			name := strings.TrimSuffix(e.Msg, satOnlineSuffix)
			if t, ok := open[name]; ok {
				out = append(out, interval{t, e.At})
				delete(open, name)
			}
		}
	}
	closeAll(now)
	return out
}

// bufferingCount counts bufferbloat warnings (with collapsed repeats).
func bufferingCount(evs []events.Event, start, end int64) int {
	n := 0
	for _, e := range evs {
		if (e.Kind == "probe" || e.Kind == "bloat") && (e.Sev == "warn" || e.Sev == "crit") && e.At >= start && e.At < end {
			c := e.Count
			if c < 1 {
				c = 1
			}
			n += c
		}
	}
	return n
}

// buildEventMetrics fills the event-derived fields of each day. Days the
// event store does not reach (before its oldest event) keep null fields.
// BufferingEvents set here is the no-VM fallback; vmDayMetrics replaces
// it with the episode count when VictoriaMetrics answers.
func buildEventMetrics(days []ReportDay, wins []dayWindow, evs []events.Event, now int64) {
	chron := chronological(evs)
	wan := wanOutages(chron, now)
	sat := satelliteOutages(chron, now)
	covered := int64(math.MaxInt64)
	if len(chron) > 0 {
		covered = chron[0].At
	}
	for i, w := range wins {
		obsStart := max(w.start, covered)
		if w.end > obsStart {
			n := bufferingCount(chron, w.start, w.end)
			days[i].BufferingEvents = &n
			days[i].SatelliteOfflineMin = f64p(round1(float64(overlap(sat, w.start, w.end)) / 60))
			down := overlap(wan, obsStart, w.end)
			v := round1(100 * (1 - float64(down)/float64(w.end-obsStart)))
			days[i].WANUpPct = &v
		}
	}
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func f64p(v float64) *float64 { return &v }

// vmDayMetrics fills latency and WAN volume for one day from VM.
func (s *Server) vmDayMetrics(ctx context.Context, d *ReportDay, w dayWindow) {
	if s.vmc == nil || w.end <= w.start {
		return
	}
	if series, err := s.vmc.QueryRange(ctx, `avg(collectd_ping)`, w.start, w.end-1, "60s"); err == nil {
		var vals []float64
		for _, se := range series {
			for _, v := range se.Val {
				if v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) {
					vals = append(vals, v)
				}
			}
		}
		if len(vals) > 0 {
			sum := 0.0
			for _, v := range vals {
				sum += v
			}
			d.LatencyAvgMS = f64p(round1(sum / float64(len(vals))))
			d.LatencyP95MS = f64p(round1(percentile(vals, 95)))
		}
	}
	win := strconv.FormatInt(w.end-w.start, 10) + "s"
	vol := func(metric string) *float64 {
		pts, err := s.vmc.QueryAt(ctx, `sum(increase(`+metric+`{device="pppoe-wan"}[`+win+`]))`, w.end)
		if err != nil || len(pts) == 0 || math.IsNaN(pts[0].Val) {
			return nil
		}
		return f64p(round1(pts[0].Val / 1e9))
	}
	d.WANRxGB = vol("node_network_receive_bytes_total")
	d.WANTxGB = vol("node_network_transmit_bytes_total")

	// Buffering episodes: the same aggregation as /api/incidents.
	if eps, probeN, err := s.bufferingEpisodes(ctx, w.start, w.end-1, true); err == nil {
		d.BufferingEvents = episodeCount(eps, w, probeN, d.BufferingEvents != nil)
	}
}

// episodeCount is the buffering_events value for one day from the shared
// episode aggregation: episodes starting inside the window. It is null
// when nothing covers the day — no probe samples, no episode found and no
// event-store history (eventCovered).
func episodeCount(eps []Incident, w dayWindow, probeSamples int, eventCovered bool) *int {
	n := 0
	for _, ep := range eps {
		if ep.Start >= w.start && ep.Start < w.end {
			n++
		}
	}
	if n == 0 && probeSamples == 0 && !eventCovered {
		return nil
	}
	return &n
}

// handleAPIReport serves the availability report.
func (s *Server) handleAPIReport(c fiber.Ctx) error {
	n := 7
	if v := c.Query("days"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 {
			return c.Status(400).SendString(`{"error":"days must be a positive integer"}`)
		}
		n = min(p, 30)
	}
	now := time.Now().In(s.loc)
	wins := dayWindows(n, now)
	days := make([]ReportDay, len(wins))
	for i, w := range wins {
		days[i].Date = w.date
	}
	if s.events != nil {
		buildEventMetrics(days, wins, s.events.List(1<<30), now.Unix())
	}
	ctx, cancel := context.WithTimeout(c.Context(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i := range wins {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.vmDayMetrics(ctx, &days[i], wins[i])
		}(i)
	}
	wg.Wait()
	return c.JSON(Report{Days: days, Alerts: s.alerts.Config()})
}
