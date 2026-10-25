package server

// Analytics endpoints computed from VictoriaMetrics history:
//
//   /api/percentiles — honest latency-quality numbers (p50/p95) for WAN RTT,
//                      loaded latency and packet loss.
//   /api/incidents   — bufferbloat episodes ("how many times and when"),
//                      from the active probe and a passive RTT-under-load
//                      detector between probe runs.
//   /api/tunnel      — WARP exit-tunnel snapshot: state, handshake age,
//                      transfer counters/rates and recent reconnect counts.

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/health"
	"github.com/dinjojo/openwrt-view/pkg/vm"
	fiber "github.com/gofiber/fiber/v3"
)

const (
	// bloatThresholdMS is how much added latency under load we call
	// bufferbloat before flagging an incident.
	bloatThresholdMS = 30.0
	// utilThresholdPct is the WAN utilization above which a passive RTT
	// sample counts as "under load".
	utilThresholdPct = 70.0
	// passiveMinSamples: at least 2 consecutive 60 s samples must show
	// inflated RTT under load before it is an episode (filters blips).
	passiveMinSamples = 2
)

// PercentileReport is the response of /api/percentiles.
type PercentileReport struct {
	Range   string             `json:"range"`
	Targets []PercentileTarget `json:"targets"`
	Loaded  *PercentilePair    `json:"loaded,omitempty"` // probe RTT under load
	Idle    *PercentilePair    `json:"idle,omitempty"`   // probe idle RTT
	Loss    *PercentilePair    `json:"loss,omitempty"`   // ping droprate
	Trends  *TrendReport       `json:"trends,omitempty"` // cross-panel trend aggregates
}

type PercentileTarget struct {
	Name    string  `json:"name"`
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99,omitempty"`
	Samples int     `json:"samples"`
}

type PercentilePair struct {
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99,omitempty"`
	Max     float64 `json:"max,omitempty"`
	Samples int     `json:"samples"`
}

func (s *Server) handleAPIPercentiles(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).JSON(fiber.Map{"error": "victoriametrics not configured"})
	}
	rng := c.Query("range", "24h")
	w, werr := parseTrendWindow(rng, c.Query("start"), c.Query("end"), time.Now().Unix())
	if werr != nil {
		return c.Status(400).JSON(fiber.Map{"error": werr.Error()})
	}
	end := w.End
	start := w.Start
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	step := w.step()

	out := PercentileReport{Range: w.Label}

	// WAN RTT per probe target (1.1.1.1, 8.8.8.8 — whatever collectd pings).
	if series, err := s.vmc.QueryRange(ctx, `collectd_ping`, start, end, step); err == nil {
		for _, se := range series {
			name := se.Labels["ping"]
			if name == "" {
				name = "wan"
			}
			out.Targets = append(out.Targets, PercentileTarget{
				Name: name, P50: percentile(se.Val, 50), P95: percentile(se.Val, 95), P99: percentile(se.Val, 99), Samples: len(se.Val),
			})
		}
		sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].Name < out.Targets[j].Name })
	}

	// Probe loaded vs idle RTT.
	if se, err := s.vmc.QueryRange(ctx, `avg(probe_loaded_rtt_ms)`, start, end, step); err == nil && len(se) > 0 {
		out.Loaded = &PercentilePair{P50: percentile(se[0].Val, 50), P95: percentile(se[0].Val, 95), Samples: len(se[0].Val)}
	}
	if se, err := s.vmc.QueryRange(ctx, `avg(probe_idle_rtt_ms)`, start, end, step); err == nil && len(se) > 0 {
		out.Idle = &PercentilePair{P50: percentile(se[0].Val, 50), P95: percentile(se[0].Val, 95), Samples: len(se[0].Val)}
	}

	// Packet loss (ping droprate, 0..1).
	if se, err := s.vmc.QueryRange(ctx, `avg(collectd_ping_ping_droprate)`, start, end, step); err == nil && len(se) > 0 {
		loss := &PercentilePair{P50: percentile(se[0].Val, 50), P95: percentile(se[0].Val, 95), Samples: len(se[0].Val)}
		loss.P99 = percentile(se[0].Val, 99)
		out.Loss = loss
	}

	// Cross-panel trend aggregates (shaper, AQM, headroom, Wi-Fi, grades,
	// reliability) — all reads over series that already exist in VM.
	s.addTrends(ctx, &out, w)

	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

// Incident is one bufferbloat episode.
type Incident struct {
	Start     int64   `json:"start"`
	End       int64   `json:"end"`
	PeakMS    float64 `json:"peak_ms"`
	Direction string  `json:"direction"`          // download | upload | both
	Source    string  `json:"source"`             // probe | passive
	Readings  int     `json:"readings,omitempty"` // probe episodes: number of probe runs over the threshold
	Hint      string  `json:"hint"`
}

type IncidentReport struct {
	Range    string     `json:"range"`
	Count    int        `json:"count"`
	WorstMS  float64    `json:"worst_ms"`
	Episodes []Incident `json:"episodes"`
}

func (s *Server) handleAPIIncidents(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	rng := c.Query("range", "24h")
	if rng != "24h" && rng != "7d" && rng != "30d" {
		return c.Status(400).SendString(`{"error":"range must be one of 24h,7d,30d"}`)
	}
	end := time.Now().Unix()
	start := rangeStart(rng, end)
	ctx, cancel := context.WithTimeout(c.Context(), 15*time.Second)
	defer cancel()

	rep := IncidentReport{Range: rng, Episodes: []Incident{}}
	// Passive detector at 24h/7d only: at 30 d the range step would
	// average the 60 s samples together and the consecutive-sample rule
	// would silently stop working.
	eps, _, _ := s.bufferingEpisodes(ctx, start, end, rng != "30d")
	rep.addEpisodes(eps)

	sort.Slice(rep.Episodes, func(i, j int) bool { return rep.Episodes[i].Start > rep.Episodes[j].Start })
	rep.Count = len(rep.Episodes)
	for _, ep := range rep.Episodes {
		if ep.PeakMS > rep.WorstMS {
			rep.WorstMS = ep.PeakMS
		}
	}

	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(rep)
	return c.Send(b)
}

func (r *IncidentReport) addEpisodes(eps []Incident) {
	r.Episodes = append(r.Episodes, eps...)
}

// bufferingEpisodes is THE bufferbloat-episode aggregation. Both the
// episodes panel (/api/incidents) and the report's buffering_events
// (/api/report) count its output, so the two numbers agree for the same
// window — keep it that way: change episode rules here, never in one
// caller only.
//
// It returns the episodes found in [start, end]: active-probe episodes in
// both directions (from raw probe samples, see probeEpisodes) plus, when
// passive is set, passive RTT-under-load episodes. probeSamples is the
// number of raw probe samples seen (0 = no probe coverage); err is set
// only when the probe data could not be read at all.
func (s *Server) bufferingEpisodes(ctx context.Context, start, end int64, passive bool) (eps []Incident, probeSamples int, err error) {
	failed := 0
	for _, d := range []struct{ label, name string }{{"down", "download"}, {"up", "upload"}} {
		series, qerr := s.vmc.QueryRaw(ctx, `probe_bloat_ms{direction="`+d.label+`"}`, start, end)
		if qerr != nil {
			failed++
			err = qerr
			continue
		}
		for _, se := range series {
			probeSamples += len(se.TS)
			eps = append(eps, probeEpisodes(se, d.name, s.loc)...)
		}
	}
	if failed < 2 {
		err = nil
	}
	if passive {
		eps = append(eps, s.passiveEpisodes(ctx, start, end)...)
	}
	return eps, probeSamples, err
}

const (
	// probeStep is the nominal width given to one probe reading. A probe
	// run takes well under a minute, but it stands for the line's state
	// around that time, so an episode ends one step after its last bad
	// reading.
	probeStep = 900 // seconds
	// probeMaxGap: bad readings further apart than this are separate
	// episodes even with no good reading between them (e.g. the 20:00
	// run and the next day's 11:00 run). Covers the hourly cadence (and
	// the older 15-minute one) with slack.
	probeMaxGap = 75 * 60 // seconds
)

// probeEpisodes groups consecutive above-threshold probe readings into
// episodes. se must hold RAW samples (vm.QueryRaw): each timestamp is a
// real probe run. (Step-aligned range points carried one hourly probe
// forward across several 15-minute steps, turning a 28-second probe into a
// "~45 min stretch" that started up to 15 minutes late.)
//
// An episode starts at its first bad reading's own timestamp and ends at
// its last bad reading + probeStep. A one-reading episode is described as
// a single probe reading at that time, not as a stretch.
func probeEpisodes(se vm.Series, direction string, loc *time.Location) []Incident {
	if loc == nil {
		loc = time.Local
	}
	var eps []Incident
	var cur *Incident
	readings := 0
	lastBad := int64(0)
	flush := func() {
		if cur == nil {
			return
		}
		cur.End = lastBad + probeStep
		cur.Readings = readings
		at := time.Unix(cur.Start, 0).In(loc).Format("15:04")
		if readings == 1 {
			cur.Hint = "single probe reading at " + at + ": the speed check added " + strconv.FormatFloat(cur.PeakMS, 'f', 0, 64) +
				" ms of latency under load — the shaper held the ceiling but the line ran over its ideal during that test"
		} else {
			cur.Hint = strconv.Itoa(readings) + " probe readings in a row from " + at + " to " + time.Unix(lastBad, 0).In(loc).Format("15:04") +
				" added up to " + strconv.FormatFloat(cur.PeakMS, 'f', 0, 64) + " ms of latency under load — the shaper held the ceiling but the line ran over its ideal for that stretch"
		}
		eps = append(eps, *cur)
		cur = nil
		readings = 0
	}
	for i, ts := range se.TS {
		v := se.Val[i]
		if v <= bloatThresholdMS {
			flush()
			continue
		}
		if cur != nil && ts-lastBad > probeMaxGap {
			flush()
		}
		if cur == nil {
			cur = &Incident{Start: ts, PeakMS: v, Direction: direction, Source: "probe"}
		} else if v > cur.PeakMS {
			cur.PeakMS = v
		}
		readings++
		lastBad = ts
	}
	flush()
	return eps
}

// passiveEpisodes detects RTT inflation while the WAN is heavily used,
// from continuously collected data (works between probe runs, including
// at night when the probe sleeps).
func (s *Server) passiveEpisodes(ctx context.Context, start, end int64) []Incident {
	// TCP-connect RTT first: ICMP can read falsely fast under load on this
	// ISP (interceptor answers echoes before the shaper), which would hide
	// exactly the episodes this looks for.
	ping, err := s.vmc.QueryRange(ctx, `avg(wan_connect_rtt_ms)`, start, end, "60s")
	if err != nil || len(ping) == 0 {
		ping, err = s.vmc.QueryRange(ctx, `avg(collectd_ping)`, start, end, "60s")
	}
	if err != nil || len(ping) == 0 {
		return nil
	}
	rx, errRx := s.vmc.QueryRange(ctx, `rate(collectd_interface_if_octets_0_total{interface="eth0"}[120s])`, start, end, "60s")
	tx, errTx := s.vmc.QueryRange(ctx, `rate(collectd_interface_if_octets_1_total{interface="eth0"}[120s])`, start, end, "60s")
	if errRx != nil || errTx != nil || len(rx) == 0 || len(tx) == 0 {
		return nil
	}
	shaped := s.shapedBitsPerS()
	if shaped <= 0 {
		return nil
	}

	rtt := ping[0]
	rxs, txs := rx[0], tx[0]
	utilAt := map[int64]float64{}
	for i, ts := range rxs.TS {
		utilAt[ts] = rxs.Val[i] * 8 / shaped * 100
	}
	for i, ts := range txs.TS {
		if u := txs.Val[i] * 8 / shaped * 100; u > utilAt[ts] {
			utilAt[ts] = u
		}
	}
	txAt := map[int64]float64{}
	for i, ts := range txs.TS {
		txAt[ts] = txs.Val[i]
	}

	// Baseline: median RTT when the line is quiet (<20% used); fall back to
	// the 20th percentile of all samples if there were few quiet moments.
	var quiet []float64
	var all []float64
	for i, ts := range rtt.TS {
		all = append(all, rtt.Val[i])
		if u := utilAt[ts]; u > 0 && u < 20 {
			quiet = append(quiet, rtt.Val[i])
		}
	}
	baseline := percentile(all, 20)
	if len(quiet) >= 10 {
		baseline = median(quiet)
	}

	// Walk the timeline; an episode needs utilThresholdPct+ utilization AND
	// RTT at least bloatThresholdMS over baseline for passiveMinSamples in
	// a row (allowing single-sample gaps in the util map).
	var eps []Incident
	var cur *Incident
	run := 0
	for i, ts := range rtt.TS {
		u := utilAt[ts]
		loaded := u >= utilThresholdPct && rtt.Val[i] >= baseline+bloatThresholdMS
		if loaded {
			run++
			if cur == nil {
				cur = &Incident{Start: ts, End: ts, PeakMS: rtt.Val[i] - baseline, Source: "passive"}
			} else {
				cur.End = ts
				if d := rtt.Val[i] - baseline; d > cur.PeakMS {
					cur.PeakMS = d
				}
			}
			// name the heavier direction at this sample
			if txu, ok := txAt[ts]; ok {
				if rxValAt(rxs, ts) >= txu {
					cur.Direction = "download"
				} else {
					cur.Direction = "upload"
				}
			}
		} else {
			if cur != nil && run >= passiveMinSamples {
				cur.Hint = "the line was heavily used and latency climbed " + strconv.FormatFloat(cur.PeakMS, 'f', 0, 64) + " ms above normal — queueing delay while the shaper held the ceiling"
				eps = append(eps, *cur)
			}
			cur = nil
			run = 0
		}
	}
	if cur != nil && run >= passiveMinSamples {
		cur.Hint = "the line was heavily used and latency climbed " + strconv.FormatFloat(cur.PeakMS, 'f', 0, 64) + " ms above normal — queueing delay while the shaper held the ceiling"
		eps = append(eps, *cur)
	}
	return eps
}

func rxValAt(se vm.Series, ts int64) float64 {
	for i, t := range se.TS {
		if t == ts {
			return se.Val[i]
		}
	}
	return -1
}

// shapedBitsPerS reads the configured shaper rate from the live CAKE
// snapshot (falling back to 415 Mbit — the configured rate here).
func (s *Server) shapedBitsPerS() float64 {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	for _, cs := range s.stats {
		if b := parseBandwidth(cs.Bandwidth); b > 0 {
			return b
		}
	}
	return 415e6
}

// parseBandwidth parses a tc bandwidth string ("415Mbit", "1Gbit", "50MBps")
// into bits/s, returning 0 when unparseable. It delegates to
// health.ShapedBits so both packages agree on tc units: "bit" is bits/s,
// "bps" is BYTES/s (×8), and K/M/G/T prefixes are accepted in either case.
func parseBandwidth(s string) float64 {
	return health.ShapedBits(s)
}

// TunnelReport is the response of /api/tunnel.
type TunnelReport struct {
	Available     bool    `json:"available"`
	Endpoint      string  `json:"endpoint"`
	HandshakeAge  float64 `json:"handshake_age_s"` // seconds since last handshake; -1 = never
	RxBytes       uint64  `json:"rx_bytes"`
	TxBytes       uint64  `json:"tx_bytes"`
	RxPerS        float64 `json:"rx_per_s"`
	TxPerS        float64 `json:"tx_per_s"`
	RatesOK       bool    `json:"rates_ok"`
	Reconnects24h int     `json:"reconnects_24h"`
	Reconnects7d  int     `json:"reconnects_7d"`
}

func (s *Server) handleAPITunnel(c fiber.Ctx) error {
	rep := TunnelReport{HandshakeAge: -1}
	if s.sys != nil && s.sys.Warp != nil {
		w := s.sys.Warp.Snapshot()
		rep.Available = w.Available
		rep.Endpoint = w.Endpoint
		rep.RxBytes = w.RxBytes
		rep.TxBytes = w.TxBytes
		rep.RxPerS = w.RxPerS
		rep.TxPerS = w.TxPerS
		rep.RatesOK = w.RatesKnown
		if !w.Handshake.IsZero() {
			rep.HandshakeAge = time.Since(w.Handshake).Seconds()
		}
	}
	if s.events != nil {
		now := time.Now().Unix()
		rep.Reconnects24h = s.events.CountSince("warp", now-24*3600)
		rep.Reconnects7d = s.events.CountSince("warp", now-7*24*3600)
	}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(rep)
	return c.Send(b)
}

// percentile returns the p-th percentile of vals (linear interpolation).
func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := make([]float64, len(vals))
	copy(sorted, vals)
	sort.Float64s(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := p / 100 * float64(len(sorted)-1)
	lo := int(rank)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}

func median(vals []float64) float64 {
	return percentile(vals, 50)
}
