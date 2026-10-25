package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	easyjson "github.com/mailru/easyjson"

	fiber "github.com/gofiber/fiber/v3"
	recovermiddleware "github.com/gofiber/fiber/v3/middleware/recover"

	"github.com/dinjojo/openwrt-view/pkg/sysmon"
	"github.com/dinjojo/openwrt-view/pkg/tapo"

	"github.com/dinjojo/openwrt-view/pkg/alerts"
	"github.com/dinjojo/openwrt-view/pkg/clients"
	"github.com/dinjojo/openwrt-view/pkg/events"
	"github.com/dinjojo/openwrt-view/pkg/health"
	"github.com/dinjojo/openwrt-view/pkg/history"
	"github.com/dinjojo/openwrt-view/pkg/log"
	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/orbissn"
	"github.com/dinjojo/openwrt-view/pkg/parser"
	"github.com/dinjojo/openwrt-view/pkg/radio"
	"github.com/dinjojo/openwrt-view/pkg/types"
	"github.com/dinjojo/openwrt-view/pkg/usage"
	"github.com/dinjojo/openwrt-view/pkg/vm"
	"github.com/dinjojo/openwrt-view/pkg/wan"
	"github.com/dinjojo/openwrt-view/web"
)

//go:embed index.html
var indexHTML string

const sseBufSize = 4
const sseRetryInterval = "2000"

// Server encapsulates the Fiber app, polling state, SSE client registry and
// history store.  It is safe for concurrent use.
type Server struct {
	app          *fiber.App
	statsMu      sync.RWMutex
	stats        []types.CakeStats
	ssesMu       sync.Mutex
	clients      map[chan []byte]struct{}
	pollInterval time.Duration
	history      *history.HistoryStore
	stopOnce     sync.Once
	vmc          *vm.Client
	healthMu     sync.Mutex
	healthCache  []health.Check
	healthAt     time.Time
	clientStore  *clients.Store
	wan          *wan.Poller
	sys          *sysmon.Pollers
	orbi         *orbi.Poller
	tapo         *tapo.Poller // smart-plug poller; nil when unconfigured
	shell        *orbissn.Poller  // Orbi shell (SSH/telnet) poller; nil or disabled when unconfigured
	radio        *radio.Collector // local monitor-mode dongle; nil or disabled when unconfigured
	alerts       *alerts.Notifier // ntfy push; nil when unconfigured
	usage        *usage.Store     // per-client daily usage files; nil disables
	events       *events.Store
	loc          *time.Location // calendar-day zone for reports and probe-episode labels (-tz)
	version      string
	configHashes map[string]string // last sha256 of each /etc/config file
}

func New(addr string, interval time.Duration, histCap int, vmURL, version string, orb *orbi.Poller) *Server {
	s := &Server{
		clients:      make(map[chan []byte]struct{}),
		pollInterval: interval,
		history:      history.NewHistoryStore(histCap),
		clientStore:  clients.New(30*time.Second, vmURL),
		orbi:         orb,
		loc:          time.Local,
		version:      version,
	}
	if vmURL != "" {
		s.vmc = vm.New(vmURL)
	}

	app := fiber.New(fiber.Config{
		ServerHeader: "openwrt-view",
	})
	app.Use(recovermiddleware.New())

	app.Get("/", s.handleIndex)
	app.Get("/favicon.ico", func(c fiber.Ctx) error { return c.Status(204).SendString("") })
	app.Get("/manifest.webmanifest", func(c fiber.Ctx) error {
		c.Set("Content-Type", "application/manifest+json")
		return c.Send(web.Manifest)
	})
	app.Get("/icon-512.png", func(c fiber.Ctx) error {
		c.Set("Content-Type", "image/png")
		c.Set("Cache-Control", "public, max-age=86400")
		return c.Send(web.Icon512)
	})
	app.Get("/api/stats", s.handleAPIStats)
	app.Get("/api/history", s.handleAPIHistory)
	app.Get("/api/history/vm", s.handleAPIHistoryVM)
	app.Get("/api/history/wan", s.handleAPIHistoryWAN)
	app.Get("/api/history/system", s.handleAPIHistorySystem)
	app.Get("/api/history/clients", s.handleAPIHistoryClients)
	app.Get("/api/history/orbi", s.handleAPIHistoryOrbi)
	app.Get("/api/history/client", s.handleAPIClientHistory)
	app.Get("/api/clients", s.handleAPIClients)
	app.Get("/api/usage/window", s.handleAPIUsageWindow)
	app.Get("/api/health", s.handleAPIHealth)
	app.Get("/api/events", s.handleAPIEvents)
	app.Get("/api/percentiles", s.handleAPIPercentiles)
	app.Get("/api/incidents", s.handleAPIIncidents)
	app.Get("/api/tunnel", s.handleAPITunnel)
	app.Get("/api/orbi", s.handleAPIOrbi)
	app.Get("/api/tapo", s.handleAPITapo)
	app.Get("/api/radio", s.handleAPIRadio)
	app.Get("/api/config", s.handleAPIConfig)
	app.Get("/api/report", s.handleAPIReport)
	app.Get("/api/usage", s.handleAPIUsage)
	app.Get("/events", s.handleSSE)

	s.app = app
	return s
}

func (s *Server) Run(ctx context.Context, addr string) error {
	s.forcePoll()
	s.wan = wan.New(ctx)
	s.sys = sysmon.NewAll(ctx)
	s.events = events.New("/opt/monitoring/openwrt-view-events.json")
	if s.alerts.Enabled() {
		s.events.SetHook(func(kind, sev, msg string) { s.alerts.Notify(kind, sev, msg) })
	}
	s.events.Add("monitor", "info", "Monitor restarted ("+s.version+") — watching WAN, WARP and Cake")
	if s.orbi.Enabled() {
		s.orbi.SetEventHook(s.events.Add)
		s.orbi.SetNameResolver(s.clientStore.Name)
	}
	go s.orbiRun(ctx)
	if s.tapo != nil {
		s.tapo.SetVMClient(s.vmc)
		go s.tapo.Run(ctx)
	}
	if s.shell.Enabled() {
		s.shell.SetEventHook(s.events.Add)
		go s.shell.Run(ctx)
	}
	go s.radio.Run(ctx) // returns at once when no dongle is configured
	go s.recordUsage(ctx)
	go s.watchEvents(ctx)
	go s.watchAccounting(ctx)
	go s.runPoller(ctx)
	go s.clientStore.Run(ctx, s.vmc) // per-client accounting poller
	go func() {
		<-ctx.Done()
		_ = s.app.Shutdown()
	}()
	log.Logger.Info().Str("addr", addr).Dur("interval", s.pollInterval).Msg("listening")
	return s.app.Listen(addr)
}

func (s *Server) forcePoll() {
	defer func() {
		if r := recover(); r != nil {
			log.Logger.Error().Interface("panic", r).Msg("poller recovered")
		}
	}()
	stats, err := parser.CollectStats(context.Background())
	if err != nil {
		log.Logger.Warn().Err(err).Msg("tc poll failed")
		return
	}
	s.history.Record(stats, s.pollInterval)
	s.statsMu.Lock()
	s.stats = stats
	s.statsMu.Unlock()
	s.broadcast(stats)
}

func (s *Server) runPoller(ctx context.Context) {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.forcePoll()
			// Persist the WAN session state to VictoriaMetrics once a minute
			// so reliability trends can count PPPoE transitions over weeks.
			ticks++
			if s.vmc != nil && s.wan != nil && ticks%60 == 0 {
				up := 0.0
				if snap := s.wan.Snapshot(); snap.Up {
					up = 1.0
				}
				line := "wan_session_up{instance=\"nanopi-r6c\"} " +
					strconv.FormatFloat(up, 'f', -1, 64) + " " +
					strconv.FormatInt(time.Now().UnixMilli(), 10) + "\n"
				go func(body string) {
					importCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = s.vmc.Import(importCtx, body)
				}(line)
			}
		}
	}
}

func (s *Server) broadcast(stats []types.CakeStats) {
	resp := types.StatsResponse{Interfaces: stats, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	payload, _ := easyjson.Marshal(&resp)
	event := buildSSEEvent(payload)

	s.ssesMu.Lock()
	defer s.ssesMu.Unlock()
	for ch := range s.clients {
		select {
		case ch <- event:
		default:
		}
	}
}

var sseBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }}

func buildSSEEvent(payload []byte) []byte {
	buf := sseBufPool.Get().(*[]byte)
	*buf = (*buf)[:0]
	*buf = append(*buf, "retry: "...)
	*buf = append(*buf, sseRetryInterval...)
	*buf = append(*buf, "\ndata: "...)
	*buf = append(*buf, payload...)
	*buf = append(*buf, "\n\n"...)
	out := make([]byte, len(*buf))
	copy(out, *buf)
	sseBufPool.Put(buf)
	return out
}

func (s *Server) handleIndex(c fiber.Ctx) error {
	c.Set("Content-Type", "text/html; charset=utf-8")
	c.Set("Cache-Control", "no-store")
	return c.SendString(indexHTML)
}

func (s *Server) handleAPIStats(c fiber.Ctx) error {
	s.statsMu.RLock()
	snapshot := s.stats
	s.statsMu.RUnlock()
	resp := types.StatsResponse{Interfaces: snapshot, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := easyjson.Marshal(&resp)
	return c.Send(b)
}

func (s *Server) handleAPIHistory(c fiber.Ctx) error {
	snap := s.history.Snapshot()
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(snap)
	return c.Send(b)
}

// vmRangeSpec describes one selectable long-range history window.
type vmRangeSpec struct {
	step      string
	rateLimit string // Prometheus rate window (matches ~2 polls minimum)
}

var vmRanges = map[string]vmRangeSpec{
	"1h":  {step: "15s", rateLimit: "2m"},
	"3h":  {step: "30s", rateLimit: "3m"},
	"6h":  {step: "60s", rateLimit: "4m"},
	"24h": {step: "120s", rateLimit: "8m"},
	"7d":  {step: "600s", rateLimit: "30m"},
	"30d": {step: "1800s", rateLimit: "1h"},
}

// specForSpan picks a query step and rate window for an arbitrary span
// (custom from/to windows). Roughly mirrors vmRanges' resolution curve:
// ~1/240th of the span per point, clamped to the finest/coarsest specs.
func specForSpan(span int64) vmRangeSpec {
	step := span / 240
	switch {
	case step <= 15:
		return vmRanges["1h"]
	case step <= 30:
		return vmRanges["3h"]
	case step <= 60:
		return vmRanges["6h"]
	case step <= 120:
		return vmRanges["24h"]
	case step <= 600:
		return vmRanges["7d"]
	default:
		return vmRanges["30d"]
	}
}

// handleAPIHistoryVM serves long-range history assembled from VictoriaMetrics
// in the same shape as /api/history (map[iface][]HistorySample) so the existing
// modal charts can render it unchanged.
func (s *Server) handleAPIHistoryVM(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	rng := c.Query("range", "6h")
	spec, ok := vmRanges[rng]
	if !ok {
		return c.Status(400).SendString(`{"error":"range must be one of 1h,6h,24h,7d"}`)
	}

	end := time.Now().Unix()
	start := end
	switch rng {
	case "1h":
		start = end - 3600
	case "6h":
		start = end - 6*3600
	case "24h":
		start = end - 24*3600
	case "7d":
		start = end - 7*24*3600
	}
	// Give rate() some history to chew on at the start of the window.
	rateStart := start - 1800

	ctx := c.Context()
	queries := map[string]string{
		// type="tx" is the interface-level counter (sqm="eth0"/"ifb4eth0").
		"tx": fmt.Sprintf("sum by (sqm) (rate(collectd_sqm_bytes{type=\"tx\"}[%s]))", spec.rateLimit),
		// Tin-level gauges live under sqm="eth0-tin-t0" etc.
		"av": `max by (sqm) (collectd_sqm_gauge{type="avg_delay_us"}) / 1000`,
		"pk": `max by (sqm) (collectd_sqm_gauge{type="peak_delay_us"}) / 1000`,
		"dr": fmt.Sprintf("sum by (sqm) (rate(collectd_sqm_gauge{type=\"drops\"}[%s]))", spec.rateLimit),
	}

	type ifaceSeries struct {
		t, tx, av, pk, dr []float64
	}
	byIface := map[string]*ifaceSeries{}

	fetch := func(query string, apply func(is *ifaceSeries, s vm.Series)) error {
		series, err := s.vmc.QueryRange(ctx, query, rateStart, end, spec.step)
		if err != nil {
			return err
		}
		for _, ser := range series {
			sqm := ser.Labels["sqm"] // e.g. "eth0-tin-t0" or "ifb4eth0-tin-t0"
			iface := sqm
			if i := indexDashTin(sqm); i > 0 {
				iface = sqm[:i]
			}
			is := byIface[iface]
			if is == nil {
				is = &ifaceSeries{}
				byIface[iface] = is
			}
			apply(is, ser)
		}
		return nil
	}

	// Query each field, aligning timestamps to the tx series' grid.
	err := fetch(queries["tx"], func(is *ifaceSeries, s vm.Series) {
		is.t = append(is.t, toFloat64(s.TS)...)
		is.tx = append(is.tx, s.Val...)
	})
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetch(queries["av"], func(is *ifaceSeries, s vm.Series) { is.av = append(is.av, s.Val...) }); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetch(queries["pk"], func(is *ifaceSeries, s vm.Series) { is.pk = append(is.pk, s.Val...) }); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetch(queries["dr"], func(is *ifaceSeries, s vm.Series) { is.dr = append(is.dr, s.Val...) }); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}

	out := types.HistoryResponse{}
	for iface, is := range byIface {
		n := len(is.t)
		if n < 2 {
			continue
		}
		samples := make([]types.HistorySample, n)
		for i := 0; i < n; i++ {
			samples[i] = types.HistorySample{
				T:  int64(is.t[i]),
				Tx: is.tx[i],
				Av: is.av[i],
				Pk: is.pk[i],
				Dr: is.dr[i],
			}
		}
		out[iface] = samples
	}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

// indexDashTin finds the "-tin-" separator in an sqm label like "eth0-tin-t0".
func indexDashTin(s string) int {
	return strings.Index(s, "-tin-")
}

func toFloat64(in []int64) []float64 {
	out := make([]float64, len(in))
	for i, v := range in {
		out[i] = float64(v)
	}
	return out
}

// handleAPIHealth evaluates (with a short cache) the health checks.
func (s *Server) handleAPIHealth(c fiber.Ctx) error {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if s.healthAt.IsZero() || time.Since(s.healthAt) > 10*time.Second {
		var live []types.CakeStats
		s.statsMu.RLock()
		live = s.stats
		s.statsMu.RUnlock()
		s.healthCache = health.Eval(c.Context(), s.vmc, live, s.history, s.clientStore, s.wan, s.sys, s.orbi, s.tapo)
		s.healthAt = time.Now()
	}

	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(s.healthCache)
	return c.Send(b)
}

// handleAPIClients serves the live per-client accounting snapshot.
func (s *Server) handleAPIClients(c fiber.Ctx) error {
	snap := s.clientStore.Snapshot()
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(snap)
	return c.Send(b)
}

// clientDetailHistory is one client's full history for the drill-down modal.
type clientDetailHistory struct {
	T       []int64   `json:"t"`
	Rx      []float64 `json:"rx"`       // bytes/s
	Tx      []float64 `json:"tx"`       // bytes/s
	Conns   []float64 `json:"conns"`    // connection count over time
	TotalRx float64   `json:"total_rx"` // bytes moved down in window
	TotalTx float64   `json:"total_tx"` // bytes moved up in window
}

var macRe = regexp.MustCompile(`^[0-9a-fA-F:]{12,17}$`)

// handleAPIClientHistory returns detailed history for one client by MAC.
func (s *Server) handleAPIClientHistory(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	mac := c.Query("mac")
	if !macRe.MatchString(mac) {
		return c.Status(400).SendString(`{"error":"mac must be a colon-separated MAC address"}`)
	}
	rng := c.Query("range", "6h")
	spec, ok := vmRanges[rng]
	if !ok {
		return c.Status(400).SendString(`{"error":"range must be one of 1h,6h,24h,7d"}`)
	}
	end := time.Now().Unix()
	start := rangeStart(rng, end)
	rateStart := start - 1800
	wl := spec.rateLimit
	ctx := c.Context()

	label := `mac="` + mac + `"`
	rxSeries, err := s.vmc.QueryRange(ctx,
		`rate(client_bytes_total{`+label+`,dir="rx"}[`+wl+`])`, rateStart, end, spec.step)
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	txSeries, err := s.vmc.QueryRange(ctx,
		`rate(client_bytes_total{`+label+`,dir="tx"}[`+wl+`])`, rateStart, end, spec.step)
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	connSeries, err := s.vmc.QueryRange(ctx,
		`client_conns{`+label+`}`, start, end, spec.step)
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}

	out := clientDetailHistory{}
	sum := func(series []vm.Series) (grid []int64, vals []float64, total float64) {
		for _, sr := range series {
			if len(sr.TS) == 0 {
				continue
			}
			if grid == nil {
				grid = sr.TS
			}
			for _, v := range sr.Val {
				total += v * spec.stepSeconds()
			}
		}
		if grid == nil {
			grid = []int64{}
		}
		vals = make([]float64, len(grid))
		for _, sr := range series {
			for i, t := range sr.TS {
				for gi, g := range grid {
					if g == t {
						vals[gi] = sr.Val[i]
						break
					}
				}
			}
		}
		return grid, vals, total
	}

	var rxT, txT, cnT []int64
	rxT, out.Rx, out.TotalRx = sum(rxSeries)
	txT, out.Tx, out.TotalTx = sum(txSeries)
	cnT, out.Conns, _ = sum(connSeries)

	// Choose the densest grid as canonical and align the others onto it.
	canonical := rxT
	if len(txT) > len(canonical) {
		canonical = txT
	}
	if len(cnT) > len(canonical) {
		canonical = cnT
	}
	out.T = canonical
	out.Rx = alignVals(rxT, out.Rx, canonical)
	out.Tx = alignVals(txT, out.Tx, canonical)
	out.Conns = alignVals(cnT, out.Conns, canonical)

	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

// alignVals resamples values from grid g onto canonical grid c.
func alignVals(g []int64, v []float64, canonical []int64) []float64 {
	if len(g) == len(canonical) && len(g) > 0 && g[0] == canonical[0] {
		return v // already aligned
	}
	out := make([]float64, len(canonical))
	idx := map[int64]float64{}
	for i, t := range g {
		idx[t] = v[i]
	}
	for i, t := range canonical {
		out[i] = idx[t]
	}
	return out
}

// clientTopSeries is one client's traffic history over a range window.
type clientTopSeries struct {
	MAC  string    `json:"mac"`
	Name string    `json:"name"`
	T    []int64   `json:"t"`
	Rx   []float64 `json:"rx"` // bytes/s
	Tx   []float64 `json:"tx"` // bytes/s
}

// handleAPIHistoryClients returns top-talker traffic history for a range.
func (s *Server) handleAPIHistoryClients(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	rng := c.Query("range", "6h")
	spec, ok := vmRanges[rng]
	if !ok {
		return c.Status(400).SendString(`{"error":"range must be one of 1h,6h,24h,7d"}`)
	}
	end := time.Now().Unix()
	start := rangeStart(rng, end)
	rateStart := start - 1800
	ctx := c.Context()

	wl := spec.rateLimit
	rxSeries, err := s.vmc.QueryRange(ctx,
		`sum by (mac,name) (rate(client_bytes_total{dir="rx"}[`+wl+`]))`, rateStart, end, spec.step)
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	txSeries, err := s.vmc.QueryRange(ctx,
		`sum by (mac,name) (rate(client_bytes_total{dir="tx"}[`+wl+`]))`, rateStart, end, spec.step)
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}

	// Pick top 8 clients by total bytes moved in the window.
	type agg struct {
		name string
		sum  float64
	}
	aggs := map[string]*agg{}
	for _, s := range rxSeries {
		mac := s.Labels["mac"]
		a := aggs[mac]
		if a == nil {
			a = &agg{name: s.Labels["name"]}
			aggs[mac] = a
		}
		for _, v := range s.Val {
			a.sum += v * spec.stepSeconds()
		}
	}
	macs := make([]string, 0, len(aggs))
	for mac := range aggs {
		macs = append(macs, mac)
	}
	// simple selection of top 8
	for n := 0; n < 8 && n < len(macs); n++ {
		for i := n + 1; i < len(macs); i++ {
			if aggs[macs[i]].sum > aggs[macs[n]].sum {
				macs[n], macs[i] = macs[i], macs[n]
			}
		}
	}
	if len(macs) > 8 {
		macs = macs[:8]
	}

	txByMac := map[string]vm.Series{}
	for _, s := range txSeries {
		mac := s.Labels["mac"]
		txByMac[mac] = s
	}

	out := []clientTopSeries{}
	var grid []int64
	for _, mac := range macs {
		rxs := findSeriesByMac(rxSeries, mac)
		txs := findSeriesByMac(txSeries, mac)
		if rxs == nil {
			continue
		}
		if grid == nil {
			// Canonical x-axis: the top talker's timestamps.
			grid = rxs.TS
		}
		rxVals := alignTo(rxs, grid)
		cs := clientTopSeries{MAC: mac, Name: s.clientStore.Name(mac), T: grid, Rx: rxVals}
		if txs != nil {
			cs.Tx = alignTo(txs, grid)
		} else {
			cs.Tx = make([]float64, len(grid))
		}
		out = append(out, cs)
	}

	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

func findSeriesByMac(series []vm.Series, mac string) *vm.Series {
	for i := range series {
		if series[i].Labels["mac"] == mac {
			return &series[i]
		}
	}
	return nil
}

// alignTo resamples series values onto the given timestamp grid.
func alignTo(s *vm.Series, grid []int64) []float64 {
	out := make([]float64, len(grid))
	idx := 0
	for gi, g := range grid {
		for idx < len(s.TS)-1 && s.TS[idx+1] <= g {
			idx++
		}
		if idx < len(s.TS) && s.TS[idx] <= g && g-s.TS[idx] < 3600 {
			out[gi] = s.Val[idx]
		}
	}
	return out
}

// sysHistory is aligned system time series for the System tab.
type sysHistory struct {
	T       []int64   `json:"t"`
	Temp    []float64 `json:"temp"`    // °C (max across zones)
	Load    []float64 `json:"load"`    // 1-minute load average
	CPU     []float64 `json:"cpu"`     // % CPU utilisation (all cores, rate window)
	Mem     []float64 `json:"mem"`     // % RAM available
	Conns   []float64 `json:"conns"`   // conntrack entries in use
	WANRTT  []float64 `json:"wan"`     // ms, average across ping targets
	WANErrs []float64 `json:"wanerrs"` // WAN link errors+drops per minute
	WANRx   []float64 `json:"wanrx"`   // WAN download, Mbit/s
	WANTx   []float64 `json:"wantx"`   // WAN upload, Mbit/s
	BloatDn []float64 `json:"bloatdn"` // added latency under download load, ms
	BloatUp []float64 `json:"bloatup"` // added latency under upload load, ms

	// WAN performance strip (last 24h), scalars for the summary cards.
	PeakDown   float64 `json:"peakdown"`   // Mbit/s, busiest 5m window
	PeakUp     float64 `json:"peakup"`     // Mbit/s
	P95Down    float64 `json:"p95down"`    // Mbit/s, typical busy rate
	P95Up      float64 `json:"p95up"`      // Mbit/s
	TotalDown  float64 `json:"totaldown"`  // GB moved in 24h
	TotalUp    float64 `json:"totalup"`    // GB
	ShapedDown float64 `json:"shapeddown"` // provisioned Mbit/s from SQM
	ShapedUp   float64 `json:"shapedup"`   // Mbit/s
}

// wanHistory is the Overview line-health hero payload: WAN round-trip time
// and packet loss over a long window, sampled from the VictoriaMetrics store
// (collectd's ping plugin, averaged across probe targets).
type wanHistory struct {
	T       []int64   `json:"t"`
	RTTMS   []float64 `json:"rtt_ms"`
	LossPct []float64 `json:"loss_pct"` // parallel to T; empty when unknown
}

// handleAPIUsageWindow returns per-client byte totals (GB) integrated over
// the requested window — same ?range=/?from=&to= grammar as the history
// endpoints. The usage donut and top-clients cards use it whenever a window
// other than the billing period is selected, so every panel speaks the same
// time range.
func (s *Server) handleAPIUsageWindow(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	spec, start, end, errc := parseWindow(c, "24h")
	if errc != "" {
		return c.Status(400).SendString(`{"error":"` + errc + `"}`)
	}
	rateStart := start - 1800 // rate window bleeds left of the range
	wl := spec.rateLimit
	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	type agg struct{ rx, tx float64 }
	aggs := map[string]*agg{}
	for _, dir := range []string{"rx", "tx"} {
		series, err := s.vmc.QueryRange(ctx,
			`sum by (mac) (rate(client_bytes_total{dir="`+dir+`"}[`+wl+`]))`, rateStart, end, spec.step)
		if err != nil {
			return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
		}
		for _, sr := range series {
			a := aggs[sr.Labels["mac"]]
			if a == nil {
				a = &agg{}
				aggs[sr.Labels["mac"]] = a
			}
			for _, v := range sr.Val {
				if dir == "rx" {
					a.rx += v * spec.stepSeconds()
				} else {
					a.tx += v * spec.stepSeconds()
				}
			}
		}
	}

	type cliTotals struct {
		RxGB float64 `json:"rx_gb"`
		TxGB float64 `json:"tx_gb"`
	}
	// WAN-level traffic over the same window. Traffic that never crosses
	// a LAN client counter (WARP tunnel keepalives and reconnects, DNS,
	// NTP, monitoring pushes, the router itself) is invisible to
	// nlbwmon, so an idle-looking window can still carry real WAN volume.
	var wanRx, wanTx float64
	for _, wq := range []struct {
		prop string
		dest *float64
	}{{"receive", &wanRx}, {"transmit", &wanTx}} {
		series, err := s.vmc.QueryRange(ctx,
			`sum(rate(node_network_`+wq.prop+`_bytes_total{device="pppoe-wan"}[`+wl+`]))`,
			rateStart, end, spec.step)
		if err != nil {
			continue
		}
		for _, sr := range series {
			for _, v := range sr.Val {
				*wq.dest += v * spec.stepSeconds()
			}
		}
	}
	out := struct {
		Start   int64                 `json:"start"`
		End     int64                 `json:"end"`
		Step    string                `json:"step"`
		WanRxGB float64               `json:"wan_rx_gb"`
		WanTxGB float64               `json:"wan_tx_gb"`
		Clients map[string]*cliTotals `json:"clients"`
	}{Start: start, End: end, Step: spec.step, Clients: map[string]*cliTotals{}}
	out.WanRxGB = wanRx / 1e9
	out.WanTxGB = wanTx / 1e9
	for mac, a := range aggs {
		out.Clients[mac] = &cliTotals{RxGB: a.rx / 1e9, TxGB: a.tx / 1e9}
	}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

func (s *Server) handleAPIHistoryWAN(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	spec, start, end, errc := parseWindow(c, "24h")
	if errc != "" {
		return c.Status(400).SendString(`{"error":"` + errc + `"}`)
	}

	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	out := wanHistory{}
	if se, err := s.vmc.QueryRange(ctx, `avg(collectd_ping)`, start, end, spec.step); err == nil && len(se) > 0 {
		out.T, out.RTTMS = se[0].TS, se[0].Val
	}
	if se, err := s.vmc.QueryRange(ctx, `avg(collectd_ping_ping_droprate)`, start, end, spec.step); err == nil && len(se) > 0 {
		loss := se[0].Val
		out.LossPct = make([]float64, len(loss))
		for i, v := range loss {
			out.LossPct[i] = v * 100
		}
	}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

// parseWindow reads either ?range=1h|3h|6h|24h|7d|30d or an explicit custom
// window ?from=<unix>&to=<unix> (to clamped to now+5min, span 2 min … 31 days)
// and returns the query spec plus absolute start/end. An empty errc means OK.
func parseWindow(c fiber.Ctx, def string) (spec vmRangeSpec, start, end int64, errc string) {
	if fromQ := c.Query("from"); fromQ != "" {
		from, err1 := strconv.ParseInt(fromQ, 10, 64)
		to, err2 := strconv.ParseInt(c.Query("to"), 10, 64)
		if err1 != nil || err2 != nil || from <= 0 || to <= 0 {
			return vmRangeSpec{}, 0, 0, "from and to must be unix seconds"
		}
		if to > time.Now().Unix()+300 {
			to = time.Now().Unix() + 300
		}
		span := to - from
		if span < 120 {
			return vmRangeSpec{}, 0, 0, "window too short (min 2 minutes)"
		}
		if span > 31*24*3600 {
			return vmRangeSpec{}, 0, 0, "window too long (max 31 days)"
		}
		return specForSpan(span), from, to, ""
	}
	rng := c.Query("range", def)
	spec, ok := vmRanges[rng]
	if !ok {
		return vmRangeSpec{}, 0, 0, "range must be one of 1h,3h,6h,24h,7d,30d"
	}
	end = time.Now().Unix()
	return spec, rangeStart(rng, end), end, ""
}

// handleAPIHistorySystem returns aligned system health history for a range.
// Either ?range=1h|3h|6h|24h|7d|30d or an explicit custom window via
// ?from=<unix>&to=<unix> (to defaults to now; span capped at 31 days).
func (s *Server) handleAPIHistorySystem(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	spec, start, end, errc := parseWindow(c, "6h")
	if errc != "" {
		return c.Status(400).SendString(`{"error":"` + errc + `"}`)
	}
	ctx := c.Context()

	out := sysHistory{}
	// fetchAvg runs a query and stores averaged values. The first successful
	// query defines the canonical timestamp grid; later queries are aligned
	// onto it so all charts share one x-axis.
	var grid []int64
	fetchAvg := func(query string, out *[]float64) error {
		series, err := s.vmc.QueryRange(ctx, query, start, end, spec.step)
		if err != nil {
			return err
		}
		if len(series) == 0 {
			return nil
		}
		if grid == nil {
			grid = series[0].TS
		}
		vals := make([]float64, len(grid))
		for gi, g := range grid {
			sum, n := 0.0, 0
			for _, sr := range series {
				for i, t := range sr.TS {
					if t == g {
						sum += sr.Val[i]
						n++
					}
				}
			}
			if n > 0 {
				vals[gi] = sum / float64(n)
			}
		}
		*out = vals
		return nil
	}

	if err := fetchAvg(`max(collectd_thermal_temperature)`, &out.Temp); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`node_load1`, &out.Load); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`100 - avg(rate(node_cpu_seconds_total{mode="idle"}[`+spec.rateLimit+`])) * 100`, &out.CPU); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`, &out.Mem); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`collectd_conntrack`, &out.Conns); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`collectd_ping`, &out.WANRTT); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	// WAN link errors/drops per minute (hardware counters on the WAN device).
	if err := fetchAvg(`60 * sum(rate(node_network_receive_errs_total{device=~"(wan|pppoe|eth0).*"}[`+spec.rateLimit+`]) + rate(node_network_transmit_errs_total{device=~"(wan|pppoe|eth0).*"}[`+spec.rateLimit+`]) + rate(node_network_receive_drop_total{device=~"(wan|pppoe|eth0).*"}[`+spec.rateLimit+`]) + rate(node_network_transmit_drop_total{device=~"(wan|pppoe|eth0).*"}[`+spec.rateLimit+`]) + rate(node_network_transmit_carrier_total{device=~"(wan|pppoe|eth0).*"}[`+spec.rateLimit+`]))`, &out.WANErrs); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	// Actual WAN throughput (download = rx, upload = tx), Mbit/s.
	if err := fetchAvg(`rate(node_network_receive_bytes_total{device="pppoe-wan"}[`+spec.rateLimit+`]) * 8 / 1000000`, &out.WANRx); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`rate(node_network_transmit_bytes_total{device="pppoe-wan"}[`+spec.rateLimit+`]) * 8 / 1000000`, &out.WANTx); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}

	// WAN performance strip: scalar metrics over the last 24 hours.
	// fetchScalar runs an instant query and stores the first point value.
	fetchScalar := func(query string, out *float64) {
		pts, err := s.vmc.Query(ctx, query)
		if err != nil || len(pts) == 0 {
			return
		}
		*out = pts[0].Val
	}
	// Latency added under load (bufferbloat history from the probe).
	if err := fetchAvg(`probe_bloat_ms{direction="down"}`, &out.BloatDn); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	if err := fetchAvg(`probe_bloat_ms{direction="up"}`, &out.BloatUp); err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	const wanDev = `{device="pppoe-wan"}`
	fetchScalar(`max(max_over_time((rate(node_network_receive_bytes_total`+wanDev+`[5m]))[24h:1m])) * 8 / 1e6`, &out.PeakDown)
	fetchScalar(`max(max_over_time((rate(node_network_transmit_bytes_total`+wanDev+`[5m]))[24h:1m])) * 8 / 1e6`, &out.PeakUp)
	fetchScalar(`quantile(0.95, quantile_over_time(0.95, (rate(node_network_receive_bytes_total`+wanDev+`[5m]))[24h:1m])) * 8 / 1e6`, &out.P95Down)
	fetchScalar(`quantile(0.95, quantile_over_time(0.95, (rate(node_network_transmit_bytes_total`+wanDev+`[5m]))[24h:1m])) * 8 / 1e6`, &out.P95Up)
	fetchScalar(`increase(node_network_receive_bytes_total`+wanDev+`[24h]) / 1e9`, &out.TotalDown)
	fetchScalar(`increase(node_network_transmit_bytes_total`+wanDev+`[24h]) / 1e9`, &out.TotalUp)

	// Provisioned capacity from the live CAKE shapers, Mbit/s.
	s.statsMu.RLock()
	liveStats := s.stats
	s.statsMu.RUnlock()
	for _, cs := range liveStats {
		switch cs.Direction {
		case "ingress":
			out.ShapedDown = health.ShapedBits(cs.Bandwidth) / 1e6
		case "egress":
			out.ShapedUp = health.ShapedBits(cs.Bandwidth) / 1e6
		}
	}
	if grid == nil {
		grid = []int64{}
	}
	out.T = grid

	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(out)
	return c.Send(b)
}

// rangeStart maps a range key to a start unix timestamp.
func rangeStart(rng string, end int64) int64 {
	switch rng {
	case "1h":
		return end - 3600
	case "3h":
		return end - 3*3600
	case "6h":
		return end - 6*3600
	case "24h":
		return end - 24*3600
	case "7d":
		return end - 7*24*3600
	case "30d":
		return end - 30*24*3600
	}
	return end - 6*3600
}

func (r vmRangeSpec) stepSeconds() float64 {
	switch r.step {
	case "15s":
		return 15
	case "60s":
		return 60
	case "120s":
		return 120
	case "600s":
		return 600
	}
	return 60
}

func (s *Server) handleSSE(c fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	ch := make(chan []byte, sseBufSize)

	s.ssesMu.Lock()
	s.clients[ch] = struct{}{}
	s.ssesMu.Unlock()

	// Capture initial snapshot before entering the stream writer.
	s.statsMu.RLock()
	snapshot := s.stats
	s.statsMu.RUnlock()

	c.RequestCtx().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer func() {
			s.ssesMu.Lock()
			delete(s.clients, ch)
			s.ssesMu.Unlock()
		}()

		// Send the current snapshot immediately so the page isn't blank.
		if len(snapshot) > 0 {
			resp := types.StatsResponse{
				Interfaces: snapshot,
				UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
			}
			if payload, err := easyjson.Marshal(&resp); err == nil {
				if _, err = w.Write(buildSSEEvent(payload)); err != nil {
					return
				}
				_ = w.Flush()
			}
		}

		for event := range ch {
			if _, err := w.Write(event); err != nil {
				return
			}
			if err := w.Flush(); err != nil {
				return
			}
		}
	})
	return nil
}

// handleAPIEvents serves the recent notable-events feed.
// orbiRun starts the Orbi AP poller when a target is configured.
func (s *Server) orbiRun(ctx context.Context) {
	if !s.orbi.Enabled() {
		return
	}
	s.orbi.SetVMClient(s.vmc)
	s.orbi.Run(ctx)
}

// SetShellPoller registers the Orbi shell poller (per-station Wi-Fi stats
// over SSH/telnet). Call before Run; Run starts it when it is configured.
func (s *Server) SetShellPoller(p *orbissn.Poller) { s.shell = p }

// SetTapoPoller registers the smart-plug poller. Call before Run; Run starts
// it and pushes its gauges when it is configured.
func (s *Server) SetTapoPoller(p *tapo.Poller) { s.tapo = p }

// handleAPITapo reports the smart-plug snapshot: relay state, model,
// nickname, Wi-Fi RSSI, on-duration and live power when the model supports it.
func (s *Server) handleAPITapo(c fiber.Ctx) error {
	if s.tapo == nil {
		return c.Status(503).SendString(`{"error":"no plug configured"}`)
	}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(s.tapo.Snapshot())
	return c.Send(b)
}

// orbiPayload is the /api/orbi body: the SOAP snapshot plus the shell
// poller's per-station stats, radio environment and status (all always
// present; radioenv is [] when the shell is down).
type orbiPayload struct {
	orbi.State
	Stations map[string]orbissn.Station `json:"stations"`
	Shell    orbissn.Status             `json:"shell"`
	RadioEnv []orbissn.RadioEnv         `json:"radioenv"`
}

// handleAPIOrbi reports the Orbi AP snapshot: reachability, firmware,
// the attached-device list (band, per-device rates), satellites (with
// online state), and shell-sourced per-station radio stats.
func (s *Server) handleAPIOrbi(c fiber.Ctx) error {
	sh := s.shell.Snapshot()
	st := orbiPayload{State: s.orbi.Snapshot(), Stations: sh.Stations, Shell: sh.Shell, RadioEnv: sh.RadioEnv}
	c.Set("Content-Type", "application/json; charset=utf-8")
	b, _ := json.Marshal(st)
	return c.Send(b)
}

// handleAPIHistoryOrbi serves Wi-Fi history from VictoriaMetrics: with no
// mac param, the per-band client-count series for the Overview sparkline;
// with mac=…, that client's signal-strength history for the drill-down.
func (s *Server) handleAPIHistoryOrbi(c fiber.Ctx) error {
	if s.vmc == nil {
		return c.Status(503).SendString(`{"error":"victoriametrics not configured"}`)
	}
	rng := c.Query("range", "24h")
	spec, ok := vmRanges[rng]
	if !ok {
		return c.Status(400).SendString(`{"error":"range must be one of 1h,6h,24h,7d,30d"}`)
	}
	end := time.Now().Unix()
	var hours int64
	switch rng {
	case "1h":
		hours = 1
	case "6h":
		hours = 6
	case "24h":
		hours = 24
	case "7d":
		hours = 7 * 24
	case "30d":
		hours = 30 * 24
	}
	start := end - hours*3600

	query := `sum by (band) (orbi_wifi_clients)`
	if mac := c.Query("mac"); mac != "" {
		// mac comes from our own UI (upper-case hex + colon), but escape
		// defensively — it lands inside a PromQL string literal.
		safe := strings.Map(func(r rune) rune {
			if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || r == ':' || r == '-' {
				return r
			}
			return -1
		}, strings.ToUpper(mac))
		metric := "orbi_client_signal"
		if c.Query("metric") == "link" {
			metric = "orbi_client_linkspeed"
		}
		query = metric + `{mac="` + safe + `"}`
	}

	series, err := s.vmc.QueryRange(c.Context(), query, start, end, spec.step)
	if err != nil {
		return c.Status(502).SendString(`{"error":"` + err.Error() + `"}`)
	}
	type bandSeries struct {
		Band string    `json:"band"`
		T    []float64 `json:"t"`
		V    []float64 `json:"v"`
	}
	out := make([]bandSeries, 0, len(series))
	for _, srs := range series {
		bs := bandSeries{Band: srs.Labels["band"], T: make([]float64, 0, len(srs.TS)), V: make([]float64, 0, len(srs.Val))}
		for i, ts := range srs.TS {
			bs.T = append(bs.T, float64(ts))
			bs.V = append(bs.V, srs.Val[i])
		}
		out = append(out, bs)
	}
	return c.JSON(out)
}

func (s *Server) handleAPIEvents(c fiber.Ctx) error {
	if s.events == nil {
		return c.JSON([]events.Event{})
	}
	return c.JSON(s.events.List(50))
}

// watchEvents turns poller state transitions into feed events: WAN session
// drops/re-establishment, WARP tunnel loss/recovery, reboots, and each
// bufferbloat probe result. Edges only — the first snapshot after the
// monitor starts never fabricates events.
func (s *Server) watchEvents(ctx context.Context) {
	prevWan := -1 // -1 = unknown (first tick records without events)
	prevWarp := -1
	prevBoot := ""
	probes := newProbeTracker(time.Now().Unix())
	s.configHashes = hashConfigDir() // seed: first tick never fabricates config events
	tick := 0
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tick++

		// WAN session edges.
		if s.wan != nil {
			ws := s.wan.Snapshot()
			if ws.Available {
				up := 0
				if ws.Up {
					up = 1
				}
				if prevWan == 0 && up == 1 {
					s.events.Add("wan", "ok", "WAN session re-established — the PPPoE link is up again")
				} else if prevWan == 1 && up == 0 {
					s.events.Add("wan", "crit", "WAN session dropped — the PPPoE link went down")
				}
				prevWan = up
			}
		}

		// WARP tunnel edges.
		if s.sys != nil && s.sys.Warp != nil {
			w := s.sys.Warp.Snapshot()
			healthy := 0
			if w.Available && !w.Handshake.IsZero() && time.Since(w.Handshake) < 3*time.Minute {
				healthy = 1
			}
			if w.Available && prevWarp != -1 {
				if prevWarp == 1 && healthy == 0 {
					s.events.Add("warp", "warn", "WARP tunnel down — policy-routed clients fall back to the direct WAN line")
				} else if prevWarp == 0 && healthy == 1 {
					s.events.Add("warp", "ok", "WARP tunnel recovered — handshake fresh again")
				}
			}
			if w.Available {
				prevWarp = healthy
			}
		}

		// Reboots (boot_id change).
		if s.sys != nil && s.sys.Disk != nil {
			d := s.sys.Disk.Snapshot()
			if d.BootID != "" {
				if prevBoot == "" {
					prevBoot = d.BootID
				} else if d.BootID != prevBoot {
					s.events.Add("reboot", "warn", "Router reboot noticed — the monitor saw the boot id change")
					prevBoot = d.BootID
				}
			}
		}

		// Router configuration changes (hash of /etc/config/*).
		now := s.configHashes
		s.configHashes = hashConfigDir()
		for f, h := range s.configHashes {
			if prev, ok := now[f]; ok && prev != h {
				s.events.Add("config", "info", "Router configuration changed: /etc/config/"+f+" — settings were edited and services may have restarted")
			}
		}

		// Probe results (checked every minute; the probe itself runs hourly
		// 11:00–20:00). One event per probe run, keyed on the sample time.
		if s.vmc != nil && tick%4 == 0 {
			s.recordProbeEvents(ctx, probes)
		}
	}
}

// hashConfigDir returns a map of /etc/config file name → sha256, so the
// watcher can tell when router configuration was edited.
func hashConfigDir() map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir("/etc/config")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/etc/config", e.Name()))
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(sum[:])
	}
	return out
}
