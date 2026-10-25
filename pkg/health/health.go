// Package health evaluates a small set of high-level health checks from the
// live CAKE stats, the in-memory history and VictoriaMetrics, producing
// plain-language verdicts so the UI can say whether something is wrong
// instead of making the user interpret raw data.
package health

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/clients"
	"github.com/dinjojo/openwrt-view/pkg/history"
	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/sysmon"
	"github.com/dinjojo/openwrt-view/pkg/tapo"
	"github.com/dinjojo/openwrt-view/pkg/types"
	"github.com/dinjojo/openwrt-view/pkg/vm"
	"github.com/dinjojo/openwrt-view/pkg/wan"
)

// State classifies a check result.
type State string

const (
	StateOK      State = "ok"
	StateWarn    State = "warn"
	StateCrit    State = "crit"
	StateUnknown State = "unknown"
)

// Check is one evaluated health signal with a human-readable verdict.
type Check struct {
	Name     string  `json:"name"`
	State    State   `json:"state"`
	Value    string  `json:"value"`     // short raw value, e.g. "+0.5 ms (A+)"
	Detail   string  `json:"detail"`    // plain-language verdict
	NumState float64 `json:"num_state"` // 0=ok, 1=warn, 2=crit, -1=unknown (for sorting)
	// Minor marks a check that never deserves a problem card (e.g. clock
	// drift): it renders as a pill even when warning.
	Minor bool `json:"minor,omitempty"`
}

// gradeState maps a Waveform-style bufferbloat grade to a check state.
func gradeState(grade string) State {
	switch grade {
	case "A+", "A", "B":
		return StateOK
	case "C":
		return StateWarn
	case "D", "E", "F":
		return StateCrit
	}
	return StateUnknown
}

// probeAgeLimit is how long we tolerate a missing/stale bufferbloat probe
// before flagging it (cron runs it hourly between 11:00 and 20:00).
const probeAgeLimit = 90 * time.Minute

// Eval runs all checks. vm may be nil, in which case VM-backed checks report
// unknown rather than failing. wan may be nil (PPPoE check reports unknown).
// sys may be nil (its checks report unknown).
func Eval(ctx context.Context, client *vm.Client, live []types.CakeStats, hist *history.HistoryStore, store *clients.Store, wp *wan.Poller, sys *sysmon.Pollers, op *orbi.Poller, tp *tapo.Poller) []Check {
	checks := []Check{
		evalBufferbloat(ctx, client, live),
		evalWANLatency(ctx, client),
		evalQueue(live),
		evalDrops(live),
		evalQdisc(live),
		evalCPU(ctx, client, live),
		evalWANLink(ctx, client),
		evalPPPoE(pppoeSnap(wp)),
		evalWarp(warpSnap(sys)),
		evalDNS(newDNSProber("127.0.0.1:53")),
		evalClock(clockSnap(sys)),
		evalClients(store),
		evalSystem(ctx, client),
		evalStorage(diskSnap(sys)),
		evalWANRejects(fwSnap(sys)),
		evalConntrack(connSnap(sys)),
		evalAccounting(ctx, client),
	}
	if op.Enabled() {
		checks = append(checks, evalOrbi(op), evalWifiSignal(op))
	}
	if tp != nil {
		checks = append(checks, evalTapo(tp))
	}
	// NumState is derived from State by definition; enforce it here so a
	// literal that forgets (or mistypes) the field can never disagree.
	for i := range checks {
		checks[i].NumState = numState(checks[i].State)
	}
	return checks
}

// warpSnap safely reads the WARP poller state (nil-safe).
func warpSnap(sys *sysmon.Pollers) sysmon.WarpState {
	if sys == nil || sys.Warp == nil {
		return sysmon.WarpState{}
	}
	return sys.Warp.Snapshot()
}

// clockSnap safely reads the clock poller state (nil-safe).
func clockSnap(sys *sysmon.Pollers) sysmon.ClockState {
	if sys == nil || sys.Clock == nil {
		return sysmon.ClockState{}
	}
	return sys.Clock.Snapshot()
}

// diskSnap safely reads the disk poller state (nil-safe).
func diskSnap(sys *sysmon.Pollers) sysmon.DiskState {
	if sys == nil || sys.Disk == nil {
		return sysmon.DiskState{}
	}
	return sys.Disk.Snapshot()
}

// fwSnap safely reads the firewall poller state (nil-safe).
func fwSnap(sys *sysmon.Pollers) sysmon.FWState {
	if sys == nil || sys.FW == nil {
		return sysmon.FWState{}
	}
	return sys.FW.Snapshot()
}

// connSnap safely reads the conntrack poller state (nil-safe).
func connSnap(sys *sysmon.Pollers) sysmon.ConnState {
	if sys == nil || sys.Conn == nil {
		return sysmon.ConnState{}
	}
	return sys.Conn.Snapshot()
}

// evalConntrack watches the connection-tracking table: utilization, real
// exhaustion (drop/early_drop) and benign clash-race noise (insert_failed).
func evalConntrack(st sysmon.ConnState) Check {
	name := "Connection table"
	if st.Max == 0 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "conntrack table size unavailable on this kernel"}
	}
	val := fmt.Sprintf("%d/%d (%.0f%%)", st.Count, st.Max, st.Util)
	switch {
	case st.DropRate > 0.5:
		return Check{Name: name, State: StateCrit, Value: val, NumState: 2,
			Detail: fmt.Sprintf("the connection table is %.0f%% full and the router evicted ~%.0f connections/s in the last 30 s — it ran out of room tracking connections and new ones were refused. Usually a device (or app) opening far too many connections; find the chatterbox or raise nf_conntrack_max", st.Util, st.DropRate)}
	case st.Util >= 90:
		return Check{Name: name, State: StateCrit, Value: val, NumState: 2,
			Detail: "the connection-tracking table is nearly full — when it fills, new connections get refused. Usually one device opening an unusual number of connections"}
	case st.InsertFailedRate > 5:
		return Check{Name: name, State: StateWarn, Value: val, NumState: 1,
			Detail: fmt.Sprintf("the table is %.0f%% full with ~%.0f insert clashes/s — usually harmless NAT races from talkative apps (BitTorrent, gaming), but worth watching for growth", st.Util, st.InsertFailedRate)}
	case st.Util >= 70:
		return Check{Name: name, State: StateWarn, Value: val, NumState: 1,
			Detail: "the connection-tracking table is more than 70% full — fine unless it keeps climbing toward the ceiling"}
	default:
		return Check{Name: name, State: StateOK, Value: val, NumState: 0,
			Detail: "the router is tracking connections comfortably inside its table"}
	}
}

// pppoeSnap safely reads the poller state (nil-safe).
func pppoeSnap(wp *wan.Poller) wan.State {
	if wp == nil {
		return wan.State{}
	}
	return wp.Snapshot()
}

// evalQdisc verifies a CAKE qdisc is actually attached to an interface —
// the most basic question when troubleshooting "is SQM even on?".
func evalQdisc(live []types.CakeStats) Check {
	name := "Traffic shaping"
	if len(live) == 0 {
		return Check{Name: name, State: StateCrit, Value: "no CAKE",
			Detail: "no CAKE shaper is attached to any interface — SQM is not active, so heavy traffic can lag the whole connection", NumState: 2}
	}
	parts := make([]string, 0, len(live))
	for _, cs := range live {
		dir := cs.Direction
		if dir == "" {
			dir = "egress"
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", cs.Interface, dir))
	}
	return Check{Name: name, State: StateOK, Value: fmt.Sprintf("%d qdisc(s)", len(live)),
		Detail: "CAKE shaper attached to " + strings.Join(parts, ", ") + " — upload and download are being smoothed", NumState: 0}
}

// shapedBits parses a tc bandwidth string ("400Mbit", "1Gbit") into bits/s.
func shapedBits(s string) float64 {
	return ShapedBits(s)
}

// tcRateRe matches a tc rate: number, optional SI prefix, unit. tc accepts
// the prefix in either case ("Kbit"/"kbit", "Mbps"/"mbps").
var tcRateRe = regexp.MustCompile(`^([\d.]+)([KkMmGgTt])?(bit|bps)`)

// tcRatePrefix maps a (lower-cased) SI prefix to its multiplier.
var tcRatePrefix = map[string]float64{"": 1, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}

// ShapedBits parses a tc bandwidth string into bits/s (exported for the
// server package, which reports provisioned capacity in the WAN strip).
// In tc(8) units "bit" is bits per second but "bps" is BYTES per second,
// so "bps" rates are multiplied by 8.
func ShapedBits(s string) float64 {
	fields := tcRateRe.FindStringSubmatch(strings.TrimSpace(s))
	if fields == nil {
		return 0
	}
	v, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0
	}
	v *= tcRatePrefix[strings.ToLower(fields[2])]
	if fields[3] == "bps" {
		v *= 8
	}
	return v
}

// evalDrops interprets packet drops and ECN marks with their circumstances.
// A shaper intentionally drops or marks packets to manage congestion, so the
// rate AND the utilisation of that specific interface decide the verdict.
// Each interface is judged separately: the upload shaper (eth0) only sees
// upload traffic, the download shaper (ifb) only download traffic.
func evalDrops(live []types.CakeStats) Check {
	name := "Packet drops"
	if len(live) == 0 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "no CAKE interfaces to check"}
	}

	worstDrops := 0.0
	worstUtil := 0.0
	worstIface := ""
	var worstDir string
	totalMarks := 0.0
	for _, cs := range live {
		shaped := shapedBits(cs.Bandwidth)
		util := 0.0
		if shaped > 0 {
			util = cs.TxBytesPerS * 8 / shaped * 100
		}
		totalMarks += cs.MarksPerS
		if cs.DropsPerS > worstDrops || worstIface == "" {
			worstDrops = cs.DropsPerS
			worstUtil = util
			worstIface = cs.Interface
			worstDir = cs.Direction
		}
	}

	dirWord := "upload"
	if worstDir == "ingress" {
		dirWord = "download"
	}

	// ECN marks without drops: CAKE signalling senders to slow down instead
	// of dropping — congestion management working exactly as designed.
	if totalMarks >= 0.5 && worstDrops < 0.5 {
		return Check{Name: name, State: StateOK, Value: fmt.Sprintf("%.1f/s marked", totalMarks), NumState: 0,
			Detail: "the shaper is politely asking senders to slow down (ECN marks) instead of dropping — congestion managed as designed"}
	}

	state := StateOK
	var detail string
	val := fmt.Sprintf("%.2f/s", worstDrops)
	switch {
	case worstDrops < 0.5:
		detail = "nothing is being dropped or marked — the link is comfortable"
		state = StateOK
	case worstUtil >= 95:
		// At the shaped ceiling, dropping IS the AQM holding latency back —
		// expected during a speed test or any full-rate transfer. Not a
		// problem, so no warning card: the user chose to saturate the line.
		state = StateOK
		detail = fmt.Sprintf("the %s line is running flat out (%.0f%% of the shaper) and Cake is dropping ~%.0f packets/s on %s to hold latency down — that is the shaper working exactly as designed during a speed test or full-rate transfer, and it stops the moment the line frees up. Nothing to fix. If you weren't running anything heavy, something on your network is using the whole line",
			dirWord, worstUtil, worstDrops, worstIface)
		val = fmt.Sprintf("%.1f/s on %s", worstDrops, worstIface)
	case worstUtil >= 70:
		state = StateWarn
		detail = fmt.Sprintf("%s link is nearly full (%.0f%% used) and %.1f packets/s are dropped on %s — approaching the shaping ceiling; if this persists at this level for hours, the shaping rate may deserve a second look",
			dirWord, worstUtil, worstDrops, worstIface)
		val = fmt.Sprintf("%.1f/s on %s", worstDrops, worstIface)
	default:
		state = StateWarn
		detail = fmt.Sprintf("%.1f packets/s dropped on %s while the %s link is only %.0f%% used — not saturation; check MTU/overhead settings or a bursty device",
			worstDrops, worstIface, dirWord, worstUtil)
		val = fmt.Sprintf("%.1f/s on %s", worstDrops, worstIface)
	}
	return Check{Name: name, State: state, Value: val, Detail: detail, NumState: numState(state)}
}

// evalCPU watches CPU utilisation while SQM is active: a saturating CPU under
// load means the router itself, not the link, is the bottleneck.
func evalCPU(ctx context.Context, client *vm.Client, live []types.CakeStats) Check {
	name := "Router CPU"
	if client == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "VictoriaMetrics not configured"}
	}
	pts, err := client.Query(ctx, `100 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100`)
	if err != nil || len(pts) == 0 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "no CPU data — is node-exporter running?"}
	}
	cpu := pts[0].Val

	// Traffic right now vs the configured shaper rates — use the busier
	// direction, since upload and download shape independently.
	traffic := 0.0
	for _, cs := range live {
		shaped := shapedBits(cs.Bandwidth)
		if shaped > 0 {
			traffic = math.Max(traffic, cs.TxBytesPerS*8/shaped*100)
		}
	}

	state := StateOK
	var detail string
	switch {
	case cpu >= 90 && traffic >= 40:
		state = StateCrit
		detail = fmt.Sprintf("CPU at %.0f%% while shaping %.0f%% of the configured rate — router CPU is the bottleneck, not the link", cpu, traffic)
	case cpu >= 75 && traffic >= 40:
		state = StateWarn
		detail = fmt.Sprintf("CPU at %.0f%% while shaping %.0f%% of the configured rate — watch for throughput ceilings", cpu, traffic)
	case cpu >= 75:
		detail = fmt.Sprintf("CPU at %.0f%% with little SQM traffic — load is from something else", cpu)
	default:
		detail = fmt.Sprintf("CPU at %.0f%% — plenty of headroom for shaping", cpu)
	}
	return Check{Name: name, State: state, Value: fmt.Sprintf("%.0f%%", cpu), Detail: detail, NumState: numState(state)}
}

// evalClients reports per-client tracking status from the nlbwmon poller.
func evalClients(store *clients.Store) Check {
	name := "Device tracking"
	if store == nil || !store.Available() {
		return Check{Name: name, State: StateWarn, Value: "off", NumState: 1,
			Detail: "per-client accounting unavailable — is nlbwmon installed and running?"}
	}
	snap := store.Snapshot()
	online := 0
	for _, c := range snap {
		if c.Online {
			online++
		}
	}
	val := fmt.Sprintf("%d online", online)
	detail := fmt.Sprintf("%d devices tracked by nlbwmon (per-client accounting active)", len(snap))
	if online == 0 && len(snap) > 0 {
		return Check{Name: name, State: StateWarn, Value: "0 online", NumState: 1,
			Detail: fmt.Sprintf("%d devices tracked but none reachable — check LAN/WiFi", len(snap))}
	}
	return Check{Name: name, State: StateOK, Value: val, Detail: detail, NumState: 0}
}

// latest returns the most recent value (and timestamp) of an instant query.
func latest(pts []vm.Point) (float64, time.Time, bool) {
	var best vm.Point
	found := false
	for _, p := range pts {
		if !found || p.TS > best.TS {
			best = p
			found = true
		}
	}
	if !found {
		return 0, time.Time{}, false
	}
	return best.Val, time.Unix(best.TS, 0), true
}

// latestFromSeries returns the most recent value across all series.
func latestFromSeries(series []vm.Series) (float64, time.Time, bool) {
	var bestTS int64
	bestVal := 0.0
	found := false
	for _, s := range series {
		for i, ts := range s.TS {
			if !found || ts > bestTS {
				bestTS = ts
				bestVal = s.Val[i]
				found = true
			}
		}
	}
	if !found {
		return 0, time.Time{}, false
	}
	return bestVal, time.Unix(bestTS, 0), true
}

// gradeFromSeries extracts the grade label from the most recent
// probe_bloat_grade sample across all series.
func gradeFromSeries(series []vm.Series) string {
	var bestTS int64
	bestGrade := ""
	found := false
	for _, s := range series {
		for i, ts := range s.TS {
			if s.Val[i] <= 0 {
				continue
			}
			if !found || ts > bestTS {
				bestTS = ts
				bestGrade = s.Labels["grade"]
				found = true
			}
		}
	}
	if !found {
		return ""
	}
	return bestGrade
}

func evalBufferbloat(ctx context.Context, client *vm.Client, live []types.CakeStats) Check {
	name := "Latency under load"
	if client == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "VictoriaMetrics not configured"}
	}

	// Find the newest probe result with its real sample time (raw samples,
	// not step-aligned range points) over probeLookback, so last night's
	// run is still visible in the morning; then judge it against the cron
	// schedule (probe_schedule.go).
	now := time.Now().In(schedLoc())
	end := now.Unix()
	down, err := client.QueryRaw(ctx, `probe_bloat_ms{direction="down"}`, end-int64(probeLookback/time.Second), end)
	if err != nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "probe query failed: " + err.Error()}
	}
	dBloat, dTS, ok := latestFromSeries(down)
	if f := classifyProbe(now, dTS, ok); f != probeFresh {
		grade := ""
		if ok && f == probeLast {
			if gs, gerr := client.QueryRaw(ctx, `probe_bloat_grade{direction="down"}`, dTS.Unix()-1, dTS.Unix()+1); gerr == nil {
				grade = gradeFromSeries(gs)
			}
		}
		return probeOffScheduleCheck(name, f, now, dTS, dBloat, grade)
	}

	// Fresh result: the other probe series over the last two hours (the
	// probe pushes hourly, so instant queries would miss them).
	start := end - 7200
	up, _ := client.QueryRange(ctx, `probe_bloat_ms{direction="up"}`, start, end, "60s")
	downGrade, _ := client.QueryRange(ctx, `probe_bloat_grade{direction="down"}`, start, end, "60s")
	upGrade, _ := client.QueryRange(ctx, `probe_bloat_grade{direction="up"}`, start, end, "60s")
	speeds, _ := client.QueryRange(ctx, `probe_burst_speed_bps{direction="down"}`, start, end, "60s")

	uBloat, _, uOK := latestFromSeries(up)
	dGrade := gradeFromSeries(downGrade)
	uGrade := gradeFromSeries(upGrade)
	dSpeed, _, sOK := latestFromSeries(speeds)

	dState := gradeState(dGrade)
	uState := StateUnknown
	if uOK {
		uState = gradeState(uGrade)
	}
	worst := dState
	if uState == StateCrit || (uState == StateWarn && dState == StateOK) {
		worst = uState
	}

	// Clamp tiny negative bloat (baseline jitter) so the verdict reads "+0.0 ms".
	if dBloat < 0 {
		dBloat = 0
	}
	if uBloat < 0 {
		uBloat = 0
	}

	detail := fmt.Sprintf("bufferbloat: latency rises %s under download, %s under upload",
		fmtBloat(dBloat), fmtBloatOrNA(uBloat, uOK))
	val := fmtBloat(dBloat)
	if dGrade != "" {
		val += " (" + dGrade + ")"
	}
	// The probe grade is only trustworthy if the burst actually loaded the
	// line. A short burst that never reaches the shaper rate flatters the
	// grade, so say how close the probe got and hedge when it fell short.
	// probe_burst_speed_bps is bits/s; shapedDown is bits/s too.
	shapedDown := 0.0
	for _, cs := range live {
		if cs.Direction == "ingress" {
			shapedDown += shapedBits(cs.Bandwidth)
		}
	}
	if sOK && dSpeed > 0 {
		detail += fmt.Sprintf(" · probe reached %s down", humanBits(dSpeed/8))
		if shapedDown > 0 {
			pct := dSpeed / shapedDown * 100
			detail += fmt.Sprintf(" (%.0f%% of the %.0f Mbit/s shaper)", pct, shapedDown/1e6)
			if pct < 90 {
				detail += " — line not fully loaded, so the grade is a best case"
			}
		}
	} else if shapedDown > 0 {
		detail += " · probe could not measure download speed — grade unverified"
	}
	return Check{Name: name, State: worst, Value: val, Detail: detail, NumState: numState(worst)}
}

func evalWANLatency(ctx context.Context, client *vm.Client) Check {
	name := "Internet response time"
	if client == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "VictoriaMetrics not configured"}
	}
	rtts, err := client.Query(ctx, `collectd_ping`)
	if err != nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "ping query failed: " + err.Error()}
	}
	losses, _ := client.Query(ctx, `collectd_ping_ping_droprate`)

	if len(rtts) == 0 {
		return Check{Name: name, State: StateWarn, Value: "—", NumState: 1, Detail: "no WAN latency data — is collectd ping plugin running?"}
	}

	worstRTT := 0.0
	worstHost := ""
	var sumRTT float64
	for _, p := range rtts {
		sumRTT += p.Val
		if p.Val > worstRTT {
			worstRTT = p.Val
			worstHost = p.Labels["ping"]
		}
	}
	avgRTT := sumRTT / float64(len(rtts))

	maxLoss := 0.0
	for _, p := range losses {
		if p.Val > maxLoss {
			maxLoss = p.Val
		}
	}

	state := StateOK
	switch {
	case worstRTT >= 100 || maxLoss >= 0.05:
		state = StateCrit
	case worstRTT >= 50 || maxLoss >= 0.01:
		state = StateWarn
	}

	// Baseline: compare this hour against the same hour a week ago so the
	// verdict reflects what is normal for this network, not a fixed number.
	basePts, _ := client.Query(ctx, `avg_over_time(collectd_ping[1h] offset 1w)`)
	baseline := 0.0
	if len(basePts) > 0 {
		sum := 0.0
		for _, p := range basePts {
			sum += p.Val
		}
		baseline = sum / float64(len(basePts))
	}
	if baseline > 0 && state == StateOK {
		if avgRTT > math.Max(3*baseline, baseline+15) {
			state = StateWarn
		}
	}

	val := fmt.Sprintf("%.1f ms avg", avgRTT)
	detail := fmt.Sprintf("%.1f ms to %s, %.1f%% loss", worstRTT, worstHost, maxLoss*100)
	switch {
	case baseline > 0 && avgRTT > math.Max(3*baseline, baseline+15):
		detail = fmt.Sprintf("unusually slow for this hour: %.1f ms now vs a typical %.1f ms a week ago — something between the router and the internet is busier than usual", avgRTT, baseline)
	case baseline > 0:
		detail += fmt.Sprintf(" — same as usual for this hour (typically %.1f ms)", baseline)
	}
	return Check{Name: name, State: state, Value: val, Detail: detail, NumState: numState(state)}
}

// evalWANLink checks the WAN interface is visible and its hardware counters
// are clean. Errors here usually mean a physical/link problem (cable, modem,
// ISP signal) rather than congestion — congestion lives in the CAKE checks.
func evalWANLink(ctx context.Context, client *vm.Client) Check {
	name := "Internet line"
	if client == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "VictoriaMetrics not configured"}
	}
	const wanDev = `device=~"(wan|pppoe|eth0).*"`
	// Presence: is a WAN-facing interface reporting at all?
	info, err := client.Query(ctx, `count(node_network_info{`+wanDev+`}) by (device)`)
	if err != nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "WAN interface query failed: " + err.Error()}
	}
	if len(info) == 0 {
		return Check{Name: name, State: StateCrit, Value: "no WAN",
			Detail: "no WAN interface is reporting — the PPPoE link may be down or the interface name changed", NumState: 2}
	}
	devs := make([]string, 0, len(info))
	for _, p := range info {
		devs = append(devs, p.Labels["device"])
	}
	devList := strings.Join(devs, ", ")

	// Physical errors (errs/carrier) mean a link problem; port drops are
	// usually the router momentarily not keeping up (e.g. traffic bursts).
	errsQ := `sum(increase(node_network_receive_errs_total{` + wanDev + `}[1h]))
		+ sum(increase(node_network_transmit_errs_total{` + wanDev + `}[1h]))
		+ sum(increase(node_network_transmit_carrier_total{` + wanDev + `}[1h]))`
	dropsQ := `sum(increase(node_network_receive_drop_total{` + wanDev + `}[1h]))
		+ sum(increase(node_network_transmit_drop_total{` + wanDev + `}[1h]))`

	errsPts, err := client.Query(ctx, errsQ)
	dropPts, derr := client.Query(ctx, dropsQ)
	if (err != nil || len(errsPts) == 0) || (derr != nil || len(dropPts) == 0) {
		return Check{Name: name, State: StateOK, Value: devList, NumState: 0,
			Detail: "WAN interface " + devList + " is up (no error counters available to inspect)"}
	}
	physErrs, portDrops := 0.0, 0.0
	for _, p := range errsPts {
		physErrs += p.Val
	}
	for _, p := range dropPts {
		portDrops += p.Val
	}
	if physErrs >= 0.01 {
		return Check{Name: name, State: StateWarn, Value: fmt.Sprintf("%.0f/hr", physErrs+portDrops),
			Detail: fmt.Sprintf("%.0f link errors in the last hour on %s — usually a cable, modem or ISP signal problem, not a congestion problem", physErrs, devList), NumState: 1}
	}

	// Port drops need context: many ports discard a small constant trickle of
	// junk (modem-originated frames the driver filters) around the clock.
	// Judge the last hour against the 24h baseline instead of the raw count.
	drops24, err := client.QueryRange(ctx, dropsQ, time.Now().Add(-24*time.Hour).Unix(), time.Now().Unix(), "1h")
	if err != nil || len(drops24) == 0 {
		// No baseline available — fall back to reporting the absolute count.
		if portDrops >= 0.01 {
			return Check{Name: name, State: StateWarn, Value: fmt.Sprintf("%.0f drops/hr", portDrops),
				Detail: fmt.Sprintf("%.0f packets were dropped at the port in the last hour on %s — the router momentarily couldn't keep up, typically during heavy bursts; no physical errors though", portDrops, devList), NumState: 1}
		}
		return Check{Name: name, State: StateOK, Value: devList, NumState: 0,
			Detail: "WAN interface " + devList + " is up and its link counters are clean — no cable, modem or signal errors in the last hour"}
	}
	baseline := median(drops24[0].Val)
	switch {
	case portDrops > baseline*1.5+240:
		return Check{Name: name, State: StateWarn, Value: fmt.Sprintf("%.0f drops/hr", portDrops),
			Detail: fmt.Sprintf("port drops are spiking: %.0f in the last hour vs your usual %.0f/hr on %s. Bursts like this mean the port momentarily couldn't take the load (the bufferbloat probe causes some of this by design); no physical errors though.", portDrops, baseline, devList), NumState: 1}
	case baseline > 0:
		return Check{Name: name, State: StateOK, Value: devList, NumState: 0,
			Detail: fmt.Sprintf("WAN interface %s is up, link counters clean. The port discards its usual background trickle (~%.0f/hr) — filtered modem chatter the driver never passes up, not real traffic; zero CRC, overrun or ring-miss errors confirm nothing is actually being lost under load.", devList, baseline)}
	}
	return Check{Name: name, State: StateOK, Value: devList, NumState: 0,
		Detail: "WAN interface " + devList + " is up and its link counters are clean — no cable, modem or signal errors in the last hour"}
}

// median returns the median value of a float slice.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	return sorted[len(sorted)/2]
}

// evalQueue judges the live CAKE queue: peak delay vs the configured target
// (5 ms default) and any backlog.
func evalQueue(live []types.CakeStats) Check {
	name := "Traffic queue"
	if len(live) == 0 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "no CAKE interfaces"}
	}
	maxPk := 0.0
	iface := ""
	for _, cs := range live {
		if cs.MaxPkDelayMs > maxPk {
			maxPk = cs.MaxPkDelayMs
			iface = cs.Interface
		}
	}
	state := StateOK
	switch {
	case maxPk >= 30:
		state = StateCrit
	case maxPk >= 5:
		state = StateWarn
	}
	val := fmt.Sprintf("peak %.2f ms", maxPk)
	var detail string
	if iface == "" {
		// Every interface reports a zero peak delay, so none was picked
		// as the worst; name them all rather than leaving a blank.
		names := make([]string, 0, len(live))
		for _, cs := range live {
			names = append(names, cs.Interface)
		}
		detail = fmt.Sprintf("packets are not waiting in the queue at all on %s — well under the 5 ms target, no bufferbloat", strings.Join(names, ", "))
	} else {
		detail = fmt.Sprintf("packets wait at most %.2f ms in the queue on %s — well under the 5 ms target, no bufferbloat", maxPk, iface)
	}
	if state == StateWarn {
		detail = fmt.Sprintf("packets wait up to %.2f ms in the queue on %s — above the 5 ms target, so video calls may feel laggy while the line is busy", maxPk, iface)
	} else if state == StateCrit {
		detail = fmt.Sprintf("packets wait up to %.2f ms in the queue on %s — far above target; the shaper is not holding latency down, check SQM settings", maxPk, iface)
	}
	return Check{Name: name, State: state, Value: val, Detail: detail, NumState: numState(state)}
}

// evalSystem judges overall router health: temperature, load and memory.
func evalSystem(ctx context.Context, client *vm.Client) Check {
	name := "Temperature & memory"
	if client == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "VictoriaMetrics not configured"}
	}
	temps, err := client.Query(ctx, `max(collectd_thermal_temperature)`)
	if err != nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "thermal query failed: " + err.Error()}
	}
	loadPts, _ := client.Query(ctx, `node_load1`)
	memPts, _ := client.Query(ctx, `100 * node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`)

	maxTemp := 0.0
	if t, _, ok := latest(temps); ok {
		maxTemp = t
	}
	load := 0.0
	if l, _, ok := latest(loadPts); ok {
		load = l
	}
	memPct := 100.0
	if m, _, ok := latest(memPts); ok {
		memPct = m
	}

	state := StateOK
	switch {
	case maxTemp >= 85 || memPct < 10:
		state = StateCrit
	case maxTemp >= 75 || memPct < 20:
		state = StateWarn
	}
	val := fmt.Sprintf("%.0f°C", maxTemp)
	detail := fmt.Sprintf("SoC %.0f°C, load %.2f, %.0f%% RAM free", maxTemp, load, memPct)
	if state != StateOK {
		detail += " — check cooling / memory pressure"
	}
	return Check{Name: name, State: state, Value: val, Detail: detail, NumState: numState(state)}
}

// --- small formatting helpers -------------------------------------------

func fmtBloat(ms float64) string {
	return fmt.Sprintf("%+.1f ms", ms)
}

func fmtBloatOrNA(ms float64, ok bool) string {
	if !ok || math.IsNaN(ms) {
		return "n/a"
	}
	return fmtBloat(ms)
}

// humanBits converts bytes/s to a human Mbps string.
func humanBits(bps float64) string {
	mbits := bps * 8 / 1e6
	if mbits >= 100 {
		return fmt.Sprintf("%.0f Mbps", mbits)
	}
	return fmt.Sprintf("%.1f Mbps", mbits)
}

func numState(s State) float64 {
	switch s {
	case StateOK:
		return 0
	case StateWarn:
		return 1
	case StateCrit:
		return 2
	}
	return -1
}
