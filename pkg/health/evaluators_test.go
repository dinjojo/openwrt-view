package health

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/clients"
	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/sysmon"
	"github.com/dinjojo/openwrt-view/pkg/types"
	"github.com/dinjojo/openwrt-view/pkg/vm"
	"github.com/dinjojo/openwrt-view/pkg/wan"
)

// want describes the expected key properties of a Check.
type want struct {
	state    State
	value    string   // exact Value, "" = only require non-empty
	contains []string // substrings the Detail must contain
	absent   []string // substrings the Detail must NOT contain
}

// checkCommon asserts the properties every Check must have: the expected
// name and state, a non-empty value and detail, and a NumState consistent
// with the State (-1/0/1/2 for unknown/ok/warn/crit).
func checkCommon(t *testing.T, c Check, name string, w want) {
	t.Helper()
	if c.Name != name {
		t.Errorf("Name = %q, want %q", c.Name, name)
	}
	if c.State != w.state {
		t.Errorf("State = %q, want %q (detail: %s)", c.State, w.state, c.Detail)
	}
	if c.Value == "" {
		t.Error("Value is empty")
	}
	if w.value != "" && c.Value != w.value {
		t.Errorf("Value = %q, want %q", c.Value, w.value)
	}
	if strings.TrimSpace(c.Detail) == "" {
		t.Error("Detail is empty")
	}
	if c.NumState != numState(c.State) {
		t.Errorf("NumState = %v, inconsistent with State %q", c.NumState, c.State)
	}
	for _, s := range w.contains {
		if !strings.Contains(c.Detail, s) {
			t.Errorf("Detail missing %q: %s", s, c.Detail)
		}
	}
	for _, s := range w.absent {
		if strings.Contains(c.Detail, s) {
			t.Errorf("Detail must not contain %q: %s", s, c.Detail)
		}
	}
}

func TestEvalConntrack(t *testing.T) {
	cases := []struct {
		name string
		in   sysmon.ConnState
		w    want
	}{
		{"table size unavailable", sysmon.ConnState{}, want{state: StateUnknown, value: "—"}},
		{"comfortable", sysmon.ConnState{Count: 100, Max: 1000, Util: 10},
			want{state: StateOK, value: "100/1000 (10%)", contains: []string{"comfortably"}}},
		{"above 70%", sysmon.ConnState{Count: 750, Max: 1000, Util: 75},
			want{state: StateWarn, contains: []string{"70%"}}},
		{"insert clashes only", sysmon.ConnState{Count: 200, Max: 1000, Util: 20, InsertFailedRate: 12},
			want{state: StateWarn, contains: []string{"12 insert clashes/s", "harmless"}}},
		{"clash noise below threshold", sysmon.ConnState{Count: 200, Max: 1000, Util: 20, InsertFailedRate: 4},
			want{state: StateOK}},
		{"nearly full", sysmon.ConnState{Count: 950, Max: 1000, Util: 95},
			want{state: StateCrit, contains: []string{"nearly full"}}},
		{"real exhaustion", sysmon.ConnState{Count: 1000, Max: 1000, Util: 100, DropRate: 3, InsertFailedRate: 50},
			want{state: StateCrit, contains: []string{"100% full", "evicted ~3"}}},
		{"tiny drop rate ignored", sysmon.ConnState{Count: 10, Max: 1000, Util: 1, DropRate: 0.2},
			want{state: StateOK}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalConntrack(c.in)
			checkCommon(t, got, "Connection table", c.w)
			if again := evalConntrack(c.in); again != got {
				t.Errorf("not stable for stable input:\n%+v\n%+v", got, again)
			}
		})
	}
}

func TestEvalQdisc(t *testing.T) {
	cases := []struct {
		name string
		in   []types.CakeStats
		w    want
	}{
		{"no cake", nil, want{state: StateCrit, value: "no CAKE", contains: []string{"not active"}}},
		{"both directions", []types.CakeStats{{Interface: "eth0", Direction: "egress"}, {Interface: "ifb4eth0", Direction: "ingress"}},
			want{state: StateOK, value: "2 qdisc(s)", contains: []string{"eth0 (egress)", "ifb4eth0 (ingress)"}}},
		{"missing direction defaults to egress", []types.CakeStats{{Interface: "wan"}},
			want{state: StateOK, value: "1 qdisc(s)", contains: []string{"wan (egress)"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkCommon(t, evalQdisc(c.in), "Traffic shaping", c.w)
		})
	}
}

func TestShapedBits(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"400Mbit", 400e6},
		{"1Gbit", 1e9},
		{"1.5Gbit", 1.5e9},
		{"500Kbit", 500e3},
		{"2Tbit", 2e12},
		{"100bit", 100},
		// tc "bps" is BYTES per second: 8 bits each.
		{"100bps", 800},
		{"5Mbps", 40e6},
		{"51875Kbps", 415e6},
		{"1Gbps", 8e9},
		{"500kbit", 500e3},
		{"5mbps", 40e6},
		{"  40Mbit\n", 40e6},
		{"unlimited", 0},
		{"", 0},
		{"Mbit", 0},
	}
	for _, c := range cases {
		if got := ShapedBits(c.in); got != c.want {
			t.Errorf("ShapedBits(%q) = %v, want %v", c.in, got, c.want)
		}
		if shapedBits(c.in) != ShapedBits(c.in) {
			t.Errorf("shapedBits and ShapedBits disagree for %q", c.in)
		}
	}
}

// 40 Mbit/s shaper = 5e6 bytes/s at 100%.
func iface(name, dir string, txBytes, drops, marks float64) types.CakeStats {
	return types.CakeStats{Interface: name, Direction: dir, Bandwidth: "40Mbit",
		TxBytesPerS: txBytes, DropsPerS: drops, MarksPerS: marks}
}

func TestEvalDrops(t *testing.T) {
	cases := []struct {
		name string
		in   []types.CakeStats
		w    want
	}{
		{"no interfaces", nil, want{state: StateUnknown, value: "—"}},
		{"idle", []types.CakeStats{iface("eth0", "egress", 1e5, 0, 0)},
			want{state: StateOK, value: "0.00/s", contains: []string{"nothing is being dropped"}}},
		{"ECN marks instead of drops", []types.CakeStats{iface("eth0", "egress", 4e6, 0.1, 0.4), iface("ifb4eth0", "ingress", 4e6, 0, 0.6)},
			want{state: StateOK, value: "1.0/s marked", contains: []string{"ECN"}}},
		{"saturated line dropping is by design", []types.CakeStats{iface("eth0", "egress", 4.9e6, 5, 0)},
			want{state: StateOK, value: "5.0/s on eth0", contains: []string{"upload", "98%", "flat out"}}},
		{"nearly full", []types.CakeStats{iface("ifb4eth0", "ingress", 4e6, 2, 0)},
			want{state: StateWarn, value: "2.0/s on ifb4eth0", contains: []string{"download link is nearly full (80% used)"}}},
		{"drops on idle link", []types.CakeStats{iface("eth0", "egress", 5e5, 3, 0)},
			want{state: StateWarn, contains: []string{"only 10% used", "MTU/overhead"}}},
		{"worst interface wins", []types.CakeStats{iface("eth0", "egress", 1e5, 0.6, 0), iface("ifb4eth0", "ingress", 1e5, 9, 0)},
			want{state: StateWarn, value: "9.0/s on ifb4eth0", contains: []string{"download"}}},
		{"unparseable bandwidth treated as 0% util", []types.CakeStats{{Interface: "eth0", Bandwidth: "unlimited", TxBytesPerS: 9e9, DropsPerS: 1}},
			want{state: StateWarn, contains: []string{"only 0% used"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalDrops(c.in)
			checkCommon(t, got, "Packet drops", c.w)
			if again := evalDrops(c.in); again != got {
				t.Error("not stable for stable input")
			}
		})
	}
}

func TestEvalQueue(t *testing.T) {
	q := func(name string, pk float64) types.CakeStats {
		return types.CakeStats{Interface: name, MaxPkDelayMs: pk}
	}
	cases := []struct {
		name string
		in   []types.CakeStats
		w    want
	}{
		{"no interfaces", nil, want{state: StateUnknown, value: "—"}},
		{"healthy", []types.CakeStats{q("eth0", 1.5), q("ifb4eth0", 0.5)},
			want{state: StateOK, value: "peak 1.50 ms", contains: []string{"on eth0", "well under"}}},
		{"above target", []types.CakeStats{q("eth0", 1), q("ifb4eth0", 12)},
			want{state: StateWarn, value: "peak 12.00 ms", contains: []string{"on ifb4eth0", "above the 5 ms target"}}},
		{"boundary 5 ms warns", []types.CakeStats{q("eth0", 5)}, want{state: StateWarn}},
		{"far above", []types.CakeStats{q("eth0", 45)},
			want{state: StateCrit, contains: []string{"far above target"}}},
		{"boundary 30 ms is crit", []types.CakeStats{q("eth0", 30)}, want{state: StateCrit}},
		{"all delays zero names the interfaces", []types.CakeStats{q("eth0", 0), q("ifb4eth0", 0)},
			want{state: StateOK, value: "peak 0.00 ms", contains: []string{"on eth0, ifb4eth0", "well under"}, absent: []string{"on  "}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkCommon(t, evalQueue(c.in), "Traffic queue", c.w)
		})
	}
}

func TestEvalPPPoE(t *testing.T) {
	cases := []struct {
		name string
		in   wan.State
		w    want
	}{
		{"ubus unavailable", wan.State{}, want{state: StateUnknown, value: "—"}},
		{"session down", wan.State{Available: true}, want{state: StateCrit, value: "down", contains: []string{"DOWN"}}},
		{"recent flap", wan.State{Available: true, Up: true, UptimeSec: 125},
			want{state: StateWarn, value: "up 2m", contains: []string{"2m5s ago", "dropped recently"}}},
		{"stable with address", wan.State{Available: true, Up: true, UptimeSec: 3*86400 + 7200, Addr: "100.64.1.2"},
			want{state: StateOK, value: "up 3d 2h", contains: []string{"established for 3d 2h", "100.64.1.2"}}},
		{"stable without address", wan.State{Available: true, Up: true, UptimeSec: 3600},
			want{state: StateOK, value: "up 1h 0m", absent: []string{"WAN address"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkCommon(t, evalPPPoE(c.in), "ISP session", c.w)
		})
	}
}

func TestHumanUp(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{59 * time.Second, "59s"},
		{time.Minute, "1m"},
		{59*time.Minute + 59*time.Second, "59m"},
		{5*time.Hour + 12*time.Minute, "5h 12m"},
		{4*24*time.Hour + 21*time.Hour, "4d 21h"},
		{(3*30 + 12) * 24 * time.Hour, "3mo 12d"},
		{(365 + 65) * 24 * time.Hour, "1y 2mo"},
	}
	for _, c := range cases {
		if got := humanUp(c.d); got != c.want {
			t.Errorf("humanUp(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestEvalWarp(t *testing.T) {
	ago := func(d time.Duration) time.Time { return time.Now().Add(-d) }
	cases := []struct {
		name string
		in   sysmon.WarpState
		w    want
	}{
		{"interface gone", sysmon.WarpState{}, want{state: StateWarn, value: "fallback", contains: []string{"falling back"}}},
		{"never handshaked", sysmon.WarpState{Available: true, PeerCount: 1},
			want{state: StateWarn, value: "no handshake", contains: []string{"never completed a handshake"}}},
		{"healthy idle", sysmon.WarpState{Available: true, PeerCount: 1, Handshake: ago(30 * time.Second), RxPerS: 100},
			want{state: StateOK, value: "via WARP", contains: []string{"healthy", "no traffic flowing"}}},
		{"healthy with traffic", sysmon.WarpState{Available: true, PeerCount: 1, Handshake: ago(time.Minute), RxPerS: 2 * 1024 * 1024},
			want{state: StateOK, value: "via WARP", contains: []string{"~2.0 MiB/s flowing in"}}},
		{"stalled", sysmon.WarpState{Available: true, PeerCount: 1, Handshake: ago(5 * time.Minute)},
			want{state: StateWarn, value: "quiet 5m", contains: []string{"stalled"}}},
		{"down", sysmon.WarpState{Available: true, PeerCount: 1, Handshake: ago(time.Hour)},
			want{state: StateWarn, value: "fallback", contains: []string{"down (no handshake for 1.0h)"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalWarp(c.in)
			checkCommon(t, got, "Exit path (WARP)", c.w)
			// A dead tunnel falls back to WAN — never critical by design.
			if got.State == StateCrit {
				t.Error("WARP must never be critical")
			}
		})
	}
}

func TestEvalClock(t *testing.T) {
	cases := []struct {
		name string
		in   sysmon.ClockState
		w    want
	}{
		{"no reference", sysmon.ClockState{}, want{state: StateUnknown, value: "—"}},
		{"sntp in sync", sysmon.ClockState{Available: true, OffsetMs: 42, Server: "pool.ntp.org:123", Source: "sntp"},
			want{state: StateOK, value: "+42 ms", contains: []string{"within 42 ms", "pool.ntp.org:123", "sntp"}}},
		{"sntp negative offset warn", sysmon.ClockState{Available: true, OffsetMs: -150, Source: "sntp"},
			want{state: StateWarn, value: "-150 ms", contains: []string{"drifted 150 ms"}}},
		{"sntp crit", sysmon.ClockState{Available: true, OffsetMs: 2500, Source: "sntp"},
			want{state: StateCrit, value: "+2.5 s", contains: []string{"2.5 seconds"}}},
		{"http loose ok", sysmon.ClockState{Available: true, OffsetMs: 3000, Source: "http"},
			want{state: StateOK, value: "+3000 ms"}},
		{"http warn", sysmon.ClockState{Available: true, OffsetMs: -10000, Source: "http"},
			want{state: StateWarn}},
		{"http crit", sysmon.ClockState{Available: true, OffsetMs: 120000, Source: "http"},
			want{state: StateCrit, value: "+120.0 s"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalClock(c.in)
			checkCommon(t, got, "Clock sync", c.w)
			if !got.Minor {
				t.Error("clock check must always be Minor")
			}
		})
	}
}

func TestEvalStorage(t *testing.T) {
	healthy := sysmon.DiskState{Available: true, PercentUsed: 3, AvailableSpare: 100, SpareKnown: true, TempC: 41}
	mod := func(f func(*sysmon.DiskState)) sysmon.DiskState { s := healthy; f(&s); return s }
	cases := []struct {
		name string
		in   sysmon.DiskState
		w    want
	}{
		{"smart unavailable", sysmon.DiskState{}, want{state: StateUnknown, value: "—"}},
		{"healthy", healthy, want{state: StateOK, contains: []string{"3% write endurance", "41°C"}, absent: []string{"rebooted", "unclean"}}},
		{"unsafe shutdowns noted", mod(func(s *sysmon.DiskState) { s.UnsafeShutdowns = 7 }),
			want{state: StateOK, contains: []string{"7 unclean shutdowns"}}},
		{"recent reboot noted", mod(func(s *sysmon.DiskState) { s.RebootSpotted = true; s.LastReboot = time.Now().Add(-2 * time.Hour) }),
			want{state: StateOK, contains: []string{"rebooted 2.0h ago"}}},
		{"reboot flag without time ignored", mod(func(s *sysmon.DiskState) { s.RebootSpotted = true }),
			want{state: StateOK, absent: []string{"rebooted"}}},
		{"critical warning", mod(func(s *sysmon.DiskState) { s.CriticalWarning = 4 }),
			want{state: StateCrit, contains: []string{"critical_warning=4"}}},
		{"spare exhausted", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 5 }),
			want{state: StateCrit, contains: []string{"spare 5%"}}},
		{"reported zero spare is crit", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 0 }),
			want{state: StateCrit, contains: []string{"critical_warning=0", "spare 0%"}}},
		{"missing spare is unknown", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 0; s.SpareKnown = false }),
			want{state: StateUnknown, contains: []string{"did not report its available spare"}}},
		{"missing spare with nonzero stale value is still unknown", mod(func(s *sysmon.DiskState) { s.SpareKnown = false }),
			want{state: StateUnknown, contains: []string{"did not report its available spare"}}},
		{"missing spare plus media errors is warn", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 0; s.SpareKnown = false; s.MediaErrors = 3 }),
			want{state: StateWarn, contains: []string{"3 media errors"}}},
		{"missing spare plus critical_warning is crit", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 0; s.SpareKnown = false; s.CriticalWarning = 1 }),
			want{state: StateCrit, contains: []string{"critical_warning=1", "spare not reported"}, absent: []string{"spare 0%"}}},
		{"zero spare plus critical_warning is crit", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 0; s.CriticalWarning = 1 }),
			want{state: StateCrit, contains: []string{"critical_warning=1", "spare 0%"}}},
		{"spare at threshold is ok", mod(func(s *sysmon.DiskState) { s.AvailableSpare = 10 }),
			want{state: StateOK}},
		{"media errors", mod(func(s *sysmon.DiskState) { s.MediaErrors = 2 }),
			want{state: StateWarn, contains: []string{"2 media errors"}}},
		{"worn out", mod(func(s *sysmon.DiskState) { s.PercentUsed = 93 }),
			want{state: StateWarn, contains: []string{"93%"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evalStorage(c.in)
			checkCommon(t, got, "Storage & uptime", c.w)
			if got.State != StateUnknown && !strings.HasPrefix(got.Value, "up ") {
				t.Errorf("Value = %q, want uptime", got.Value)
			}
		})
	}
}

func TestEvalWANRejects(t *testing.T) {
	cases := []struct {
		name string
		in   sysmon.FWState
		w    want
	}{
		{"counters missing", sysmon.FWState{}, want{state: StateUnknown, value: "—"}},
		{"background noise", sysmon.FWState{Available: true, InDropsPerMin: 80, FwdDropsPerMin: 20, Median: 90},
			want{state: StateOK, value: "100/min"}},
		{"elevated without baseline", sysmon.FWState{Available: true, InDropsPerMin: 600},
			want{state: StateWarn, value: "600/min"}},
		{"high but normal for this network", sysmon.FWState{Available: true, InDropsPerMin: 600, Median: 100},
			want{state: StateOK}},
		{"elevated vs baseline", sysmon.FWState{Available: true, InDropsPerMin: 1500, Median: 100},
			want{state: StateWarn, contains: []string{"1500 packets/min vs your usual 100/min"}}},
		{"flood without baseline", sysmon.FWState{Available: true, InDropsPerMin: 4000, FwdDropsPerMin: 2000},
			want{state: StateCrit, value: "6000/min", contains: []string{"flooding"}}},
		{"big but only 30x baseline is warn", sysmon.FWState{Available: true, InDropsPerMin: 6000, Median: 200},
			want{state: StateWarn}},
		{"flood vs baseline", sysmon.FWState{Available: true, InDropsPerMin: 20000, Median: 100},
			want{state: StateCrit}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checkCommon(t, evalWANRejects(c.in), "Unsolicited inbound", c.w)
		})
	}
}

func TestEvalClientsUnavailable(t *testing.T) {
	for _, s := range []*clients.Store{nil, {}} {
		c := evalClients(s)
		if c.Name != "Device tracking" || c.State != StateWarn || c.NumState != 1 || c.Value != "off" || !strings.Contains(c.Detail, "nlbwmon") {
			t.Errorf("evalClients(%v) = %+v", s, c)
		}
	}
}

func TestEvalOrbiDisabledOrUnreachable(t *testing.T) {
	// The password must never surface in a verdict.
	const secret = "hunter2-orbi-pass"
	for _, op := range []*orbi.Poller{nil, orbi.New("", "", "", nil), orbi.New("http://192.0.2.1", "admin", secret, nil)} {
		c := evalOrbi(op)
		if c.Name != "WiFi AP" || c.State != StateCrit || c.NumState != 2 || c.Value != "no response" || c.Detail == "" {
			t.Errorf("evalOrbi = %+v", c)
		}
		s := evalWifiSignal(op)
		if s.Name != "Wi-Fi signal" || s.State != StateUnknown || s.NumState != -1 || s.Detail == "" {
			t.Errorf("evalWifiSignal = %+v", s)
		}
		for _, d := range []string{c.Detail, c.Value, s.Detail, s.Value} {
			if strings.Contains(d, secret) {
				t.Errorf("verdict leaks the AP password: %q", d)
			}
		}
	}
}

func TestOrbiLabelsAndBands(t *testing.T) {
	if got := orbiLabel(orbi.State{}); got != "Orbi AP" {
		t.Errorf("orbiLabel(empty) = %q", got)
	}
	if got := orbiLabel(orbi.State{Model: "RBR50"}); got != "RBR50" {
		t.Errorf("orbiLabel(model) = %q", got)
	}
	for in, w := range map[string]string{"2.4G": "2.4 GHz", "5G": "5 GHz", "": "5 GHz"} {
		if got := bandLabel(in); got != w {
			t.Errorf("bandLabel(%q) = %q, want %q", in, got, w)
		}
	}
}

func TestNilSafeSnapshots(t *testing.T) {
	for _, sys := range []*sysmon.Pollers{nil, {}} {
		if warpSnap(sys).Available || clockSnap(sys).Available || diskSnap(sys).Available ||
			fwSnap(sys).Available || connSnap(sys).Max != 0 {
			t.Errorf("snapshots of %v must be zero", sys)
		}
	}
	if pppoeSnap(nil).Available {
		t.Error("pppoeSnap(nil) must be zero")
	}
	// The zero snapshots must map to non-alarming states for sysmon checks
	// whose data is simply missing.
	if evalClock(clockSnap(nil)).State != StateUnknown || evalStorage(diskSnap(nil)).State != StateUnknown ||
		evalWANRejects(fwSnap(nil)).State != StateUnknown || evalConntrack(connSnap(nil)).State != StateUnknown ||
		evalPPPoE(pppoeSnap(nil)).State != StateUnknown {
		t.Error("missing sysmon data must report unknown")
	}
}

func TestGradeAndNumState(t *testing.T) {
	cases := []struct {
		grade string
		state State
		num   float64
	}{
		{"A+", StateOK, 0}, {"A", StateOK, 0}, {"B", StateOK, 0},
		{"C", StateWarn, 1},
		{"D", StateCrit, 2}, {"E", StateCrit, 2}, {"F", StateCrit, 2},
		{"", StateUnknown, -1}, {"a", StateUnknown, -1}, {"Z", StateUnknown, -1},
	}
	for _, c := range cases {
		s := gradeState(c.grade)
		if s != c.state {
			t.Errorf("gradeState(%q) = %q, want %q", c.grade, s, c.state)
		}
		if n := numState(s); n != c.num {
			t.Errorf("numState(%q) = %v, want %v", s, n, c.num)
		}
	}
}

func TestLatestHelpers(t *testing.T) {
	t.Run("latest", func(t *testing.T) {
		if _, _, ok := latest(nil); ok {
			t.Error("latest(nil) ok")
		}
		v, ts, ok := latest([]vm.Point{{TS: 10, Val: 1}, {TS: 30, Val: 3}, {TS: 20, Val: 2}})
		if !ok || v != 3 || ts.Unix() != 30 {
			t.Errorf("latest = %v %v %v", v, ts, ok)
		}
	})
	t.Run("latestFromSeries", func(t *testing.T) {
		if _, _, ok := latestFromSeries([]vm.Series{{}}); ok {
			t.Error("empty series ok")
		}
		v, ts, ok := latestFromSeries([]vm.Series{
			{TS: []int64{1, 5}, Val: []float64{10, 50}},
			{TS: []int64{3, 9}, Val: []float64{30, 90}},
		})
		if !ok || v != 90 || ts.Unix() != 9 {
			t.Errorf("latestFromSeries = %v %v %v", v, ts, ok)
		}
	})
	t.Run("gradeFromSeries", func(t *testing.T) {
		cases := []struct {
			in   []vm.Series
			want string
		}{
			{nil, ""},
			{[]vm.Series{{Labels: map[string]string{"grade": "A"}, TS: []int64{5}, Val: []float64{0}}}, ""}, // inactive label
			{[]vm.Series{
				{Labels: map[string]string{"grade": "A"}, TS: []int64{1, 2}, Val: []float64{1, 1}},
				{Labels: map[string]string{"grade": "C"}, TS: []int64{3}, Val: []float64{1}},
				{Labels: map[string]string{"grade": "F"}, TS: []int64{4}, Val: []float64{0}},
			}, "C"},
		}
		for i, c := range cases {
			if got := gradeFromSeries(c.in); got != c.want {
				t.Errorf("case %d: gradeFromSeries = %q, want %q", i, got, c.want)
			}
		}
	})
}

func TestFormattingHelpers(t *testing.T) {
	strCases := []struct{ got, want string }{
		{fmtBloat(0), "+0.0 ms"},
		{fmtBloat(-3), "-3.0 ms"},
		{fmtBloatOrNA(2, true), "+2.0 ms"},
		{fmtBloatOrNA(2, false), "n/a"},
		{fmtBloatOrNA(math.NaN(), true), "n/a"},
		{humanBits(1.25e6), "10.0 Mbps"},
		{humanBits(50e6), "400 Mbps"},
		{humanBytes(512), "512 B"},
		{humanBytes(2048), "2 KiB"},
		{humanBytes(3 * 1024 * 1024), "3.0 MiB"},
		{humanBytes(1.5 * 1024 * 1024 * 1024), "1.5 GiB"},
		{trimAge(30 * time.Second), "30s"},
		{trimAge(3*time.Minute + 12*time.Second), "3m"},
		{trimAge(90 * time.Minute), "1.5h"},
		{trimAge(72 * time.Hour), "3d"},
	}
	for i, c := range strCases {
		if c.got != c.want {
			t.Errorf("case %d: got %q, want %q", i, c.got, c.want)
		}
	}
	if m := median(nil); m != 0 {
		t.Errorf("median(nil) = %v", m)
	}
	in := []float64{9, 1, 5}
	if m := median(in); m != 5 || in[0] != 9 {
		t.Errorf("median = %v (input %v must be untouched)", m, in)
	}
}

func TestScheduleHelpers(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	at := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, ist) }
	runCases := []struct {
		now, want time.Time
	}{
		{at(22, 9, 0), at(21, 20, 0)},
		{at(22, 11, 0), at(22, 11, 0)},
		{at(22, 15, 59), at(22, 15, 0)},
		{at(22, 20, 30), at(22, 20, 0)},
		{at(22, 23, 0), at(22, 20, 0)},
		{time.Date(2026, 11, 1, 3, 0, 0, 0, ist), time.Date(2026, 10, 31, 20, 0, 0, 0, ist)}, // month rollover
	}
	for _, c := range runCases {
		if got := lastScheduledRun(c.now); !got.Equal(c.want) {
			t.Errorf("lastScheduledRun(%v) = %v, want %v", c.now, got, c.want)
		}
	}
	hourCases := []struct {
		h, want int
	}{{3, 11}, {10, 11}, {11, 12}, {19, 20}, {20, 11}, {23, 11}}
	for _, c := range hourCases {
		if got := nextRunHour(at(22, c.h, 30)); got != c.want {
			t.Errorf("nextRunHour(%02d:30) = %d, want %d", c.h, got, c.want)
		}
	}
}

func TestSetLocation(t *testing.T) {
	old := scheduleLoc.Load()
	t.Cleanup(func() { scheduleLoc.Store(old) })

	scheduleLoc.Store(nil)
	if schedLoc() != time.Local {
		t.Error("default zone must be time.Local")
	}
	ist := time.FixedZone("IST", 19800)
	SetLocation(ist)
	if schedLoc() != ist {
		t.Error("SetLocation not applied")
	}
	SetLocation(nil) // ignored
	if schedLoc() != ist {
		t.Error("SetLocation(nil) must not reset the zone")
	}
}
