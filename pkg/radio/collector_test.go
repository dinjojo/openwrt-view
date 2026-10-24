package radio

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBandOf(t *testing.T) {
	cases := map[int]string{
		2412: "2.4G", 2484: "2.4G", 4999: "2.4G",
		5000: "5G", 5180: "5G", 5885: "5G", 5924: "5G",
		5925: "6G", 5955: "6G", 7115: "6G",
	}
	for mhz, want := range cases {
		if got := bandOf(mhz); got != want {
			t.Errorf("bandOf(%d) = %q, want %q", mhz, got, want)
		}
	}
}

func TestChannelOfEdges(t *testing.T) {
	cases := map[int]int{
		2407: 0, 2417: 2, 2473: 0, 2480: 0, 2483: 0,
		5000: 0, 5035: 7, 5260: 52, 5500: 100, 5865: 173, 5895: 179, 5900: 0,
		5950: 0, 6115: 33, 7115: 233, 7125: 235, 7130: 0, 9000: 0,
	}
	for mhz, want := range cases {
		if got := channelOf(mhz); got != want {
			t.Errorf("channelOf(%d) = %d, want %d", mhz, got, want)
		}
	}
}

func TestParseSurveyEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []surveyEntry
	}{
		{"lines before first header ignored",
			"frequency: 2412 MHz\nnoise: -90 dBm\nSurvey data from wlan1\n\tfrequency: 2437 MHz\n",
			[]surveyEntry{{FreqMHz: 2437}}},
		{"only active time -> HasTimes false",
			"Survey data from wlan1\n\tfrequency: 2412 MHz\n\tchannel active time: 500 ms\n",
			[]surveyEntry{{FreqMHz: 2412, ActiveMS: 500}}},
		{"only busy time -> HasTimes false",
			"Survey data from wlan1\n\tfrequency: 2412 MHz\n\tchannel busy time: 50 ms\n",
			[]surveyEntry{{FreqMHz: 2412, BusyMS: 50}}},
		{"block without frequency dropped",
			"Survey data from wlan1\n\tnoise: -90 dBm\n\tchannel active time: 1 ms\n\tchannel busy time: 1 ms\nSurvey data from wlan1\n\tfrequency: 5180 MHz\n",
			[]surveyEntry{{FreqMHz: 5180}}},
		{"times reset between blocks",
			"Survey data from wlan1\n\tfrequency: 2412 MHz\n\tchannel active time: 10 ms\n\tchannel busy time: 1 ms\nSurvey data from wlan1\n\tfrequency: 2417 MHz\n\tchannel busy time: 3 ms\n",
			[]surveyEntry{{FreqMHz: 2412, ActiveMS: 10, BusyMS: 1, HasTimes: true}, {FreqMHz: 2417, BusyMS: 3}}},
		{"unrelated lines and garbage values ignored",
			"Survey data from wlan1\n\tfrequency: 2412 MHz\n\tnoise: loud dBm\n\tchannel receive time: 99 ms\n\tchannel active time: lots ms\n",
			[]surveyEntry{{FreqMHz: 2412}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseSurvey(c.out)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got {
				g := got[i]
				if g.NoiseDBm != nil {
					t.Errorf("[%d] unexpected noise %d", i, *g.NoiseDBm)
				}
				g.NoiseDBm = nil
				if g != c.want[i] {
					t.Errorf("[%d] got %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestParseScanEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []Neighbour
	}{
		{"indented BSS line is not a new entry",
			"BSS 00:11:22:33:44:55(on wlan1)\n\tfreq: 2412\n\tsignal: -40.00 dBm\n\tSSID: first\n\t BSS 66:77:88:99:aa:bb\n\tSSID: second\n",
			[]Neighbour{{SSID: "first", BSSID: "00:11:22:33:44:55", SignalDBm: -40, FreqMHz: 2412, Band: "2.4G", Channel: 1}}},
		{"signal rounded to one decimal",
			"BSS 00:11:22:33:44:55(on wlan1)\n\tfreq: 5745\n\tsignal: -61.26 dBm\n",
			[]Neighbour{{BSSID: "00:11:22:33:44:55", SignalDBm: -61.3, FreqMHz: 5745, Band: "5G", Channel: 149}}},
		{"equal signals keep input order",
			"BSS 00:00:00:00:00:01\n\tfreq: 2412\n\tsignal: -50.00 dBm\nBSS 00:00:00:00:00:02\n\tfreq: 2437\n\tsignal: -50.00 dBm\n",
			[]Neighbour{
				{BSSID: "00:00:00:00:00:01", SignalDBm: -50, FreqMHz: 2412, Band: "2.4G", Channel: 1},
				{BSSID: "00:00:00:00:00:02", SignalDBm: -50, FreqMHz: 2437, Band: "2.4G", Channel: 6},
			}},
		{"lines before first BSS ignored",
			"freq: 2412\nsignal: -1.00 dBm\nSSID: stray\n",
			nil},
		{"CRLF output",
			"BSS 00:11:22:33:44:55(on wlan1)\r\n\tfreq: 2462\r\n\tsignal: -70.00 dBm\r\n\tSSID: crlf\r\n",
			[]Neighbour{{SSID: "crlf", BSSID: "00:11:22:33:44:55", SignalDBm: -70, FreqMHz: 2462, Band: "2.4G", Channel: 11}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseScan(c.out)
			if len(got) != len(c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("[%d] got %+v, want %+v", i, got[i], c.want[i])
				}
			}
		})
	}
}

func se(freq int, inUse bool, active, busy int64, has bool) surveyEntry {
	return surveyEntry{FreqMHz: freq, InUse: inUse, ActiveMS: active, BusyMS: busy, HasTimes: has}
}

func TestComputeBands(t *testing.T) {
	prev := map[int]surveyEntry{
		2412: se(2412, false, 1000, 100, true),
		2437: se(2437, false, 1000, 100, true),
		2462: se(2462, false, 1000, 100, true),
		2472: se(2472, false, 1000, 100, false),
		5180: se(5180, false, 5000, 500, true),
		5955: se(5955, false, 100, 10, true),
	}
	cur := []surveyEntry{
		se(5955, false, 50, 5, true),      // counters went backwards: no util
		se(2462, false, 2000, 1500, true), // Δa 1000 Δb 1400: busy>active, rejected
		se(2437, false, 3000, 600, true),  // Δa 2000 Δb 500: 25%
		se(2412, false, 2000, 100, true),  // Δa 1000 Δb 0: 0%
		se(2472, false, 9000, 900, true),  // prev had no times: no util
		se(5180, true, 5000, 500, true),   // no progress: no util
		se(5200, false, 999999, 1, true),  // most active but 5180 is in use
		se(2484, false, 0, 0, false),      // never seen before
	}
	bands := computeBands(prev, cur)
	if len(bands) != 3 {
		t.Fatalf("want 3 bands, got %+v", bands)
	}
	b24, b5, b6 := bands[0], bands[1], bands[2]
	if b24.Band != "2.4G" || b5.Band != "5G" || b6.Band != "6G" {
		t.Fatalf("band order = %s,%s,%s", b24.Band, b5.Band, b6.Band)
	}

	// 2.4G: Σ Δbusy (0+500) / Σ Δactive (1000+2000) = 16.7%.
	if b24.UtilPct == nil || *b24.UtilPct != 16.7 {
		t.Errorf("2.4G util = %s, want 16.7", fptr(b24.UtilPct))
	}
	// No channel in use: representative channel is the most active one.
	if b24.FreqMHz != 2472 {
		t.Errorf("2.4G freq = %d, want 2472 (most active)", b24.FreqMHz)
	}
	wantCh := []struct {
		freq, ch int
		util     string
	}{{2412, 1, "0"}, {2437, 6, "25"}, {2462, 11, "nil"}, {2472, 13, "nil"}, {2484, 14, "nil"}}
	if len(b24.Channels) != len(wantCh) {
		t.Fatalf("2.4G channels = %+v", b24.Channels)
	}
	for i, w := range wantCh {
		c := b24.Channels[i]
		if c.FreqMHz != w.freq || c.Channel != w.ch || fptr(c.UtilPct) != w.util {
			t.Errorf("2.4G channel %d = %+v util %s, want %+v", i, c, fptr(c.UtilPct), w)
		}
	}

	if b5.UtilPct != nil || b5.FreqMHz != 5180 || len(b5.Channels) != 2 || !b5.Channels[0].InUse {
		t.Errorf("5G band = %+v util %s (in-use channel must win, no util without progress)", b5, fptr(b5.UtilPct))
	}
	if b6.UtilPct != nil || b6.Channels[0].UtilPct != nil || b6.Channels[0].Channel != 1 {
		t.Errorf("6G band = %+v (counter reset must give null util)", b6)
	}
}

func TestComputeBandsEmpty(t *testing.T) {
	if got := computeBands(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("computeBands(nil,nil) = %#v, want empty non-nil", got)
	}
}

func TestShortErr(t *testing.T) {
	long := strings.Repeat("x", 130)
	cases := []struct {
		in, want string
	}{
		{"  plain  ", "plain"},
		{"first line\nsecond line", "first line"},
		{long, strings.Repeat("x", 120) + "…"},
		{strings.Repeat("y", 120), strings.Repeat("y", 120)},
	}
	for _, c := range cases {
		if got := shortErr(errors.New(c.in)); got != c.want {
			t.Errorf("shortErr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNewInterfaceValidation(t *testing.T) {
	cases := []struct {
		iface   string
		enabled bool
		err     string
	}{
		{"", false, "radio interface not configured"},
		{"wlan1", true, "radio interface not configured"},
		{"mon0.1_a-b", true, "radio interface not configured"},
		{"abcdefghijklmno", true, "radio interface not configured"}, // 15 chars
		{"abcdefghijklmnop", false, "invalid radio interface name"}, // 16 chars
		{"wlan 1", false, "invalid radio interface name"},
		{"../etc", false, "invalid radio interface name"},
		{"-", true, "radio interface not configured"},
	}
	for _, c := range cases {
		col := New(c.iface)
		st := col.Snapshot()
		if col.Enabled() != c.enabled || st.Err != c.err || st.OK || st.Bands == nil || st.Neighbours == nil || st.Iface != c.iface {
			t.Errorf("New(%q): enabled=%v status=%+v", c.iface, col.Enabled(), st)
		}
	}
}

// fakeIW answers `iw` invocations from a table keyed by the joined args.
type fakeIW struct {
	mu   sync.Mutex
	resp map[string]struct {
		out string
		err error
	}
	calls []string
}

func (f *fakeIW) set(args, out string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resp == nil {
		f.resp = map[string]struct {
			out string
			err error
		}{}
	}
	f.resp[args] = struct {
		out string
		err error
	}{out, err}
}

func (f *fakeIW) run(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.Join(args, " ")
	f.calls = append(f.calls, k)
	r, ok := f.resp[k]
	if !ok {
		return "", errors.New("unexpected " + k)
	}
	return r.out, r.err
}

func TestScanFallsBackToDump(t *testing.T) {
	cases := []struct {
		name      string
		scanOut   string
		scanErr   error
		dumpOut   string
		dumpErr   error
		wantCalls []string
		wantN     int
	}{
		{"fresh scan works", scanFixture, nil, "", nil, []string{"dev wlan1 scan"}, 4},
		{"scan refused, dump works", "", errors.New("command failed: Device or resource busy (-16)"), scanFixture, nil,
			[]string{"dev wlan1 scan", "dev wlan1 scan dump"}, 4},
		{"scan empty, dump empty is ok with no neighbours", "", nil, "", nil,
			[]string{"dev wlan1 scan", "dev wlan1 scan dump"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeIW{}
			f.set("dev wlan1 scan", c.scanOut, c.scanErr)
			f.set("dev wlan1 scan dump", c.dumpOut, c.dumpErr)
			col := New("wlan1")
			col.run = f.run
			col.scan(context.Background())
			st := col.Snapshot()
			if strings.Join(f.calls, "|") != strings.Join(c.wantCalls, "|") {
				t.Errorf("calls = %q, want %q", f.calls, c.wantCalls)
			}
			if st.Neighbours == nil || len(st.Neighbours) != c.wantN {
				t.Errorf("neighbours = %#v, want %d", st.Neighbours, c.wantN)
			}
		})
	}
}

func TestScanFailureKeepsLastNeighbours(t *testing.T) {
	f := &fakeIW{}
	f.set("dev wlan1 scan", scanFixture, nil)
	col := New("wlan1")
	col.run = f.run
	col.scan(context.Background())
	if n := len(col.Snapshot().Neighbours); n != 4 {
		t.Fatalf("first scan neighbours = %d", n)
	}
	f.set("dev wlan1 scan", "", errors.New("busy"))
	f.set("dev wlan1 scan dump", "", errors.New("busy"))
	col.scan(context.Background())
	if n := len(col.Snapshot().Neighbours); n != 4 {
		t.Errorf("failed scan should keep last neighbours, got %d", n)
	}
	if col.lastScanOK == nil || *col.lastScanOK {
		t.Error("lastScanOK should record the failure")
	}
}

func TestSurveyErrorResetsBaseline(t *testing.T) {
	f := &fakeIW{}
	f.set("dev wlan1 survey dump", surveyT0, nil)
	col := New("wlan1")
	col.run = f.run
	col.survey(context.Background())
	if st := col.Snapshot(); !st.OK || st.At == 0 {
		t.Fatalf("first survey: %+v", st)
	}

	// Empty output without an error is still a failure.
	f.set("dev wlan1 survey dump", "", nil)
	col.survey(context.Background())
	st := col.Snapshot()
	if st.OK || st.Err != "survey: no survey data" || len(st.Bands) != 0 || st.Bands == nil {
		t.Fatalf("empty survey: %+v", st)
	}
	if len(col.prev) != 0 {
		t.Error("failure must drop the previous baseline")
	}

	// Recovery: first good survey after a failure has no utilisation yet,
	// because the baseline was dropped.
	f.set("dev wlan1 survey dump", surveyT1, nil)
	col.survey(context.Background())
	st = col.Snapshot()
	if !st.OK || st.Err != "" || col.lastErr != "" {
		t.Fatalf("recovered survey: %+v", st)
	}
	for _, b := range st.Bands {
		if b.UtilPct != nil {
			t.Errorf("band %s has utilisation right after recovery: %s", b.Band, fptr(b.UtilPct))
		}
	}
}

func TestSurveyMultilineErrorIsShortened(t *testing.T) {
	f := &fakeIW{}
	f.set("dev wlan1 survey dump", "", errors.New("command failed: No such device (-19)\nmore detail"))
	col := New("wlan1")
	col.run = f.run
	col.survey(context.Background())
	if st := col.Snapshot(); st.Err != "survey: command failed: No such device (-19)" {
		t.Errorf("err = %q", st.Err)
	}
}

func TestSurveyCancelledParentLeavesStatus(t *testing.T) {
	f := &fakeIW{}
	f.set("dev wlan1 survey dump", surveyT0, nil)
	f.set("dev wlan1 scan", scanFixture, nil)
	col := New("wlan1")
	col.run = f.run
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	col.survey(ctx)
	col.scan(ctx)
	st := col.Snapshot()
	if st.At != 0 || st.OK || len(st.Neighbours) != 0 {
		t.Errorf("cancelled poll must not update status: %+v", st)
	}
}

func TestRunDisabledReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		New("").Run(context.Background())
		var nilC *Collector
		nilC.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run on a disabled collector must return immediately")
	}
}

func TestRunPollsOnceThenStopsOnCancel(t *testing.T) {
	f := &fakeIW{}
	f.set("dev wlan1 survey dump", surveyT0, nil)
	f.set("dev wlan1 scan", scanFixture, nil)
	col := New("wlan1")
	col.run = f.run
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { col.Run(ctx); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		st := col.Snapshot()
		if st.OK && len(st.Neighbours) == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial survey+scan did not complete: %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}
