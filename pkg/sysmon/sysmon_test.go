package sysmon

import (
	"encoding/binary"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeBin installs an executable shell script called name into a fresh
// directory and points PATH at it, so exec.Command(name, ...) runs the
// script instead of the real router tool.
func fakeBin(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin") // fake first; coreutils for the script
	return dir
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------- WARP ----------

func wgDump(hs int64, rx, tx uint64) string {
	return "PRIVKEY\tPUBKEY\t51820\toff\n" +
		"PEERPUB\t(none)\t162.159.192.1:2408\t0.0.0.0/0\t" +
		itoa(hs) + "\t" + utoa(rx) + "\t" + utoa(tx) + "\t25\n"
}

func itoa(v int64) string  { return strconv.FormatInt(v, 10) }
func utoa(v uint64) string { return strconv.FormatUint(v, 10) }

func TestWarpRefreshParsesDump(t *testing.T) {
	hs := time.Now().Add(-time.Minute).Unix()
	cases := []struct {
		name          string
		dump          string // "" = wg binary fails
		wantAvailable bool
		wantPeers     int
		wantEndpoint  string
		wantHS        bool
		wantRx        uint64
		wantTx        uint64
	}{
		{"wg missing / interface gone", "", false, 0, "", false, 0, 0},
		{"interface only, no peers", "PRIVKEY\tPUBKEY\t51820\toff\n", false, 0, "", false, 0, 0},
		{"healthy peer", wgDump(hs, 1000, 2000), true, 1, "162.159.192.1:2408", true, 1000, 2000},
		{"peer never handshaked", wgDump(0, 0, 0), true, 1, "162.159.192.1:2408", false, 0, 0},
		{"malformed short line ignored", wgDump(hs, 5, 6) + "junk\tline\n", true, 1, "162.159.192.1:2408", true, 5, 6},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := fakeBin(t, "wg", `cat "$(dirname "$0")/dump" || exit 1`+"\n")
			if c.dump != "" {
				writeFile(t, filepath.Join(dir, "dump"), c.dump)
			} else {
				writeFile(t, filepath.Join(dir, "wg"), "#!/bin/sh\nexit 1\n")
			}
			p := &WarpPoller{}
			p.refresh()
			st := p.Snapshot()
			if st.Available != c.wantAvailable || st.PeerCount != c.wantPeers || st.Endpoint != c.wantEndpoint {
				t.Errorf("got Available=%v Peers=%d Endpoint=%q, want %v %d %q",
					st.Available, st.PeerCount, st.Endpoint, c.wantAvailable, c.wantPeers, c.wantEndpoint)
			}
			if !st.Handshake.IsZero() != c.wantHS {
				t.Errorf("handshake = %v, want set=%v", st.Handshake, c.wantHS)
			}
			if c.wantHS && st.Handshake.Unix() != hs {
				t.Errorf("handshake unix = %d, want %d", st.Handshake.Unix(), hs)
			}
			if st.RxBytes != c.wantRx || st.TxBytes != c.wantTx {
				t.Errorf("rx/tx = %d/%d, want %d/%d", st.RxBytes, st.TxBytes, c.wantRx, c.wantTx)
			}
			if st.RatesKnown {
				t.Error("RatesKnown must be false after the first poll")
			}
			if st.At.IsZero() {
				t.Error("At not stamped")
			}
		})
	}
}

func TestWarpRefreshComputesRates(t *testing.T) {
	dir := fakeBin(t, "wg", `cat "$(dirname "$0")/dump"`+"\n")
	hs := time.Now().Unix()
	writeFile(t, filepath.Join(dir, "dump"), wgDump(hs, 10_000, 20_000))
	p := &WarpPoller{}
	p.refresh()

	// Pretend the previous poll happened 10 s ago so the rate is exact.
	p.state.At = time.Now().Add(-10 * time.Second)
	writeFile(t, filepath.Join(dir, "dump"), wgDump(hs, 10_000+102_400, 20_000+10_240))
	p.refresh()
	st := p.Snapshot()
	if !st.RatesKnown {
		t.Fatal("RatesKnown false after second poll")
	}
	if math.Abs(st.RxPerS-10_240) > 100 || math.Abs(st.TxPerS-1_024) > 10 {
		t.Errorf("rates rx=%v tx=%v, want ~10240 and ~1024", st.RxPerS, st.TxPerS)
	}
}

// A wg restart zeroes the peer counters. The interval spanning the restart
// must read as rate 0 (not a ~1.8e18 B/s uint64 wrap), and the new counter
// becomes the baseline so the following interval is sane again.
func TestWarpRefreshCounterReset(t *testing.T) {
	cases := []struct {
		name               string
		rx1, tx1, rx2, tx2 uint64
		wantRx, wantTx     float64 // per second over 10 s
	}{
		{"normal increment", 1000, 2000, 1000 + 10_240, 2000 + 1_024, 1024, 102.4},
		{"both counters reset", 5_000_000, 6_000_000, 100, 50, 0, 0},
		{"rx reset only", 5_000_000, 2000, 100, 2000 + 1_000, 0, 100},
		{"drop by one", 1001, 1001, 1000, 1000, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := fakeBin(t, "wg", `cat "$(dirname "$0")/dump"`+"\n")
			hs := time.Now().Unix()
			writeFile(t, filepath.Join(dir, "dump"), wgDump(hs, c.rx1, c.tx1))
			p := &WarpPoller{}
			p.refresh()

			p.state.At = time.Now().Add(-10 * time.Second)
			writeFile(t, filepath.Join(dir, "dump"), wgDump(hs, c.rx2, c.tx2))
			p.refresh()
			st := p.Snapshot()
			if !st.RatesKnown {
				t.Fatal("RatesKnown false after second poll")
			}
			if math.Abs(st.RxPerS-c.wantRx) > c.wantRx*0.02+1e-9 || math.Abs(st.TxPerS-c.wantTx) > c.wantTx*0.02+1e-9 {
				t.Errorf("rates rx=%v tx=%v, want ~%v ~%v", st.RxPerS, st.TxPerS, c.wantRx, c.wantTx)
			}

			// Next interval diffs against the post-reset counters.
			p.state.At = time.Now().Add(-10 * time.Second)
			writeFile(t, filepath.Join(dir, "dump"), wgDump(hs, c.rx2+10_000, c.tx2+1_000))
			p.refresh()
			st = p.Snapshot()
			if math.Abs(st.RxPerS-1000) > 20 || math.Abs(st.TxPerS-100) > 2 {
				t.Errorf("post-reset rates rx=%v tx=%v, want ~1000 ~100", st.RxPerS, st.TxPerS)
			}
		})
	}
}

// ---------- Clock ----------

// fakeNTP answers SNTP requests with a transmit timestamp skewed by skew.
// zero=true replies with an all-zero (kiss-of-death style) timestamp.
func fakeNTP(t *testing.T, skew time.Duration, zero bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 48)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != 48 || buf[0] != 0x24 {
				continue // must be an SNTPv4 client request
			}
			resp := make([]byte, 48)
			resp[0] = 0x24
			if !zero {
				ts := time.Now().Add(skew)
				binary.BigEndian.PutUint32(resp[40:], uint32(ts.Unix()+2208988800))
				binary.BigEndian.PutUint32(resp[44:], uint32(float64(ts.Nanosecond())/1e9*4294967296))
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// closedUDP returns a localhost UDP address with nothing listening.
func closedUDP(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

func TestSNTPOffset(t *testing.T) {
	cases := []struct {
		name   string
		addr   string
		wantOK bool
		wantMs float64
	}{
		{"in sync", fakeNTP(t, 0, false), true, 0},
		{"router 5 s behind", fakeNTP(t, 5*time.Second, false), true, 5000},
		{"router 2 s ahead", fakeNTP(t, -2*time.Second, false), true, -2000},
		{"zero timestamp rejected", fakeNTP(t, 0, true), false, 0},
		{"nothing listening", closedUDP(t), false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			off, ok := sntpOffset(c.addr)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (off=%v)", ok, c.wantOK, off)
			}
			if ok && math.Abs(off-c.wantMs) > 250 {
				t.Errorf("offset = %.1f ms, want ~%.0f", off, c.wantMs)
			}
		})
	}
}

func dateServer(t *testing.T, date func() []string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = date() // nil suppresses the automatic header
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestHTTPDateOffset(t *testing.T) {
	ahead := func(d time.Duration) func() []string {
		return func() []string { return []string{time.Now().Add(d).UTC().Format(http.TimeFormat)} }
	}
	cases := []struct {
		name   string
		url    string
		wantOK bool
		wantMs float64
	}{
		{"in sync", dateServer(t, ahead(0)), true, 0},
		{"router one hour behind", dateServer(t, ahead(time.Hour)), true, 3_600_000},
		{"no Date header", dateServer(t, func() []string { return nil }), false, 0},
		{"unparseable Date", dateServer(t, func() []string { return []string{"yesterday-ish"} }), false, 0},
		{"unreachable", "http://" + closedUDP(t), false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			off, ok := httpDateOffset(c.url)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			// HTTP Date has one-second resolution.
			if ok && math.Abs(off-c.wantMs) > 1500 {
				t.Errorf("offset = %.0f ms, want ~%.0f", off, c.wantMs)
			}
		})
	}
}

func TestClockRefreshSourceSelection(t *testing.T) {
	origNTP, origHTTP := ntpServers, httpDateServers
	t.Cleanup(func() { ntpServers, httpDateServers = origNTP, origHTTP })

	good := dateServer(t, func() []string { return []string{time.Now().UTC().Format(http.TimeFormat)} })
	ntp := fakeNTP(t, 0, false)
	cases := []struct {
		name       string
		ntp, http  []string
		wantAvail  bool
		wantSource string
		wantServer string
	}{
		{"sntp preferred", []string{ntp}, []string{good}, true, "sntp", ntp},
		{"falls through to second sntp", []string{closedUDP(t), ntp}, []string{good}, true, "sntp", ntp},
		{"udp blocked -> http", []string{closedUDP(t)}, []string{good}, true, "http", good},
		{"nothing reachable", []string{closedUDP(t)}, []string{"http://" + closedUDP(t)}, false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ntpServers, httpDateServers = c.ntp, c.http
			p := &ClockPoller{}
			p.refresh()
			st := p.Snapshot()
			if st.Available != c.wantAvail || st.Source != c.wantSource || st.Server != c.wantServer {
				t.Errorf("got %+v, want avail=%v source=%q server=%q", st, c.wantAvail, c.wantSource, c.wantServer)
			}
			if st.CheckedAt.IsZero() {
				t.Error("CheckedAt not stamped")
			}
		})
	}
}

// ---------- nil-safe grouping ----------

func TestSnapshotsOnZeroPollers(t *testing.T) {
	if (&WarpPoller{}).Snapshot().Available || (&ClockPoller{}).Snapshot().Available ||
		(&DiskPoller{}).Snapshot().Available ||
		(&ConnPoller{}).Snapshot().Max != 0 {
		t.Error("zero-value pollers must report empty snapshots")
	}
}

// ---------- NVMe SMART parsing ----------

func TestParseDiskSpareKnown(t *testing.T) {
	cases := []struct {
		name     string
		parse    func([]byte, *DiskState)
		out      string
		avail    bool
		known    bool
		spare    float64
		critWarn uint64
		tempC    float64
	}{
		{"nvme-cli spare present", parseNvmeCLI,
			`{"critical_warning":0,"temperature":314,"avail_spare":100,"percent_used":3,"media_errors":0}`,
			true, true, 100, 0, 314 - 273.15},
		{"nvme-cli reported zero spare", parseNvmeCLI,
			`{"critical_warning":1,"temperature":314,"avail_spare":0,"percent_used":3}`,
			true, true, 0, 1, 314 - 273.15},
		{"nvme-cli spare missing", parseNvmeCLI,
			`{"critical_warning":0,"temperature":314,"percent_used":3}`,
			true, false, 0, 0, 314 - 273.15},
		{"nvme-cli garbage", parseNvmeCLI, `not json`, false, false, 0, 0, 0},
		{"smartctl spare present", parseSmartctl,
			`{"nvme_smart_health_information_log":{"available_spare":87,"percent_used":5,"temperature":40}}`,
			true, true, 87, 0, 40},
		{"smartctl reported zero spare", parseSmartctl,
			`{"nvme_smart_health_information_log":{"available_spare":0,"temperature":40}}`,
			true, true, 0, 0, 40},
		{"smartctl spare missing", parseSmartctl,
			`{"nvme_smart_health_information_log":{"percent_used":5,"temperature":40,"critical_warning":2}}`,
			true, false, 0, 2, 40},
		{"smartctl no nvme log", parseSmartctl, `{"smartctl":{}}`, true, false, 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var st DiskState
			c.parse([]byte(c.out), &st)
			if st.Available != c.avail || st.SpareKnown != c.known || st.AvailableSpare != c.spare ||
				st.CriticalWarning != c.critWarn || math.Abs(st.TempC-c.tempC) > 1e-9 {
				t.Errorf("got %+v, want avail=%v known=%v spare=%v crit=%v temp=%v",
					st, c.avail, c.known, c.spare, c.critWarn, c.tempC)
			}
		})
	}
}
