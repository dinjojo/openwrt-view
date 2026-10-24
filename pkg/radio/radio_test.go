package radio

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Survey dump as printed by iw 5.x for an ath9k_htc (AR9271) card.
const surveyT0 = `Survey data from wlan1
	frequency:			2412 MHz
	noise:				-95 dBm
	channel active time:		1000 ms
	channel busy time:		100 ms
	channel receive time:		80 ms
	channel transmit time:		0 ms
Survey data from wlan1
	frequency:			2437 MHz [in use]
	noise:				-92 dBm
	channel active time:		50000 ms
	channel busy time:		10000 ms
	channel receive time:		9000 ms
	channel transmit time:		20 ms
Survey data from wlan1
	frequency:			2462 MHz
Survey data from wlan1
	frequency:			5180 MHz
	noise:				-101 dBm
	channel active time:		200 ms
	channel busy time:		10 ms
`

const surveyT1 = `Survey data from wlan1
	frequency:			2412 MHz
	noise:				-95 dBm
	channel active time:		1000 ms
	channel busy time:		100 ms
Survey data from wlan1
	frequency:			2437 MHz [in use]
	noise:				-91 dBm
	channel active time:		80000 ms
	channel busy time:		16000 ms
Survey data from wlan1
	frequency:			2462 MHz
Survey data from wlan1
	frequency:			5180 MHz
	noise:				-101 dBm
	channel active time:		1200 ms
	channel busy time:		510 ms
`

func ip(v int) *int { return &v }

func TestParseSurvey(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []surveyEntry
	}{
		{"ath9k blocks", surveyT0, []surveyEntry{
			{FreqMHz: 2412, NoiseDBm: ip(-95), ActiveMS: 1000, BusyMS: 100, HasTimes: true},
			{FreqMHz: 2437, InUse: true, NoiseDBm: ip(-92), ActiveMS: 50000, BusyMS: 10000, HasTimes: true},
			{FreqMHz: 2462},
			{FreqMHz: 5180, NoiseDBm: ip(-101), ActiveMS: 200, BusyMS: 10, HasTimes: true},
		}},
		{"fractional frequency, CRLF", "Survey data from mon0\r\n\tfrequency:\t\t\t5745.0 MHz [in use]\r\n\tchannel active time:\t\t10 ms\r\n\tchannel busy time:\t\t5 ms\r\n",
			[]surveyEntry{{FreqMHz: 5745, InUse: true, ActiveMS: 10, BusyMS: 5, HasTimes: true}}},
		{"error text", "command failed: No such device (-19)\n", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		got := parseSurvey(c.out)
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %d entries %+v, want %d", c.name, len(got), got, len(c.want))
		}
		for i := range got {
			g, w := got[i], c.want[i]
			gn, wn := g.NoiseDBm, w.NoiseDBm
			g.NoiseDBm, w.NoiseDBm = nil, nil
			if g != w || (gn == nil) != (wn == nil) || (gn != nil && *gn != *wn) {
				t.Errorf("%s[%d]: got %+v (noise %v), want %+v (noise %v)", c.name, i, got[i], gn, c.want[i], wn)
			}
		}
	}
}

const scanFixture = `BSS aa:bb:cc:00:00:0a(on wlan1) -- associated
	last seen: 1234.567s [boottime]
	TSF: 123456789 usec (0d, 00:02:03)
	freq: 5180
	beacon interval: 100 TUs
	capability: ESS Privacy SpectrumMgmt (0x0111)
	signal: -72.00 dBm
	last seen: 120 ms ago
	Information elements from Probe Response frame:
	SSID: TestSSID
	Supported rates: 6.0* 9.0 12.0* 18.0 24.0* 36.0 48.0 54.0
	HT operation:
		 * primary channel: 36
BSS a0:04:60:11:22:33(on wlan1)
	freq: 2437.0
	signal: -48.50 dBm
	SSID: Neighbour Net 2.4
	DS Parameter set: channel 6
BSS 12:34:56:78:9a:bc(on wlan1)
	freq: 2462
	signal: -88.00 dBm
	SSID: 
BSS de:ad:be:ef:00:01(on wlan1)
	freq: 5975
	signal: -80.00 dBm
	SSID: SixGig
`

func TestParseScan(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []Neighbour
	}{
		{"mixed bands, strongest first", scanFixture, []Neighbour{
			{SSID: "Neighbour Net 2.4", BSSID: "A0:04:60:11:22:33", SignalDBm: -48.5, FreqMHz: 2437, Band: "2.4G", Channel: 6},
			{SSID: "TestSSID", BSSID: "AA:BB:CC:00:00:0A", SignalDBm: -72, FreqMHz: 5180, Band: "5G", Channel: 36},
			{SSID: "SixGig", BSSID: "DE:AD:BE:EF:00:01", SignalDBm: -80, FreqMHz: 5975, Band: "6G", Channel: 5},
			{SSID: "", BSSID: "12:34:56:78:9A:BC", SignalDBm: -88, FreqMHz: 2462, Band: "2.4G", Channel: 11},
		}},
		{"no freq dropped", "BSS aa:bb:cc:00:00:0a(on wlan1)\n\tsignal: -50.00 dBm\n\tSSID: x\n", nil},
		{"error text", "command failed: Operation not supported (-95)\n", nil},
	}
	for _, c := range cases {
		got := parseScan(c.out)
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %d %+v, want %d", c.name, len(got), got, len(c.want))
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s[%d]: got %+v, want %+v", c.name, i, got[i], c.want[i])
			}
		}
	}
}

func TestChannelOf(t *testing.T) {
	for mhz, want := range map[int]int{2412: 1, 2437: 6, 2472: 13, 2484: 14, 5180: 36, 5745: 149, 5825: 165, 5935: 2, 5955: 1, 4000: 0} {
		if got := channelOf(mhz); got != want {
			t.Errorf("channelOf(%d)=%d, want %d", mhz, got, want)
		}
	}
}

func fptr(p *float64) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprint(*p)
}

func TestCollectorUtilisation(t *testing.T) {
	outputs := []string{surveyT0, surveyT1}
	n := 0
	c := New("wlan1")
	c.run = func(_ context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") != "dev wlan1 survey dump" {
			return "", errors.New("unexpected " + strings.Join(args, " "))
		}
		out := outputs[n]
		n++
		return out, nil
	}
	c.survey(context.Background())
	st := c.Snapshot()
	if !st.OK || len(st.Bands) != 2 || st.Bands[0].UtilPct != nil {
		t.Fatalf("first poll: want ok, 2 bands, no utilisation yet; got %+v", st)
	}
	c.survey(context.Background())
	st = c.Snapshot()
	b24, b5 := st.Bands[0], st.Bands[1]
	// 2.4G: only 2437 advanced: Δbusy 6000 / Δactive 30000 = 20%.
	if b24.Band != "2.4G" || b24.UtilPct == nil || *b24.UtilPct != 20 || b24.FreqMHz != 2437 || *b24.NoiseDBm != -91 {
		t.Errorf("2.4G band = %+v (util %s)", b24, fptr(b24.UtilPct))
	}
	// 5G: Δbusy 500 / Δactive 1000 = 50%.
	if b5.Band != "5G" || b5.UtilPct == nil || *b5.UtilPct != 50 || b5.FreqMHz != 5180 {
		t.Errorf("5G band = %+v (util %s)", b5, fptr(b5.UtilPct))
	}
	if len(b24.Channels) != 3 || b24.Channels[0].UtilPct != nil || b24.Channels[2].UtilPct != nil {
		t.Errorf("2.4G channels: idle/timeless channels must have null util: %+v", b24.Channels)
	}
}

func TestCollectorDisabledAndFailing(t *testing.T) {
	var nilC *Collector
	if nilC.Enabled() || nilC.Snapshot().OK || nilC.Snapshot().Bands == nil {
		t.Fatal("nil collector must be disabled with empty slices")
	}
	if New("").Enabled() || New("bad iface;rm").Enabled() {
		t.Fatal("empty/invalid iface must disable")
	}
	c := New("wlan1")
	c.run = func(context.Context, ...string) (string, error) {
		return "", errors.New("command failed: No such device (-19)")
	}
	c.survey(context.Background())
	c.scan(context.Background())
	st := c.Snapshot()
	if st.OK || !strings.HasPrefix(st.Err, "survey: ") || st.Bands == nil || st.Neighbours == nil {
		t.Fatalf("failing survey: %+v", st)
	}
}
