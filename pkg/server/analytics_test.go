package server

import (
	"context"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/orbi"
	"github.com/dinjojo/openwrt-view/pkg/types"
)

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		// Previously supported inputs (regression).
		{"415Mbit", 415e6},
		{"1Gbit", 1e9},
		{"500Kbit", 500e3},
		{"500kbit", 500e3},
		{"2.5Gbit", 2.5e9},
		{"  415Mbit  ", 415e6},
		// Bare bit unit.
		{"1000bit", 1000},
		// bps = BYTES per second, so ×8 to get bits.
		{"100bps", 800},
		{"50Mbps", 400e6},
		{"50mbps", 400e6},
		{"1Kbps", 8e3},
		{"1Gbps", 8e9},
		// Tera prefix.
		{"1Tbit", 1e12},
		{"1tbit", 1e12},
		{"1.5Tbit", 1.5e12},
		{"1Tbps", 8e12},
		// Unknown / garbage.
		{"", 0},
		{"Mbit", 0},
		{"415", 0},
		{"415Mbyte", 0},
		{"415Xbit", 0},
		{"415Pbit", 0},
		{"fast", 0},
		{"unlimited", 0},
	}
	for _, c := range cases {
		if got := parseBandwidth(c.in); got != c.want {
			t.Errorf("parseBandwidth(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A probe episode straddling midnight must be counted once — on the day
// it started — not once per day it touches. The daily report queries
// one day window at a time; the lookback in bufferingEpisodes makes the
// second day's query see the episode whole, and episodeCount attributes
// it by Start.
func TestMidnightSpanningEpisodeCountedOnce(t *testing.T) {
	loc := time.FixedZone("ICT", 7*3600)
	f := newFakeVM()
	s := newTrendServer(t, f)
	s.loc = loc

	at := func(day, h, m int) int64 { return time.Date(2026, 10, day, h, m, 0, 0, loc).Unix() }
	// Bad readings at 23:50 and 23:58 on day 1, then 00:05 on day 2 —
	// one episode spanning midnight (gaps well under probeMaxGap).
	ts := []int64{at(20, 23, 50), at(20, 23, 58), at(21, 0, 5)}
	vals := []float64{80, 90, 85}
	f.raw[`probe_bloat_ms{direction="down"}`] = []vmSeries{matrix(nil, ts, vals...)}
	f.raw[`probe_bloat_ms{direction="up"}`] = nil

	day1 := dayWindow{date: "2026-10-20", start: at(20, 0, 0), end: at(21, 0, 0)}
	day2 := dayWindow{date: "2026-10-21", start: at(21, 0, 0), end: at(22, 0, 0)}

	eps1, _, err := s.bufferingEpisodes(context.Background(), day1.start, day1.end-1, false)
	if err != nil {
		t.Fatalf("day1 episodes: %v", err)
	}
	if n := episodeCount(eps1, day1, 0, false); n == nil || *n != 1 {
		t.Errorf("day1 counted %v, want 1", n)
	}
	eps2, _, err := s.bufferingEpisodes(context.Background(), day2.start, day2.end-1, false)
	if err != nil {
		t.Fatalf("day2 episodes: %v", err)
	}
	if n := episodeCount(eps2, day2, 0, false); n != nil && *n != 0 {
		t.Errorf("day2 counted %d, want 0 (episode belongs to day1)", *n)
	}
}

// With asymmetric shaping the detector must use each direction's own
// rate, or utilisation reads wrong and episodes fire at the wrong load.
func TestShapedBitsPerSPerDirection(t *testing.T) {
	s := New("127.0.0.1:0", time.Second, 10, "", "test", orbi.New("", "", "", nil))
	s.stats = []types.CakeStats{
		{Interface: "eth0", Bandwidth: "400Mbit"},
		{Interface: "ifb4eth0", Bandwidth: "415Mbit"},
	}
	if got := s.shapedBitsPerS("eth0"); got != 400e6 {
		t.Errorf("upload rate = %v, want 400 Mbit", got)
	}
	if got := s.shapedBitsPerS("ifb4eth0"); got != 415e6 {
		t.Errorf("download rate = %v, want 415 Mbit", got)
	}
}
