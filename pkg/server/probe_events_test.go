package server

import (
	"strings"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

func TestProbeTrackerOneEventPerRun(t *testing.T) {
	grade := func(g string, ts ...int64) vm.Series {
		se := vm.Series{Labels: map[string]string{"grade": g}}
		for _, x := range ts {
			se.TS = append(se.TS, x)
			se.Val = append(se.Val, 1)
		}
		return se
	}
	// Each poll sees the raw samples in its 10-minute window.
	polls := []struct {
		name   string
		dir    string
		bloat  vm.Series
		grades []vm.Series
		want   bool
		grade  string
	}{
		{"sample from before the monitor started", "down", vm.Series{TS: []int64{900}, Val: []float64{40}}, []vm.Series{grade("C", 900)}, false, "C"},
		{"new probe run", "down", vm.Series{TS: []int64{900, 1200}, Val: []float64{40, 55}}, []vm.Series{grade("C", 900), grade("D", 1200)}, true, "D"},
		{"same sample on the next poll", "down", vm.Series{TS: []int64{900, 1200}, Val: []float64{40, 55}}, []vm.Series{grade("C", 900), grade("D", 1200)}, false, "D"},
		{"same sample again", "down", vm.Series{TS: []int64{1200}, Val: []float64{55}}, []vm.Series{grade("D", 1200)}, false, "D"},
		{"upload direction tracked separately", "up", vm.Series{TS: []int64{1200}, Val: []float64{35}}, []vm.Series{grade("C", 1200)}, true, "C"},
		{"newer probe run", "down", vm.Series{TS: []int64{1200, 4800}, Val: []float64{55, 31}}, []vm.Series{grade("D", 1200), grade("C", 4800)}, true, "C"},
		{"empty window", "down", vm.Series{}, nil, false, ""},
	}
	tr := newProbeTracker(1000)
	events := 0
	for _, p := range polls {
		r, ok := newestReading([]vm.Series{p.bloat}, p.grades)
		got := ok && tr.accept(p.dir, r)
		if got != p.want {
			t.Errorf("%s: accept = %v, want %v", p.name, got, p.want)
		}
		if ok && r.Grade != p.grade {
			t.Errorf("%s: grade = %q, want %q", p.name, r.Grade, p.grade)
		}
		if got {
			events++
		}
	}
	if events != 3 {
		t.Errorf("events = %d, want 3 (two download runs, one upload run)", events)
	}
}

func TestProbeSeverity(t *testing.T) {
	for g, want := range map[string]string{"A+": "ok", "A": "ok", "B": "ok", "C": "warn", "D": "crit", "E": "crit", "F": "crit", "": "ok"} {
		if got := probeSeverity(g); got != want {
			t.Errorf("probeSeverity(%q) = %s, want %s", g, got, want)
		}
	}
}

func TestProbeEpisodes(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	at := func(h, m, s int) int64 { return time.Date(2026, 10, 22, h, m, s, 0, ist).Unix() }
	type want struct {
		start, end int64
		readings   int
		peak       float64
		hint       string // substring
	}
	cases := []struct {
		name string
		ts   []int64
		val  []float64
		want []want
	}{
		{
			name: "single hourly probe is one reading at its own time, not a 45-min stretch",
			ts:   []int64{at(11, 0, 28), at(12, 0, 29), at(13, 0, 27)},
			val:  []float64{3, 42, 4},
			want: []want{{at(12, 0, 29), at(12, 0, 29) + probeStep, 1, 42, "single probe reading at 12:00"}},
		},
		{
			name: "consecutive bad readings collapse into one stretch",
			ts:   []int64{at(14, 0, 0), at(15, 0, 0), at(16, 0, 0), at(17, 0, 0)},
			val:  []float64{35, 60, 45, 2},
			want: []want{{at(14, 0, 0), at(16, 0, 0) + probeStep, 3, 60, "3 probe readings in a row from 14:00 to 16:00"}},
		},
		{
			name: "bad 20:00 run and bad next-morning run are separate episodes",
			ts:   []int64{at(19, 0, 0), at(20, 0, 0), at(20, 0, 0) + 15*3600},
			val:  []float64{1, 33, 38},
			want: []want{
				{at(20, 0, 0), at(20, 0, 0) + probeStep, 1, 33, "single probe reading at 20:00"},
				{at(20, 0, 0) + 15*3600, at(20, 0, 0) + 15*3600 + probeStep, 1, 38, "single probe reading at 11:00"},
			},
		},
		{
			name: "threshold is exclusive",
			ts:   []int64{at(11, 0, 0)},
			val:  []float64{bloatThresholdMS},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eps := probeEpisodes(vm.Series{TS: c.ts, Val: c.val}, "download", ist)
			if len(eps) != len(c.want) {
				t.Fatalf("got %d episodes %+v, want %d", len(eps), eps, len(c.want))
			}
			for i, w := range c.want {
				e := eps[i]
				if e.Start != w.start || e.End != w.end || e.Readings != w.readings || e.PeakMS != w.peak ||
					e.Source != "probe" || e.Direction != "download" || !strings.Contains(e.Hint, w.hint) {
					t.Errorf("episode %d = %+v, want start %d end %d readings %d peak %v hint ~%q", i, e, w.start, w.end, w.readings, w.peak, w.hint)
				}
			}
		})
	}
}
