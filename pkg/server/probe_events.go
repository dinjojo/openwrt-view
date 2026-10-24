package server

import (
	"context"
	"fmt"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// probeEventWindow is how far back each poll looks for raw probe samples.
// Polls run every 60 s, so 10 minutes rides out a few failed polls.
const probeEventWindow = 600 // seconds

// probeReading is one probe run's result for one direction, stamped with
// the sample's own timestamp (the probe pushes with an explicit time).
type probeReading struct {
	TS    int64
	Bloat float64
	Grade string
}

// newestReading picks the newest raw probe_bloat_ms sample and the grade
// pushed with it (the probe_bloat_grade series with value 1 stamped at the
// same second). Inputs are raw samples from vm.QueryRaw — NOT instant or
// range query points, whose timestamps are the query/step time and keep
// moving while one sample stays visible.
func newestReading(bloat, grades []vm.Series) (probeReading, bool) {
	var r probeReading
	found := false
	for _, se := range bloat {
		for i, ts := range se.TS {
			if !found || ts > r.TS {
				r = probeReading{TS: ts, Bloat: se.Val[i]}
				found = true
			}
		}
	}
	if !found {
		return r, false
	}
	for _, se := range grades {
		for i, ts := range se.TS {
			if se.Val[i] > 0 && ts >= r.TS-1 && ts <= r.TS+1 {
				r.Grade = se.Labels["grade"]
			}
		}
	}
	return r, true
}

// probeTracker remembers, per direction, the sample time of the newest
// probe run already turned into (or judged for) an event. This is what
// keeps one probe run to one event: VictoriaMetrics keeps returning the
// same sample on every poll for minutes, and previously each poll looked
// "new" (instant queries stamp results with the query time), so a single
// bad run became an event with Count 5.
type probeTracker struct {
	since int64            // samples at or before this (monitor start) belong to an earlier process
	last  map[string]int64 // direction → newest processed sample time
}

func newProbeTracker(since int64) *probeTracker {
	return &probeTracker{since: since, last: map[string]int64{}}
}

// accept reports whether r is a probe run not yet processed for dir and,
// if so, marks it processed.
func (t *probeTracker) accept(dir string, r probeReading) bool {
	if r.TS <= t.since || r.TS <= t.last[dir] {
		return false
	}
	t.last[dir] = r.TS
	return true
}

// probeSeverity maps a probe grade to an event severity.
func probeSeverity(grade string) string {
	switch grade {
	case "C":
		return "warn"
	case "D", "E", "F":
		return "crit"
	}
	return "ok"
}

// recordProbeEvents adds one event per new probe run and direction whose
// grade is C or worse. Clean runs stay off the timeline — a "speed check
// was fine" event every hour would drown the feed. Only surprises are
// events.
func (s *Server) recordProbeEvents(ctx context.Context, t *probeTracker) {
	now := time.Now().Unix()
	for _, d := range []struct{ label, name string }{{"down", "download"}, {"up", "upload"}} {
		bloat, err := s.vmc.QueryRaw(ctx, `probe_bloat_ms{direction="`+d.label+`"}`, now-probeEventWindow, now)
		if err != nil {
			continue
		}
		grades, _ := s.vmc.QueryRaw(ctx, `probe_bloat_grade{direction="`+d.label+`"}`, now-probeEventWindow, now)
		r, ok := newestReading(bloat, grades)
		if !ok || !t.accept(d.label, r) {
			continue
		}
		if sev := probeSeverity(r.Grade); sev != "ok" {
			s.events.Add("probe", sev, fmt.Sprintf("Speed check worse than usual: grade %s, +%.1f ms under %s load", r.Grade, r.Bloat, d.name))
		}
	}
}
