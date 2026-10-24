package health

import (
	"fmt"
	"sync/atomic"
	"time"
)

// The bufferbloat probe runs from cron hourly at probeFirstHour:00 …
// probeLastHour:00 (11:00–20:00). The probe's freshness is judged against
// that schedule, not against a fixed age, so the check stays right at
// night and in the morning before the first run.
//
// ASSUMPTION: the hours are in the schedule zone (SetLocation, i.e. the
// -tz flag / OPENWRT_VIEW_TZ, else the process local zone), and that zone matches
// the one crond runs in. On OpenWrt crond follows the router's system zone;
// the init script passes the same zone to the monitor as OPENWRT_VIEW_TZ. If the
// two disagree, the check misjudges the window by the zone difference
// (e.g. a UTC monitor and an IST cron are 5h30m apart).
const (
	probeFirstHour = 11
	probeLastHour  = 20
	// probeGrace is how long after a scheduled slot the result may take
	// to appear (probe run time + push + the 60 s poll) before the slot
	// counts as expected.
	probeGrace = 30 * time.Minute
	// probeSlack tolerates a sample stamped slightly before its slot
	// (cron firing early, clock adjustments).
	probeSlack = 5 * time.Minute
	// probeLookback is how far back the last probe is searched: enough to
	// reach the previous evening's last run from anywhere in the night or
	// morning (20:00 → next 11:30 is 15h30m) with room for a missed day.
	probeLookback = 26 * time.Hour
)

var scheduleLoc atomic.Pointer[time.Location]

// SetLocation sets the zone the probe cron schedule is read in. Call
// before Eval runs; defaults to time.Local.
func SetLocation(loc *time.Location) {
	if loc != nil {
		scheduleLoc.Store(loc)
	}
}

func schedLoc() *time.Location {
	if l := scheduleLoc.Load(); l != nil {
		return l
	}
	return time.Local
}

// lastScheduledRun returns the most recent cron slot (hh:00 for hh in
// probeFirstHour..probeLastHour, in t's zone) at or before t.
func lastScheduledRun(t time.Time) time.Time {
	y, m, d := t.Date()
	h := t.Hour()
	switch {
	case h < probeFirstHour:
		return time.Date(y, m, d-1, probeLastHour, 0, 0, 0, t.Location())
	case h > probeLastHour:
		return time.Date(y, m, d, probeLastHour, 0, 0, 0, t.Location())
	default:
		return time.Date(y, m, d, h, 0, 0, 0, t.Location())
	}
}

// probeFreshness classifies the newest probe result against the schedule.
type probeFreshness int

const (
	probeNone  probeFreshness = iota // no result within probeLookback
	probeFresh                       // recent enough to grade the line now
	probeLast                        // old, but no run was due since: night / before the first run
	probeStale                       // a scheduled run is missing
)

// classifyProbe judges the newest probe sample (at last; have=false when
// none was found within probeLookback) at time now. now's zone must be
// the schedule zone.
func classifyProbe(now, last time.Time, have bool) probeFreshness {
	if !have {
		return probeNone
	}
	expected := lastScheduledRun(now.Add(-probeGrace))
	if last.Before(expected.Add(-probeSlack)) {
		return probeStale
	}
	if now.Sub(last) <= probeAgeLimit {
		return probeFresh
	}
	return probeLast
}

// probeOffScheduleCheck renders the non-fresh verdicts. value/grade are
// the newest probe result.
func probeOffScheduleCheck(name string, f probeFreshness, now, last time.Time, bloat float64, grade string) Check {
	switch f {
	case probeNone:
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: fmt.Sprintf("no probe result in the last %d h — probes run hourly %02d:00–%02d:00; if this persists, check the cron entry",
				int(probeLookback.Hours()), probeFirstHour, probeLastHour)}
	case probeStale:
		expected := lastScheduledRun(now.Add(-probeGrace))
		return Check{Name: name, State: StateWarn, Value: "stale", NumState: 1,
			Detail: fmt.Sprintf("last probe ran %s ago, but a run was due at %s — check cron entry",
				now.Sub(last).Round(time.Minute), expected.Format("15:04"))}
	}
	if bloat < 0 {
		bloat = 0
	}
	last = last.In(now.Location())
	which := "this evening's probe"
	if ly, lm, ld := last.Date(); ly != now.Year() || lm != now.Month() || ld != now.Day() {
		which = "last night's probe"
	}
	val := fmtBloat(bloat)
	gtxt := ""
	if grade != "" {
		gtxt = ", grade " + grade
	}
	return Check{Name: name, State: StateOK, Value: val + " (last)", NumState: 0,
		Detail: fmt.Sprintf("ok (%s: %s%s at %s) — probes run %02d:00–%02d:00 only, next at %02d:00",
			which, val, gtxt, last.Format("15:04"), probeFirstHour, probeLastHour, nextRunHour(now))}
}

// nextRunHour is the hour of the next scheduled probe after now.
func nextRunHour(now time.Time) int {
	if h := now.Hour(); h >= probeFirstHour && h < probeLastHour {
		return h + 1
	}
	return probeFirstHour
}
