package health

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyProbeSchedule(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	// Oct 22 hh:mm IST; day 21 = the previous evening.
	at := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, ist) }
	cases := []struct {
		name string
		now  time.Time
		last time.Time
		have bool
		want probeFreshness
	}{
		{"midday, last hourly run 20 min ago", at(22, 15, 20), at(22, 15, 0), true, probeFresh},
		{"midday, one run missing", at(22, 15, 31), at(22, 14, 0), true, probeStale},
		{"within grace of a slot", at(22, 15, 25), at(22, 14, 0), true, probeFresh},
		// The old wall-clock rule warned "stale — check cron entry" at
		// 21:30–22:00 even though 20:00 is the last scheduled run.
		{"21:45 after the 20:00 run", at(22, 21, 45), at(22, 20, 0), true, probeLast},
		{"20:45 after the 20:00 run", at(22, 20, 45), at(22, 20, 0), true, probeFresh},
		{"20:45 with the 20:00 run missing", at(22, 20, 45), at(22, 19, 0), true, probeStale},
		// The old 2 h lookback reported "no probe data yet" all night.
		{"23:30, last run 20:00", at(22, 23, 30), at(22, 20, 0), true, probeLast},
		{"03:00, last run yesterday 20:00", at(22, 3, 0), at(21, 20, 0), true, probeLast},
		{"11:20, first run not due yet", at(22, 11, 20), at(21, 20, 0), true, probeLast},
		{"11:35, first run of the day missing", at(22, 11, 35), at(21, 20, 0), true, probeStale},
		{"11:35, first run done", at(22, 11, 35), at(22, 11, 0), true, probeFresh},
		{"morning, whole previous evening missing", at(22, 9, 0), at(21, 15, 0), true, probeStale},
		{"nothing in the lookback", at(22, 9, 0), time.Time{}, false, probeNone},
		{"sample stamped a little early is fine", at(22, 13, 40), at(22, 12, 58), true, probeFresh},
	}
	for _, c := range cases {
		if got := classifyProbe(c.now, c.last, c.have); got != c.want {
			t.Errorf("%s: classifyProbe = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestClassifyProbeUsesNowZone(t *testing.T) {
	// The same instants judged in UTC instead of IST: 16:15 UTC is 21:45
	// IST. A UTC process sees 16:15, inside the window, with the 20:00 IST
	// (14:30 UTC) run 1h45m old — stale. Hence the -tz flag.
	ist := time.FixedZone("IST", 5*3600+30*60)
	now := time.Date(2026, 10, 22, 21, 45, 0, 0, ist)
	last := time.Date(2026, 10, 22, 20, 0, 0, 0, ist)
	if got := classifyProbe(now, last, true); got != probeLast {
		t.Errorf("IST: %d, want probeLast", got)
	}
	if got := classifyProbe(now.UTC(), last, true); got != probeStale {
		t.Errorf("UTC: %d, want probeStale (documents the zone dependency)", got)
	}
}

func TestProbeOffScheduleCheck(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	now := time.Date(2026, 10, 22, 7, 0, 0, 0, ist)
	last := time.Date(2026, 10, 21, 20, 0, 31, 0, ist).UTC() // zone of the sample must not matter
	c := probeOffScheduleCheck("Latency under load", probeLast, now, last, 1.25, "A")
	if c.State != StateOK || c.Value != "+1.2 ms (last)" && c.Value != "+1.3 ms (last)" {
		t.Errorf("last: %+v", c)
	}
	if !strings.Contains(c.Detail, "last night's probe") || !strings.Contains(c.Detail, "at 20:00") || !strings.Contains(c.Detail, "next at 11:00") {
		t.Errorf("last detail = %q", c.Detail)
	}
	c = probeOffScheduleCheck("x", probeStale, time.Date(2026, 10, 22, 15, 40, 0, 0, ist), time.Date(2026, 10, 22, 13, 0, 0, 0, ist), 0, "")
	if c.State != StateWarn || !strings.Contains(c.Detail, "due at 15:00") {
		t.Errorf("stale: %+v", c)
	}
	c = probeOffScheduleCheck("x", probeNone, now, time.Time{}, 0, "")
	if c.State != StateUnknown || !strings.Contains(c.Detail, "26 h") {
		t.Errorf("none: %+v", c)
	}
}
