// Package tzloc resolves the time zone the monitor uses for calendar-day
// boundaries (reports, per-client usage files) and for the probe schedule
// in health checks.
//
// The router this runs on typically has no usable zoneinfo: OpenWrt keeps
// its zone as a POSIX TZ string in /etc/TZ (e.g. "IST-5:30") and in uci
// (system.@system[0].timezone), with the IANA name in
// system.@system[0].zonename. Go ignores /etc/TZ and cannot parse POSIX
// strings from $TZ, so without help the process silently runs on UTC and
// every "day" starts at 05:30 IST. Load accepts either form; the binary
// embeds the IANA database (time/tzdata, imported by main) so zone names
// work without /usr/share/zoneinfo.
package tzloc

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Load resolves name to a location. Accepted forms:
//
//	""  or "Local"       the process' local zone (time.Local)
//	"UTC", "Asia/Kolkata" IANA names (time.LoadLocation); spaces as
//	                      written by LuCI ("America/New York") are accepted
//	"IST-5:30", "<+0530>-5:30", "UTC0"
//	                      POSIX TZ strings WITHOUT a DST rule, as found in
//	                      OpenWrt's /etc/TZ. The sign is POSIX-inverted:
//	                      "IST-5:30" is UTC+05:30.
//
// POSIX strings with a DST part (e.g. "CET-1CEST,M3.5.0,M10.5.0/3") are
// rejected rather than silently mis-handled for half the year; use the
// IANA name for such zones.
func Load(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "Local" {
		return time.Local, nil
	}
	if loc, err := time.LoadLocation(name); err == nil {
		return loc, nil
	}
	// LuCI's zone list (uci zonename) writes "America/New York" for the
	// IANA "America/New_York".
	if strings.Contains(name, " ") {
		if loc, err := time.LoadLocation(strings.ReplaceAll(name, " ", "_")); err == nil {
			return loc, nil
		}
	}
	if loc, ok := parsePOSIX(name); ok {
		return loc, nil
	}
	return nil, fmt.Errorf("unknown time zone %q (use an IANA name such as Asia/Kolkata or a fixed POSIX string such as IST-5:30)", name)
}

// parsePOSIX parses a POSIX TZ string with a standard-time part only.
func parsePOSIX(s string) (*time.Location, bool) {
	s = strings.TrimPrefix(s, ":")
	// Zone abbreviation: <...> or 3+ letters.
	var abbr, rest string
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end < 2 {
			return nil, false
		}
		abbr, rest = s[1:end], s[end+1:]
	} else {
		i := 0
		for i < len(s) && (s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
			i++
		}
		if i < 3 {
			return nil, false
		}
		abbr, rest = s[:i], s[i:]
	}
	if rest == "" {
		return nil, false
	}
	// Offset: [+-]hh[:mm[:ss]], nothing after it (no DST rule).
	sign := 1
	switch rest[0] {
	case '+':
		rest = rest[1:]
	case '-':
		sign = -1
		rest = rest[1:]
	}
	parts := strings.Split(rest, ":")
	if len(parts) > 3 {
		return nil, false
	}
	secs := 0
	mult := []int{3600, 60, 1}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || len(p) == 0 || len(p) > 2 || (i == 0 && n > 24) || (i > 0 && n > 59) {
			return nil, false
		}
		secs += n * mult[i]
	}
	// POSIX offsets are west-positive; Go's are east-positive.
	return time.FixedZone(abbr, -sign*secs), true
}
