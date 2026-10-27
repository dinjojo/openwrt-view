package health

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/sysmon"
)

// This file adds the sysmon-backed checks: WARP exit tunnel, clock sync and
// NVMe storage/uptime. All verdicts are plain language: they say what is
// happening and what the consequence is, without jargon.

// evalWarp judges the Cloudflare WARP exit tunnel. pbr runs with
// strict_enforcement off, so when the tunnel dies, policy-routed clients
// automatically fall back to the direct WAN line — the network keeps
// working, just through a different path. A missing wg0 interface means
// WARP is simply switched off (e.g. the Sony-TV-only tunnel was stopped),
// which is normal operation, not a problem: the check reads OK and says
// everything is on the direct line. Only an interface that is up but not
// passing traffic (no peer, no handshake) is worth a word of caution.
func evalWarp(st sysmon.WarpState) Check {
	name := "Exit path (WARP)"
	if !st.IfaceUp {
		return Check{Name: name, State: StateOK, Minor: true, Value: "direct WAN",
			Detail: "the WARP tunnel interface is not up, so all traffic exits via the direct WAN line — normal when the tunnel is switched off. This check follows it automatically if WARP is turned back on.", NumState: 0}
	}
	if !st.Available {
		return Check{Name: name, State: StateWarn, Minor: true, Value: "no peer",
			Detail: "the WARP tunnel interface is up but has no configured peer — the tunnel cannot pass traffic. Policy-routed clients fall back to the direct WAN line.", NumState: 1}
	}

	detail := func(hs time.Time) string {
		flow := "no traffic flowing right now"
		if st.RxPerS > 1024 {
			flow = fmt.Sprintf("~%s/s flowing in", humanBytes(st.RxPerS))
		}
		return fmt.Sprintf("Cloudflare WARP tunnel is healthy: last handshake %s ago, %s. Policy-routed clients exit through WARP; everything else uses the direct line. If the tunnel ever dies, those clients automatically fall back to the raw WAN and this check notes the path change.",
			trimAge(time.Since(hs)), flow)
	}

	if st.Handshake.IsZero() {
		return Check{Name: name, State: StateWarn, Minor: true, Value: "no handshake",
			Detail: "the WARP tunnel interface is up but the remote peer has never completed a handshake — the tunnel is not passing traffic. Policy-routed clients fall back to the direct WAN line.", NumState: 1}
	}

	age := time.Since(st.Handshake)
	switch {
	case age < 3*time.Minute:
		return Check{Name: name, State: StateOK, Minor: true, Value: "via WARP", Detail: detail(st.Handshake), NumState: 0}
	case age < 15*time.Minute:
		return Check{Name: name, State: StateWarn, Minor: true, Value: fmt.Sprintf("quiet %s", trimAge(age)),
			Detail: fmt.Sprintf("no WARP handshake for %s — the tunnel looks stalled. Policy-routed clients are (or will be) falling back to the direct WAN line. It may recover on its own; if not, the tunnel is down and traffic just uses the direct line.", trimAge(age)), NumState: 1}
	default:
		return Check{Name: name, State: StateWarn, Minor: true, Value: "fallback",
			Detail: fmt.Sprintf("WARP tunnel is down (no handshake for %s). Policy-routed clients have fallen back to the direct WAN line — internet keeps working, just not through the tunnel.", trimAge(age)), NumState: 1}
	}
}

// evalClock judges router clock drift against an internet time reference.
func evalClock(st sysmon.ClockState) Check {
	name := "Clock sync"
	minor := true // clock drift is cosmetic at these thresholds — pill only
	if !st.Available {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Minor: minor,
			Detail: "couldn't reach any time reference (NTP servers or HTTP endpoints) to measure clock drift"}
	}
	off := st.OffsetMs
	if off < 0 {
		off = -off
	}
	// HTTP Date headers only carry second resolution and the round trip
	// passes through the same network path, so HTTP-sourced measurements
	// get looser thresholds. Either way the question is the same: is the
	// clock wrong enough to break TLS and scheduled jobs?
	lo, hi := 100.0, 250.0
	if st.Source == "http" {
		lo, hi = 4_000.0, 60_000.0
	}
	switch {
	case off < lo:
		return Check{Name: name, State: StateOK, Minor: true,
			Value:  fmt.Sprintf("%+.0f ms", st.OffsetMs),
			Detail: fmt.Sprintf("router clock is within %.0f ms of internet time (measured against %s via %s). TLS certificates, logs and scheduled jobs all behave normally.", off, st.Server, st.Source), NumState: 0}
	case off < hi:
		return Check{Name: name, State: StateWarn, Minor: true,
			Value:  fmt.Sprintf("%+.0f ms", st.OffsetMs),
			Detail: fmt.Sprintf("router clock has drifted %.0f ms from internet time — usually NTP can't reach its servers. Some sites may throw TLS/certificate warnings on devices that trust the router's time.", off), NumState: 1}
	default:
		return Check{Name: name, State: StateCrit, Minor: true,
			Value:  fmt.Sprintf("%+.1f s", st.OffsetMs/1000),
			Detail: fmt.Sprintf("router clock has drifted %.1f seconds from internet time. Expect TLS errors, failed scheduler jobs and confusing logs until NTP re-syncs.", off/1000), NumState: 2}
	}
}

// evalStorage judges NVMe health (the disk holding the monitoring history)
// and folds in the reboot signal.
func evalStorage(st sysmon.DiskState) Check {
	name := "Storage & uptime"
	if !st.Available {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "smartmontools is not reporting for the NVMe — install it or check the device path"}
	}

	var extra string
	if st.RebootSpotted && !st.LastReboot.IsZero() {
		extra = fmt.Sprintf(" The router rebooted %s ago (noticed by the monitor via a change in boot id).", trimAge(time.Since(st.LastReboot)))
	}

	val := fmt.Sprintf("up %s", trimAge(time.Since(time.Now().Add(-time.Duration(uptimeSeconds()*float64(time.Second))))))
	// Only judge the spare when the drive actually reported it; a real 0%
	// spare is critical, an absent field is unknown (below). A set
	// critical_warning is real data and is always critical.
	spare := "spare not reported"
	if st.SpareKnown {
		spare = fmt.Sprintf("spare %.0f%%", st.AvailableSpare)
	}
	bad := st.CriticalWarning != 0 || (st.SpareKnown && st.AvailableSpare < 10)
	if bad {
		return Check{Name: name, State: StateCrit, Value: val,
			Detail: fmt.Sprintf("the NVMe holding the monitoring data reports a critical condition (critical_warning=%d, %s) — replace it before it dies and takes the history with it.%s", st.CriticalWarning, spare, extra), NumState: 2}
	}
	if st.MediaErrors > 0 {
		return Check{Name: name, State: StateWarn, Value: val,
			Detail: fmt.Sprintf("the NVMe reports %d media errors — early wear sign. Watch this chip; if the count climbs, plan a replacement.%s", st.MediaErrors, extra), NumState: 1}
	}
	if st.PercentUsed >= 90 {
		return Check{Name: name, State: StateWarn, Value: val,
			Detail: fmt.Sprintf("the NVMe has used %.0f%% of its rated write endurance. Fine for now, but plan a replacement.%s", st.PercentUsed, extra), NumState: 1}
	}
	if !st.SpareKnown {
		return Check{Name: name, State: StateUnknown, Value: val,
			Detail: fmt.Sprintf("the NVMe did not report its available spare, so its health can't be fully judged: %.0f%% write endurance used, no media errors, %.0f°C.%s%s", st.PercentUsed, st.TempC, extraStorageNotes(st), extra), NumState: -1}
	}
	return Check{Name: name, State: StateOK, Value: val,
		Detail: fmt.Sprintf("NVMe holding the monitoring data is healthy: %.0f%% write endurance used, no media errors, %.0f°C.%s%s", st.PercentUsed, st.TempC, extraStorageNotes(st), extra), NumState: 0}
}

// extraStorageNotes adds lifetime context (unclean shutdowns) when present.
func extraStorageNotes(st sysmon.DiskState) string {
	if st.UnsafeShutdowns > 0 {
		return fmt.Sprintf(" The drive has recorded %d unclean shutdowns in its life — power cuts, not corruption.", st.UnsafeShutdowns)
	}
	return ""
}

// uptimeSeconds reads /proc/uptime for the "up …" display in evalStorage.
func uptimeSeconds() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

// humanBytes renders a bytes/s rate in the largest sensible unit.
func humanBytes(bps float64) string {
	switch {
	case bps >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GiB", bps/(1024*1024*1024))
	case bps >= 1024*1024:
		return fmt.Sprintf("%.1f MiB", bps/(1024*1024))
	case bps >= 1024:
		return fmt.Sprintf("%.0f KiB", bps/1024)
	default:
		return fmt.Sprintf("%.0f B", bps)
	}
}

// trimAge shortens a duration for chip text: "56s", "3m12s" → "3m", "2d".
func trimAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%.0fm", d.Minutes())
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1fh", d.Hours())
	default:
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	}
}
