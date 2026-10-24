package health

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/wan"
)

// dnsProber runs end-to-end DNS checks against the local resolver. Probing
// DNS the way a client does needs no AdGuard credentials, no access to query
// logs (privacy) and exercises the exact path the household's devices use.
type dnsProber struct {
	resolver *net.Resolver
}

func newDNSProber(server string) *dnsProber {
	return &dnsProber{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Force every lookup through the local resolver (AdGuard).
				var d net.Dialer
				return d.DialContext(ctx, network, server)
			},
		},
	}
}

// lookup resolves host and returns elapsed milliseconds.
func (p *dnsProber) lookup(host string) ([]net.IPAddr, error, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	ips, err := p.resolver.LookupIPAddr(ctx, host)
	return ips, err, time.Since(start)
}

// evalDNS answers the question "does name resolution work, is filtering on,
// and is it fast?" — DNS is a frequent cause of "the internet feels slow
// even though bandwidth and latency are fine".
func evalDNS(p *dnsProber) Check {
	name := "DNS & ad-blocking"
	// 1. A real name must resolve — if this fails, the network feels broken
	// no matter how good the bandwidth is.
	ips, err, ms := p.lookup("wikipedia.org")
	if err != nil || len(ips) == 0 {
		return Check{Name: name, State: StateCrit, Value: "failing",
			Detail: "the local resolver could not resolve a common website — DNS is down or timing out; pages will hang even though bandwidth is fine", NumState: 2}
	}

	// 2. A canary domain the user's own AdGuard rules deliberately block.
	// "Blocked" can appear as an NXDOMAIN error, an empty answer, or a
	// 0.0.0.0 / 127.0.0.1 sinkhole. Testing a user rule verifies the whole
	// filtering pipeline is enforcing blocks.
	adIPs, adErr, _ := p.lookup("updates.amazon.com")
	blocked := adErr != nil || len(adIPs) == 0
	for _, ip := range adIPs {
		if ip.IP.Equal(net.IPv4zero) || ip.IP.Equal(net.ParseIP("127.0.0.1")) {
			blocked = true
		}
	}
	if !blocked {
		return Check{Name: name, State: StateWarn, Value: fmt.Sprintf("%.0f ms", ms.Seconds()*1000),
			Detail: "names resolve, but blocking rules are not taking effect — AdGuard Home filtering may be off (ads and blocked services would go through)", NumState: 1}
	}

	// 3. Resolution speed: normal local answers are single-digit ms.
	state := StateOK
	detail := fmt.Sprintf("names resolve in %.0f ms and blocking rules are enforced — AdGuard Home is doing its job", ms.Seconds()*1000)
	if ms > 200*time.Millisecond {
		state = StateWarn
		detail = fmt.Sprintf("DNS answers take %.0f ms — slow enough to make every page feel laggy; check AdGuard upstreams or caching", ms.Seconds()*1000)
	}
	return Check{Name: name, State: state, Value: fmt.Sprintf("%.0f ms", ms.Seconds()*1000),
		Detail: detail, NumState: numState(state)}
}

// humanUp renders an uptime in the largest sensible units — "5h 12m",
// "4d 21h", "3mo 12d" — never raw hours past a day. Go's Duration string
// prints "117h11m0s", which reads like a bug report, not a status line.
func humanUp(d time.Duration) string {
	s := int64(d / time.Second)
	const min, hr, day = 60, 3600, 86400
	const month, year = 30 * 86400, 365 * 86400
	switch {
	case s < min:
		return fmt.Sprintf("%ds", s)
	case s < hr:
		return fmt.Sprintf("%dm", s/min)
	case s < day:
		return fmt.Sprintf("%dh %dm", s/hr, (s%hr)/min)
	case s < month:
		return fmt.Sprintf("%dd %dh", s/day, (s%day)/hr)
	case s < year:
		return fmt.Sprintf("%dmo %dd", s/month, (s%month)/day)
	default:
		return fmt.Sprintf("%dy %dmo", s/year, (s%year)/month)
	}
}

// evalPPPoE watches the ISP session itself: whether it is established, how
// long it has been up, and whether it recently flapped.
func evalPPPoE(snap wan.State) Check {
	name := "ISP session"
	if !snap.Available {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "cannot read PPPoE state (ubus unavailable)"}
	}
	if !snap.Up {
		return Check{Name: name, State: StateCrit, Value: "down",
			Detail: "the PPPoE session is DOWN — the ISP link is disconnected or authentication failed", NumState: 2}
	}
	d := time.Duration(snap.UptimeSec) * time.Second
	val := "up " + humanUp(d)
	if d < 10*time.Minute {
		return Check{Name: name, State: StateWarn, Value: val,
			Detail: fmt.Sprintf("the session was re-established %s ago — the ISP link dropped recently; frequent repeats mean an ISP stability problem", d.Round(time.Second)), NumState: 1}
	}
	detail := "PPPoE session established for " + humanUp(d)
	if snap.Addr != "" {
		detail += fmt.Sprintf(" — WAN address %s (carrier-grade NAT: address changes are normal, instability shows up here as short uptimes)", snap.Addr)
	}
	return Check{Name: name, State: StateOK, Value: val, Detail: detail, NumState: 0}
}
