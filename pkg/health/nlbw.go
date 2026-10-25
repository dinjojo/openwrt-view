package health

import (
	"context"
	"fmt"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// evalAccounting watches nlbwmon's per-device accounting. nlbwmon's netlink
// feed can silently stall (observed live: every client counter frozen at a
// byte-identical value for 5+ hours while the WAN carried gigabytes) without
// the process dying — so "is nlbwmon running" is not enough. The tell is a
// divergence: real WAN volume but zero movement in the summed client
// counters. When this happens every per-device panel (usage donut, top
// clients, per-client history) silently reads 0, so it deserves a warning.
func evalAccounting(ctx context.Context, client *vm.Client) Check {
	name := "Per-device accounting"
	if client == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1, Detail: "VictoriaMetrics not configured"}
	}

	const lookback = `[10m]`
	wanQ := `sum(increase(node_network_receive_bytes_total{device="pppoe-wan"}` + lookback + `))` +
		` + sum(increase(node_network_transmit_bytes_total{device="pppoe-wan"}` + lookback + `))`
	cliQ := `sum(increase(client_bytes_total` + lookback + `))`

	wanPts, err := client.Query(ctx, wanQ)
	if err != nil || len(wanPts) == 0 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "WAN byte query failed — cannot verify per-device accounting"}
	}
	cliPts, err := client.Query(ctx, cliQ)
	if err != nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "client counter query failed: " + err.Error()}
	}
	var wanBytes, cliBytes float64
	for _, p := range wanPts {
		wanBytes += p.Val
	}
	for _, p := range cliPts {
		cliBytes += p.Val
	}

	// A quiet WAN proves nothing either way — do not cry wolf on an idle
	// network. 5 MB over 10 minutes (~70 kbit/s average) is noise-level.
	if wanBytes < 5e6 {
		return Check{Name: name, State: StateOK, Value: "idle", NumState: 0,
			Detail: "WAN was nearly silent over the last 10 minutes — not enough traffic to verify per-device accounting"}
	}
	if cliBytes < 1024 {
		return Check{Name: name, State: StateWarn, Value: "stuck", NumState: 1,
			Detail: fmt.Sprintf("the WAN moved %s in the last 10 minutes but no client counter moved at all — nlbwmon's accounting is stuck (usage panels will show 0 for every device). It usually recovers with: /etc/init.d/nlbwmon restart",
				fmtBytes(wanBytes))}
	}
	return Check{Name: name, State: StateOK, Value: "live", NumState: 0,
		Detail: fmt.Sprintf("nlbwmon is attributing traffic per device — %s crossed the WAN in the last 10 minutes and the client counters tracked it", fmtBytes(wanBytes))}
}

// fmtBytes renders a byte count in the friendliest decimal unit.
func fmtBytes(b float64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0f KB", b/1e3)
	}
	return fmt.Sprintf("%.0f B", b)
}
