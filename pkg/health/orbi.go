package health

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/orbi"
)

// evalOrbi checks the WiFi AP (Netgear Orbi in AP mode): reachable, its
// admin page not permanently locked, and poll data fresh. The AP is the
// radio path for every wireless client — if it hangs, Wi-Fi is down even
// though the router itself looks healthy.
func evalOrbi(op *orbi.Poller) Check {
	const name = "WiFi AP"
	st := op.Snapshot()

	if !st.Reachable {
		return Check{Name: name, State: StateCrit, Value: "no response", NumState: 2,
			Detail: "the Orbi AP is not responding on the network — wireless devices lose connectivity"}
	}
	if !st.At.IsZero() && time.Since(st.At) > 10*time.Minute {
		return Check{Name: name, State: StateWarn, Value: "stale", NumState: 1,
			Detail: fmt.Sprintf("no fresh data from the AP for %s — poll blocked or AP degraded", time.Since(st.At).Round(time.Minute))}
	}

	wifi := 0
	for _, d := range st.Devices {
		if d.ConnType == "2.4G" || d.ConnType == "5G" {
			wifi++
		}
	}

	detail := fmt.Sprintf("%s (firmware %s) reachable — %d device(s) attached, %d on Wi-Fi",
		orbiLabel(st), st.Firmware, len(st.Devices), wifi)
	if st.Busy {
		detail += " — its device list is unavailable right now, showing the last known devices"
	}
	return Check{Name: name, State: StateOK, Value: fmt.Sprintf("%d devices", len(st.Devices)), Detail: detail, NumState: 0}
}

func orbiLabel(st orbi.State) string {
	if st.Model != "" {
		return st.Model
	}
	return "Orbi AP"
}

// evalWifiSignal watches the weakest client on the mesh. A single client
// far from the AP drags its own experience; only severe weakness signals
// a placement or interference problem worth acting on.
func evalWifiSignal(op *orbi.Poller) Check {
	const name = "Wi-Fi signal"
	st := op.Snapshot()
	if st.Busy || len(st.Devices) == 0 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "no fresh Wi-Fi device list from the AP"}
	}
	weakest := -1
	who := ""
	band := ""
	for _, d := range st.Devices {
		if d.ConnType != "2.4G" && d.ConnType != "5G" {
			continue
		}
		if weakest == -1 || d.Signal < weakest {
			weakest, who, band = d.Signal, d.Name, d.ConnType
		}
	}
	if weakest == -1 {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "no wireless clients are connected right now"}
	}
	// Randomized-MAC devices have no resolvable name; say so instead of the
	// bare "unknown", and give the MAC prefix so the owner can match it.
	whoLabel := who
	if who == "" || who == "unknown" {
		if d := st.Devices; len(d) > 0 {
			for _, dev := range d {
				if dev.ConnType != "2.4G" && dev.ConnType != "5G" {
					continue
				}
				if dev.Signal == weakest && (dev.Name == "" || dev.Name == "unknown") {
					mac := strings.ToUpper(dev.MAC)
					if len(mac) > 8 {
						mac = mac[:8]
					}
					whoLabel = "an unnamed device (" + mac + "…, randomized MAC)"
					break
				}
			}
		}
	}
	if whoLabel == "" || whoLabel == "unknown" {
		whoLabel = "an unnamed device"
	}
	detail := "weakest client is " + whoLabel + " on " + bandLabel(band) +
		" — for reference, 70%+ is strong, 50–70% is usable, below 50% shows in slow speeds and dropouts"
	if weakest < 35 {
		return Check{Name: name, State: StateCrit, Value: strconv.Itoa(weakest) + "%", Detail: detail, NumState: 2}
	}
	if weakest < 50 {
		return Check{Name: name, State: StateWarn, Value: strconv.Itoa(weakest) + "%", Detail: detail, NumState: 1}
	}
	return Check{Name: name, State: StateOK, Value: strconv.Itoa(weakest) + "%", Detail: detail, NumState: 0}
}

func bandLabel(ct string) string {
	if ct == "2.4G" {
		return "2.4 GHz"
	}
	return "5 GHz"
}
