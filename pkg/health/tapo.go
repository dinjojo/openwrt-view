package health

import (
	"fmt"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/tapo"
)

// evalTapo checks the Tapo smart plug: reachable, and how long the relay has
// been on. A plug that stops answering usually means it lost Wi-Fi or power
// at the wall — worth surfacing, since whatever it controls goes dark too.
// tp may be nil (no plug configured): the check is simply omitted.
func evalTapo(tp *tapo.Poller) Check {
	const name = "Smart plug"
	if tp == nil {
		return Check{Name: name, State: StateUnknown, Value: "—", NumState: -1,
			Detail: "not configured"}
	}
	st := tp.Snapshot()

	if !st.Available {
		return Check{Name: name, State: StateCrit, Value: "no response", NumState: 2,
			Detail: "the plug is not responding — it may have dropped off Wi-Fi or lost power"}
	}

	onFor := ""
	if st.OnForS > 0 {
		onFor = fmt.Sprintf(", on for %s", (time.Duration(st.OnForS) * time.Second).Round(time.Minute))
	}
	detail := fmt.Sprintf("%s reachable — relay is %s%s", tapoLabel(st), onOff(st.On), onFor)
	if st.HasPower {
		detail += fmt.Sprintf(", drawing %.1f W", st.PowerW)
	}
	return Check{Name: name, State: StateOK, Value: onOff(st.On), Detail: detail, NumState: 0}
}

func tapoLabel(st tapo.State) string {
	if st.Name != "" {
		return st.Name
	}
	if st.Model != "" {
		return st.Model
	}
	return "Plug"
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
