// Package wan tracks the ISP (PPPoE) session state by polling ubus every
// 15 seconds. This answers the "is the line actually established, or did the
// ISP drop it again?" question — which interface counters cannot, because a
// freshly re-established session looks healthy from the outside.
package wan

import (
	"context"
	"encoding/json"
	"os/exec"
	"sync"
	"time"
)

// State is the latest PPPoE session snapshot from ubus.
type State struct {
	Available bool   // ubus answered for network.interface.wan
	Up        bool   // PPPoE session established
	Proto     string // normally "pppoe"
	UptimeSec float64
	Addr      string // WAN address (often CGNAT on this network)
	At        time.Time
}

// Poller periodically refreshes the session snapshot.
type Poller struct {
	mu    sync.RWMutex
	state State
}

// ubusStatus mirrors the fields we need from
// `ubus call network.interface.wan status`.
type ubusStatus struct {
	Up     bool   `json:"up"`
	Proto  string `json:"proto"`
	Uptime int64  `json:"uptime"`
	IPv4   []struct {
		Address string `json:"address"`
	} `json:"ipv4-address"`
}

// New creates the poller, takes the first snapshot synchronously and then
// refreshes every 15s until ctx is done.
func New(ctx context.Context) *Poller {
	p := &Poller{}
	p.refresh()
	go p.loop(ctx)
	return p
}

// Snapshot returns the latest known session state.
func (p *Poller) Snapshot() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *Poller) loop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh()
		}
	}
}

func (p *Poller) refresh() {
	st := State{At: time.Now()}
	out, err := exec.Command("ubus", "call", "network.interface.wan", "status").Output()
	if err == nil {
		var s ubusStatus
		if json.Unmarshal(out, &s) == nil {
			st.Available = true
			st.Up = s.Up
			st.Proto = s.Proto
			st.UptimeSec = float64(s.Uptime)
			if len(s.IPv4) > 0 {
				st.Addr = s.IPv4[0].Address
			}
		}
	}
	p.mu.Lock()
	p.state = st
	p.mu.Unlock()
}
