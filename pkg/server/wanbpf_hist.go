package server

import (
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/wanbpf"
)

// wanbpfHist keeps minute-resolution samples of the eBPF latency views
// (queue delay, per-device passive RTT) so the Trends tab can chart the
// last 24 hours without an external time-series store. The live 5 s
// windows on the SQM tab answer "who is slow right now"; this ring
// answers "when, and how often" — the intermittent 10-second path
// spikes a live window misses between looks.
//
// One point per minute caps the ring at 1440 points per day; each
// point carries only the devices with samples in that minute.

type wanbpfHistDev struct {
	Mac      string `json:"mac"`
	WinAvgNs uint64 `json:"win_avg_ns"` // windowed mean RTT
	MaxNs    uint64 `json:"max_ns"`     // windowed worst RTT
	WinCount uint64 `json:"win_count"`  // samples in the window
}

type wanbpfHistPoint struct {
	T      int64           `json:"t"` // unix seconds
	QAvgNs uint64          `json:"q_avg_ns"`
	QMaxNs uint64          `json:"q_max_ns"`
	QCount uint64          `json:"q_count"`
	Devs   []wanbpfHistDev `json:"devs"`
}

type wanbpfRing struct {
	mu     sync.Mutex
	points []wanbpfHistPoint
	cap    int
}

func newWanbpfRing(capacity int) *wanbpfRing {
	if capacity < 2 {
		capacity = 2
	}
	return &wanbpfRing{cap: capacity}
}

// add appends one sample, dropping the oldest past capacity.
func (r *wanbpfRing) add(p wanbpfHistPoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.points = append(r.points, p)
	if n := len(r.points); n > r.cap {
		copy(r.points, r.points[n-r.cap:])
		r.points = r.points[:r.cap]
	}
}

// all returns the retained samples, oldest first.
func (r *wanbpfRing) all() []wanbpfHistPoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]wanbpfHistPoint, len(r.points))
	copy(out, r.points)
	return out
}

// wanbpfHistCap is 24 h at one sample per minute.
const wanbpfHistCap = 24 * 60

// recordWanbpfHistory samples one snapshot into the ring. The poller
// ticks every 5 s; only every twelfth read lands in the ring, so the
// per-device window between recorded reads covers a full minute.
func (s *Server) recordWanbpfHistory(snap *wanbpf.Snapshot) {
	if s.wanbpfHist == nil || snap == nil {
		return
	}
	p := wanbpfHistPoint{
		T:      time.Now().Unix(),
		QAvgNs: snap.QAvgNs,
		QMaxNs: snap.QMaxNs,
		QCount: snap.QCount,
	}
	for _, r := range snap.Srtt {
		if r.WinCount == 0 {
			continue // nothing measured in this window
		}
		p.Devs = append(p.Devs, wanbpfHistDev{
			Mac:      r.Mac,
			WinAvgNs: r.WinAvgNs,
			MaxNs:    r.MaxNs,
			WinCount: r.WinCount,
		})
	}
	s.wanbpfHist.add(p)
}
