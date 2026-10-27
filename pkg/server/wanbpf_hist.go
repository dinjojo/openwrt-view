package server

import (
	"sort"
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/wanbpf"
)

// wanbpfHist keeps minute-resolution samples of the eBPF latency views
// (queue delay, per-device passive RTT) so the Trends tab can chart the
// last 24 hours without an external time-series store. The live 5 s
// windows on the SQM tab answer "who is slow right now"; this ring
// answers "when, and how often" — the intermittent 10-second path
// spikes a live window misses between looks. One ring point aggregates
// twelve consecutive 5 s windows (a full minute): count and mean are
// the minute's totals and weighted mean, max is the worst window.
//
// One point per minute caps the ring at 1440 points per day; each
// point carries only the devices with samples in that minute.

type wanbpfHistDev struct {
	Mac      string `json:"mac"`
	WinAvgNs uint64 `json:"win_avg_ns"` // minute's RTT mean
	MaxNs    uint64 `json:"max_ns"`     // worst RTT in the minute
	WinCount uint64 `json:"win_count"`  // samples in the minute
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

// wanbpfAgg accumulates twelve consecutive 5 s poller reads so one
// ring point covers a full minute. Owned by the poller goroutine —
// the HTTP handler reads only through the ring's lock.
type wanbpfAgg struct {
	n        uint64
	qCount   uint64
	qSumProd uint64 // sum of QAvgNs × QCount
	qMaxNs   uint64
	devs     map[string]*wanbpfAggDev
}

type wanbpfAggDev struct {
	winCount uint64
	sumProd  uint64 // sum of WinAvgNs × WinCount
	maxNs    uint64
}

// wanbpfHistEvery is the number of 5 s windows aggregated per ring point.
const wanbpfHistEvery = 12

// sampleWanbpf folds one snapshot into the minute accumulator and, on
// the twelfth read, records the aggregate into the ring.
func (s *Server) sampleWanbpf(snap *wanbpf.Snapshot) {
	if s.wanbpfHist == nil || snap == nil {
		return
	}
	if s.wanbpfAgg == nil {
		s.wanbpfAgg = &wanbpfAgg{devs: map[string]*wanbpfAggDev{}}
	}
	a := s.wanbpfAgg
	a.n++
	a.qCount += snap.QCount
	a.qSumProd += snap.QAvgNs * snap.QCount
	if snap.QMaxNs > a.qMaxNs {
		a.qMaxNs = snap.QMaxNs
	}
	for _, r := range snap.Srtt {
		if r.WinCount == 0 {
			continue // idle device this window
		}
		d := a.devs[r.Mac]
		if d == nil {
			d = &wanbpfAggDev{}
			a.devs[r.Mac] = d
		}
		d.winCount += r.WinCount
		d.sumProd += r.WinAvgNs * r.WinCount
		if r.MaxNs > d.maxNs {
			d.maxNs = r.MaxNs
		}
	}
	if a.n < wanbpfHistEvery {
		return
	}
	p := wanbpfHistPoint{T: time.Now().Unix(), QCount: a.qCount, QMaxNs: a.qMaxNs}
	if a.qCount > 0 {
		p.QAvgNs = a.qSumProd / a.qCount
	}
	for mac, d := range a.devs {
		if d.winCount == 0 {
			continue
		}
		p.Devs = append(p.Devs, wanbpfHistDev{
			Mac: mac, WinCount: d.winCount, MaxNs: d.maxNs, WinAvgNs: d.sumProd / d.winCount,
		})
	}
	sort.Slice(p.Devs, func(i, j int) bool { return p.Devs[i].WinCount > p.Devs[j].WinCount })
	s.wanbpfHist.add(p)
	a.n, a.qCount, a.qSumProd, a.qMaxNs = 0, 0, 0, 0
	a.devs = map[string]*wanbpfAggDev{}
}
