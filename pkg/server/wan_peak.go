package server

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// wanPeakRing keeps per-minute maxima of the poller's 1-second WAN rates
// so the dashboard's peak row reflects true short bursts. VictoriaMetrics
// history derives peaks from counter scrapes (node_exporter every 10 s)
// through a rate() window, which averages a seconds-long full-rate burst
// down several-fold; this ring answers "how fast did it actually get" —
// the same 1 s deltas the live cards show, kept as one max per minute.
//
// One point per minute caps the ring at 1440 points per day. When a
// path is set the closed minutes are flushed to it on every minute
// roll — one small atomic write per minute — and loaded back on boot,
// so daemon restarts (upgrades, router reboots) no longer forget the
// day's true peaks.

type wanPeakPoint struct {
	T    int64   `json:"t"`    // unix seconds, floored to the minute
	Down float64 `json:"down"` // Mbit/s, worst 1 s download in the minute
	Up   float64 `json:"up"`   // Mbit/s, worst 1 s upload
}

type wanPeakRing struct {
	mu     sync.Mutex
	path   string // JSON persistence file; empty = memory-only
	points []wanPeakPoint
	cur    wanPeakPoint // current, still-open minute
}

// wanPeakCap is 24 h at one point per minute.
const wanPeakCap = 24 * 60

func newWanPeakRing() *wanPeakRing {
	return &wanPeakRing{}
}

// setPath points the ring at a JSON file and loads whatever is already
// on disk, dropping points older than the ring's 24 h span.
func (r *wanPeakRing) setPath(path string) error {
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
	return r.load()
}

// load reads persisted points back into the ring; a missing file is a
// fresh start, a corrupt one just means memory-only history.
func (r *wanPeakRing) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path == "" {
		return nil
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var pts []wanPeakPoint
	if err := json.Unmarshal(b, &pts); err != nil {
		return err
	}
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	out := pts[:0]
	for _, p := range pts {
		if p.T >= cutoff {
			out = append(out, p)
		}
	}
	r.points = out
	return nil
}

// flushLocked atomically writes the closed minutes to disk; best
// effort — a failed write only costs the next restart its history.
func (r *wanPeakRing) flushLocked() {
	if r.path == "" {
		return
	}
	b, err := json.Marshal(r.points)
	if err != nil {
		return
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, r.path)
}

// sample folds one 1-second reading into the open minute bucket,
// rolling the previous minute into the ring when the minute turns.
func (r *wanPeakRing) sample(down, up float64, now time.Time) {
	minute := now.Unix() / 60 * 60
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur.T == 0 {
		r.cur = wanPeakPoint{T: minute, Down: down, Up: up}
		return
	}
	if minute != r.cur.T {
		r.points = append(r.points, r.cur)
		if n := len(r.points); n > wanPeakCap {
			copy(r.points, r.points[n-wanPeakCap:])
			r.points = r.points[:wanPeakCap]
		}
		r.flushLocked()
		r.cur = wanPeakPoint{T: minute, Down: down, Up: up}
		return
	}
	if down > r.cur.Down {
		r.cur.Down = down
	}
	if up > r.cur.Up {
		r.cur.Up = up
	}
}

// all returns the closed minutes plus the open one, oldest first,
// trimmed to the cap so the endpoint never exceeds it.
func (r *wanPeakRing) all() []wanPeakPoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]wanPeakPoint, 0, len(r.points)+1)
	out = append(out, r.points...)
	if r.cur.T != 0 {
		out = append(out, r.cur)
	}
	if n := len(out); n > wanPeakCap {
		out = out[n-wanPeakCap:]
	}
	return out
}
