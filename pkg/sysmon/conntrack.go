package sysmon

// Conntrack monitoring from /proc only — no netlink, no external tools.
//
// Counter semantics (kernel 6.x /proc/net/stat/nf_conntrack, hex per CPU):
//   - drop + early_drop rise when the table is genuinely full and entries
//     are being evicted to make room — that is real exhaustion.
//   - insert_failed also counts benign NAT/UDP clash races on healthy
//     routers, so it is reported but never treated as exhaustion by itself.

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"sync"
	"time"
)

// ConnState is the latest conntrack snapshot.
type ConnState struct {
	Count            int64   // entries in use
	Max              int64   // table capacity
	Util             float64 // count/max * 100
	DropRate         float64 // drop + early_drop per second (real exhaustion)
	InsertFailedRate float64 // insert_failed per second (clash races, warn only)
	At               time.Time
}

// ConnPoller refreshes the conntrack snapshot every 30 seconds.
type ConnPoller struct {
	mu       sync.RWMutex
	st       ConnState
	prevDrop uint64
	prevFail uint64
	prevOK   bool
}

// NewConntrack starts the poller with a synchronous first snapshot.
func NewConntrack(ctx context.Context) *ConnPoller {
	p := &ConnPoller{}
	p.refresh()
	go p.loop(ctx)
	return p
}

// Snapshot returns the latest known conntrack state.
func (p *ConnPoller) Snapshot() ConnState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.st
}

func (p *ConnPoller) loop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
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

func (p *ConnPoller) refresh() {
	st := ConnState{At: time.Now()}

	// Table capacity and current use.
	if v, err := readInt("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		st.Count = v
	}
	if v, err := readInt("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil && v > 0 {
		st.Max = v
		st.Util = float64(st.Count) / float64(v) * 100
	}

	// Per-CPU failure counters; every column is a hex counter and each line
	// after the header is one CPU.
	drop, failed, ok := readConntrackStat()
	if ok {
		st.DropRate, st.InsertFailedRate = 0, 0
		if p.prevOK {
			if dt := st.At.Sub(p.st.At).Seconds(); dt > 0 {
				st.DropRate = diffRate(drop, p.prevDrop, dt)
				st.InsertFailedRate = diffRate(failed, p.prevFail, dt)
			}
		}
		p.prevDrop, p.prevFail, p.prevOK = drop, failed, true
	}

	p.mu.Lock()
	p.st = st
	p.mu.Unlock()
}

func diffRate(cur, prev uint64, dt float64) float64 {
	if cur < prev { // counter reset (module reload)
		return 0
	}
	return float64(cur-prev) / dt
}

func readInt(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(string(trimBytes(b)), 10, 64)
}

func trimBytes(b []byte) []byte {
	// strip trailing whitespace/newline
	end := len(b)
	for end > 0 && (b[end-1] == '\n' || b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r') {
		end--
	}
	return b[:end]
}

// readConntrackStat sums the drop+early_drop and insert_failed columns
// across all CPUs. Column indexes come from the header line so kernel
// column-order changes do not silently misread.
func readConntrackStat() (drop uint64, failed uint64, ok bool) {
	f, err := os.Open("/proc/net/stat/nf_conntrack")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	dropIdx, failIdx, earlyIdx := -1, -1, -1
	for sc.Scan() {
		fields := splitFields(sc.Text())
		if dropIdx < 0 {
			// header row: find our columns
			for i, name := range fields {
				switch name {
				case "drop":
					dropIdx = i
				case "insert_failed":
					failIdx = i
				case "early_drop":
					earlyIdx = i
				}
			}
			if dropIdx < 0 {
				return 0, 0, false
			}
			continue
		}
		if dropIdx < len(fields) {
			drop += hexVal(fields[dropIdx])
			if earlyIdx >= 0 && earlyIdx < len(fields) {
				drop += hexVal(fields[earlyIdx])
			}
			if failIdx >= 0 && failIdx < len(fields) {
				failed += hexVal(fields[failIdx])
			}
		}
	}
	return drop, failed, true
}

func hexVal(s string) uint64 {
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return v
}

func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
