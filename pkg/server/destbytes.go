package server

import (
	"strconv"
	"strings"
	"sync"
	"time"

	fiber "github.com/gofiber/fiber/v3"

	"github.com/dinjojo/openwrt-view/pkg/ebpfacct"
	"github.com/dinjojo/openwrt-view/pkg/log"
)

// destTrack folds the eBPF per-destination byte counters into a rolling
// same-day total per device: each poll differences the monotonic kernel
// counters against the previous read and adds the window into
// map[mac][prefix]. The map resets at local midnight, so /api/usage/dests
// answers "which services did this device talk to today" — the same
// ranking Firewalla's large-bandwidth alarm shows — without per-flow
// storage. Memory is bounded by active devices × prefixes (~a few
// hundred entries); the kernel map's 2048-entry LRU cap bounds the walk.
type destTrack struct {
	mu     sync.Mutex
	day    string                         // store-zone calendar day of the totals
	totals map[string]map[string]*destTot // mac -> prefix -> totals
	fam    map[string]int                 // prefix -> address family
	prev   map[ebpfacct.DestKey]ebpfacct.DestCounters
}

type destTot struct {
	rx, tx uint64 // bytes
}

func min64u(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func newDestTrack() *destTrack {
	return &destTrack{
		totals: map[string]map[string]*destTot{},
		fam:    map[string]int{},
		prev:   map[ebpfacct.DestKey]ebpfacct.DestCounters{},
	}
}

// record folds one kernel read in. Counters are monotonic; a counter
// that went backwards (map eviction + re-insert, restart) contributes 0
// for that step instead of inventing traffic.
func (d *destTrack) record(cur map[ebpfacct.DestKey]ebpfacct.DestCounters) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, c := range cur {
		p := d.prev[k]
		if dUp := c.Up - min64u(p.Up, c.Up); dUp > 0 || c.Down > p.Down {
			d.add(strings.ToUpper(k.Mac), k.Prefix, k.Fam, c.Down-min64u(p.Down, c.Down), dUp)
		}
		d.prev[k] = c
	}
	// Drop prev entries that vanished (LRU eviction keeps the map tight).
	if len(d.prev) > 4*len(cur)+512 {
		d.prev = cur
	}
}

func (d *destTrack) add(mac, prefix string, fam int, down, up uint64) {
	day := time.Now().Format("2006-01-02")
	if d.day != day {
		d.day = day
		d.totals = map[string]map[string]*destTot{}
	}
	m := d.totals[mac]
	if m == nil {
		m = map[string]*destTot{}
		d.totals[mac] = m
	}
	t := m[prefix]
	if t == nil {
		t = &destTot{}
		m[prefix] = t
		d.fam[prefix] = fam
	}
	t.rx += down
	t.tx += up
}

// destRow is one prefix's day total in /api/usage/dests.
type destRow struct {
	Prefix string  `json:"prefix"`
	Fam    int     `json:"fam"`
	RxGB   float64 `json:"rx_gb"`
	TxGB   float64 `json:"tx_gb"`
	Total  float64 `json:"total_gb"`
}

// topDests returns each device's top-n prefixes by total bytes.
func (d *destTrack) topDests(n int, now time.Time) map[string][]destRow {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string][]destRow{}
	for mac, prefixes := range d.totals {
		rows := make([]destRow, 0, len(prefixes))
		for p, t := range prefixes {
			rows = append(rows, destRow{
				Prefix: p,
				Fam:    d.fam[p],
				RxGB:   gbFloat(t.rx),
				TxGB:   gbFloat(t.tx),
				Total:  gbFloat(t.rx + t.tx),
			})
		}
		// insertion sort by total, descending, keep top n — the map
		// holds tens of entries per device, not thousands.
		for i := 1; i < len(rows); i++ {
			for j := i; j > 0 && rows[j].Total > rows[j-1].Total; j-- {
				rows[j], rows[j-1] = rows[j-1], rows[j]
			}
		}
		if len(rows) > n {
			rows = rows[:n]
		}
		out[mac] = rows
	}
	return out
}

func gbFloat(b uint64) float64 { return float64(b) / 1e9 }

// startDestPoller polls the collector's destination map every 5 s for
// the life of the server. Walk errors are logged and skipped — the next
// window folds in whatever accumulated meanwhile.
func (s *Server) startDestPoller(stop <-chan struct{}) {
	tr := newDestTrack()
	s.destTrack = tr
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			cur, err := s.ebpf.ReadDests()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("dest_bytes walk failed; window skipped")
				continue
			}
			tr.record(cur)
		}
	}
}

// handleAPIUsageDests serves per-device top internet destinations by
// today's byte volume.
func (s *Server) handleAPIUsageDests(c fiber.Ctx) error {
	n := 5
	if v := c.Query("top"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= 20 {
			n = p
		}
	}
	if s.destTrack == nil {
		return c.JSON(fiber.Map{"day": time.Now().Format("2006-01-02"), "clients": fiber.Map{}})
	}
	return c.JSON(fiber.Map{
		"day":     s.destTrack.day,
		"clients": s.destTrack.topDests(n, time.Now()),
	})
}
