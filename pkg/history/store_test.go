package history

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/types"
)

// statWithDelay builds a CakeStats whose single tier reports the given
// av_delay. Av is independent of wall-clock timing, so it is a stable
// marker for checking ring-buffer ordering.
func statWithDelay(iface string, avMs int) types.CakeStats {
	return types.CakeStats{
		Interface: iface,
		Tiers:     []types.CakeTier{{AvDelay: fmt.Sprintf("%dms", avMs)}},
	}
}

func avs(samples []types.HistorySample) []float64 {
	out := make([]float64, len(samples))
	for i, s := range samples {
		out[i] = s.Av
	}
	return out
}

func equalF(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRingBufferOrderAndEviction(t *testing.T) {
	cases := []struct {
		name     string
		capacity int
		records  int // records after the baseline one
		want     []float64
	}{
		{"no samples after baseline", 3, 0, nil},
		{"partial fill", 3, 2, []float64{1, 2}},
		{"exactly full", 3, 3, []float64{1, 2, 3}},
		{"wraps once", 3, 4, []float64{2, 3, 4}},
		{"wraps many times", 3, 10, []float64{8, 9, 10}},
		{"capacity below 2 clamps to 2", 0, 5, []float64{4, 5}},
		{"capacity 1 clamps to 2", 1, 5, []float64{4, 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := NewHistoryStore(tc.capacity)
			hs.Record([]types.CakeStats{statWithDelay("eth0", 0)}, time.Second) // baseline: no sample
			for i := 1; i <= tc.records; i++ {
				hs.Record([]types.CakeStats{statWithDelay("eth0", i)}, time.Second)
			}
			snap := hs.Snapshot()
			got, ok := snap["eth0"]
			if tc.want == nil {
				if ok {
					t.Fatalf("want no samples, got %+v", got)
				}
				return
			}
			if !equalF(avs(got), tc.want) {
				t.Errorf("av = %v, want %v", avs(got), tc.want)
			}
			for i := 1; i < len(got); i++ {
				if got[i].T < got[i-1].T {
					t.Errorf("timestamps not chronological: %+v", got)
				}
			}
		})
	}
}

func TestRecordComputesRatesAndDelays(t *testing.T) {
	hs := NewHistoryStore(5)
	base := []types.CakeStats{{
		Interface: "eth0",
		SentBytes: 1000,
		Dropped:   10,
		Tiers:     []types.CakeTier{{Marks: 1}, {Marks: 2}},
	}}
	hs.Record(base, time.Second)
	if base[0].TxBytesPerS != 0 || base[0].DropsPerS != 0 {
		t.Fatalf("first poll must leave rates at zero: %+v", base[0])
	}

	time.Sleep(10 * time.Millisecond)
	next := []types.CakeStats{{
		Interface: "eth0",
		SentBytes: 5000,
		Dropped:   12,
		Tiers: []types.CakeTier{
			{Marks: 4, AvDelay: "500us", PkDelay: "3ms"},
			{Marks: 2, AvDelay: "2ms", PkDelay: "1.5s"},
		},
	}}
	hs.Record(next, time.Second)
	cs := next[0]
	if cs.TxBytesPerS <= 0 || cs.DropsPerS <= 0 || cs.MarksPerS <= 0 {
		t.Errorf("rates must be positive after counters grew: %+v", cs)
	}
	// Ratios are fixed regardless of elapsed time: Δtx 4000, Δdrops 2, Δmarks 3.
	if r := cs.TxBytesPerS / cs.DropsPerS; r < 1999.9 || r > 2000.1 {
		t.Errorf("tx/drops ratio = %v, want 2000", r)
	}
	if r := cs.MarksPerS / cs.DropsPerS; r < 1.49 || r > 1.51 {
		t.Errorf("marks/drops ratio = %v, want 1.5", r)
	}
	if cs.MaxAvDelayMs != 2 || cs.MaxPkDelayMs != 1500 {
		t.Errorf("max delays av=%v pk=%v, want 2 / 1500", cs.MaxAvDelayMs, cs.MaxPkDelayMs)
	}
	s := hs.Snapshot()["eth0"]
	if len(s) != 1 || s[0].Tx != cs.TxBytesPerS || s[0].Dr != cs.DropsPerS || s[0].Av != 2 || s[0].Pk != 1500 {
		t.Errorf("sample = %+v, stats = %+v", s, cs)
	}
}

func TestRecordTxFallsBackToTierBytes(t *testing.T) {
	hs := NewHistoryStore(5)
	hs.Record([]types.CakeStats{{Interface: "ifb0", Tiers: []types.CakeTier{{Bytes: 100}, {Bytes: 100}}}}, time.Second)
	time.Sleep(5 * time.Millisecond)
	next := []types.CakeStats{{Interface: "ifb0", Tiers: []types.CakeTier{{Bytes: 300}, {Bytes: 300}}}}
	hs.Record(next, time.Second)
	if next[0].TxBytesPerS <= 0 {
		t.Errorf("SentBytes=0 should fall back to summed tier bytes; got rate %v", next[0].TxBytesPerS)
	}
}

func TestRecordCounterResetGivesZeroRate(t *testing.T) {
	hs := NewHistoryStore(5)
	hs.Record([]types.CakeStats{{Interface: "eth0", SentBytes: 9000, Dropped: 50, Tiers: []types.CakeTier{{Marks: 9}}}}, time.Second)
	next := []types.CakeStats{{Interface: "eth0", SentBytes: 10, Dropped: 1, Tiers: []types.CakeTier{{Marks: 0}}}}
	hs.Record(next, time.Second)
	if next[0].TxBytesPerS != 0 || next[0].DropsPerS != 0 || next[0].MarksPerS != 0 {
		t.Errorf("counter reset must yield zero rates, got %+v", next[0])
	}
	// The reset values become the new baseline.
	time.Sleep(5 * time.Millisecond)
	again := []types.CakeStats{{Interface: "eth0", SentBytes: 20, Dropped: 2, Tiers: []types.CakeTier{{Marks: 1}}}}
	hs.Record(again, time.Second)
	if again[0].TxBytesPerS <= 0 || again[0].DropsPerS <= 0 || again[0].MarksPerS <= 0 {
		t.Errorf("rates after reset baseline should be positive, got %+v", again[0])
	}
}

func TestRecordDropsVanishedInterfaces(t *testing.T) {
	hs := NewHistoryStore(4)
	both := []types.CakeStats{statWithDelay("eth0", 1), statWithDelay("ifb4eth0", 1)}
	hs.Record(both, time.Second)
	hs.Record(both, time.Second)
	if snap := hs.Snapshot(); len(snap) != 2 {
		t.Fatalf("want 2 interfaces, got %v", snap)
	}
	hs.Record([]types.CakeStats{statWithDelay("eth0", 2)}, time.Second)
	snap := hs.Snapshot()
	if _, ok := snap["ifb4eth0"]; ok || len(snap["eth0"]) != 2 {
		t.Fatalf("vanished interface must be dropped: %v", snap)
	}
	// Re-appearing starts from a fresh baseline (no sample on first sight).
	hs.Record([]types.CakeStats{statWithDelay("eth0", 3), statWithDelay("ifb4eth0", 3)}, time.Second)
	if _, ok := hs.Snapshot()["ifb4eth0"]; ok {
		t.Error("re-added interface should have no samples until its second poll")
	}
	// An empty poll clears everything.
	hs.Record(nil, time.Second)
	if snap := hs.Snapshot(); len(snap) != 0 {
		t.Errorf("empty poll should clear store, got %v", snap)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	hs := NewHistoryStore(3)
	hs.Record([]types.CakeStats{statWithDelay("eth0", 0)}, time.Second)
	hs.Record([]types.CakeStats{statWithDelay("eth0", 1)}, time.Second)
	snap := hs.Snapshot()
	snap["eth0"][0].Av = 999
	if got := hs.Snapshot()["eth0"][0].Av; got != 1 {
		t.Errorf("mutating a snapshot leaked into the store: av=%v", got)
	}
}

func TestConcurrentRecordAndSnapshot(t *testing.T) {
	const capacity = 8
	hs := NewHistoryStore(capacity)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				hs.Record([]types.CakeStats{statWithDelay("eth0", i), statWithDelay("eth1", i)}, time.Second)
			}
		}(w)
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for k, s := range hs.Snapshot() {
					if len(s) == 0 || len(s) > capacity {
						t.Errorf("%s: snapshot length %d out of range", k, len(s))
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	snap := hs.Snapshot()
	if len(snap["eth0"]) != capacity || len(snap["eth1"]) != capacity {
		t.Errorf("after 800 records both buffers should be full: eth0=%d eth1=%d", len(snap["eth0"]), len(snap["eth1"]))
	}
}
