package server

import (
	"testing"

	"github.com/dinjojo/openwrt-view/pkg/wanbpf"
)

func TestWanbpfRingEvictsOldest(t *testing.T) {
	r := newWanbpfRing(3)
	for i := 0; i < 5; i++ {
		r.add(wanbpfHistPoint{T: int64(100 + i), QCount: uint64(i)})
	}
	got := r.all()
	if len(got) != 3 {
		t.Fatalf("kept %d points, want 3", len(got))
	}
	for i, p := range got {
		if want := int64(102 + i); p.T != want {
			t.Errorf("point %d has t=%d, want %d", i, p.T, want)
		}
	}
}

func TestSampleWanbpfAggregatesFullMinute(t *testing.T) {
	s := &Server{wanbpfHist: newWanbpfRing(4)}
	// Eleven windows accumulate without emitting a point.
	for i := 0; i < 11; i++ {
		s.sampleWanbpf(&wanbpf.Snapshot{
			QCount: 2, QAvgNs: uint64(100 + i), QMaxNs: uint64(200 + i),
			Srtt: []wanbpf.DeviceRTT{
				{Mac: "aa:aa:aa:aa:aa:01", WinCount: 5, WinAvgNs: 2e7, MaxNs: 3e7},
				{Mac: "bb:bb:bb:bb:bb:02"}, // idle window: no samples
			},
		})
	}
	if pts := s.wanbpfHist.all(); len(pts) != 0 {
		t.Fatalf("emitted %d points before a full minute, want 0", len(pts))
	}
	// Twelfth window flushes the aggregate.
	s.sampleWanbpf(&wanbpf.Snapshot{
		QCount: 2, QAvgNs: 300, QMaxNs: 900,
		Srtt: []wanbpf.DeviceRTT{
			{Mac: "aa:aa:aa:aa:aa:01", WinCount: 5, WinAvgNs: 4e7, MaxNs: 5e7},
		},
	})
	pts := s.wanbpfHist.all()
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	p := pts[0]
	if p.QCount != 24 || p.QMaxNs != 900 || p.QAvgNs != uint64((100+110)*11+600)/24 {
		t.Errorf("queue aggregate wrong: %+v", p)
	}
	if len(p.Devs) != 1 || p.Devs[0].Mac != "aa:aa:aa:aa:aa:01" {
		t.Errorf("devs = %+v, want only the device with samples", p.Devs)
	}
	if d := p.Devs[0]; d.WinCount != 60 || d.MaxNs != 5e7 || d.WinAvgNs != uint64((20000000*55+40000000*5)/60) {
		t.Errorf("device aggregate wrong: %+v", d)
	}
	// The accumulator reset: the next point must not carry old counts.
	for i := 0; i < 12; i++ {
		s.sampleWanbpf(&wanbpf.Snapshot{QCount: 1, QAvgNs: 10, QMaxNs: 20})
	}
	pts = s.wanbpfHist.all()
	if len(pts) != 2 {
		t.Fatalf("got %d points after second minute, want 2", len(pts))
	}
	if p := pts[1]; p.QCount != 12 || len(p.Devs) != 0 {
		t.Errorf("second minute leaked first-minute state: %+v", p)
	}
	// A nil snapshot and a nil ring must both be no-ops.
	s2 := &Server{}
	s2.sampleWanbpf(nil)
	s.sampleWanbpf(&wanbpf.Snapshot{})
}
