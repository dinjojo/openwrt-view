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

func TestRecordWanbpfHistorySkipsIdleDevices(t *testing.T) {
	s := &Server{wanbpfHist: newWanbpfRing(4)}
	s.recordWanbpfHistory(&wanbpf.Snapshot{
		QCount: 10, QAvgNs: 1e5, QMaxNs: 2e5,
		Srtt: []wanbpf.DeviceRTT{
			{Mac: "aa:aa:aa:aa:aa:01", WinCount: 5, WinAvgNs: 2e7, MaxNs: 3e7},
			{Mac: "bb:bb:bb:bb:bb:02"}, // idle window: no samples
		},
	})
	pts := s.wanbpfHist.all()
	if len(pts) != 1 {
		t.Fatalf("got %d points, want 1", len(pts))
	}
	if len(pts[0].Devs) != 1 || pts[0].Devs[0].Mac != "aa:aa:aa:aa:aa:01" {
		t.Errorf("devs = %+v, want only the device with samples", pts[0].Devs)
	}
	if pts[0].QAvgNs != 1e5 || pts[0].QMaxNs != 2e5 {
		t.Errorf("queue delay not carried through: %+v", pts[0])
	}
	// A nil snapshot and a nil ring must both be no-ops.
	s2 := &Server{}
	s2.recordWanbpfHistory(nil)
	s.recordWanbpfHistory(&wanbpf.Snapshot{})
}
