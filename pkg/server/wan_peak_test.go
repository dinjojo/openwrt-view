package server

import (
	"testing"
	"time"
)

func TestWanPeakRing(t *testing.T) {
	r := newWanPeakRing()
	base := int64(1_800_000) // a minute boundary
	// Three samples in the first minute; the max must win.
	r.sample(100, 5, time.Unix(base, 0))
	r.sample(370, 8, time.Unix(base+20, 0))
	r.sample(50, 2, time.Unix(base+40, 0))
	// A second minute rolls the first one in.
	r.sample(10, 1, time.Unix(base+60, 0))
	pts := r.all()
	if len(pts) != 2 {
		t.Fatalf("all() = %d points, want 2", len(pts))
	}
	if pts[0].T != base || pts[0].Down != 370 || pts[0].Up != 8 {
		t.Errorf("minute 1 = %+v, want down 370 up 8 at t=%d", pts[0], base)
	}
	if pts[1].T != base+60 || pts[1].Down != 10 {
		t.Errorf("minute 2 = %+v, want down 10 at t=%d", pts[1], base+60)
	}
}

func TestWanPeakRingCap(t *testing.T) {
	r := newWanPeakRing()
	for i := int64(0); i < wanPeakCap+10; i++ {
		r.sample(float64(i), 0, time.Unix(i*60, 0))
	}
	if got := len(r.all()); got != wanPeakCap {
		t.Fatalf("ring holds %d points, want cap %d", got, wanPeakCap)
	}
}
