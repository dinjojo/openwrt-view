package server

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestWanPeakRingPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wan-peaks.json")
	r := newWanPeakRing()
	if err := r.setPath(p); err != nil {
		t.Fatalf("setPath: %v", err)
	}
	base := time.Now().Truncate(time.Minute)
	r.sample(100, 5, base)
	r.sample(400, 8, base.Add(20*time.Second)) // the speedtest second
	r.sample(300, 7, base.Add(time.Minute))    // rolls minute 1 in, flushes

	// A fresh ring — what a daemon restart gets — loads the closed
	// minute's maxima from disk.
	r2 := newWanPeakRing()
	if err := r2.setPath(p); err != nil {
		t.Fatalf("reload setPath: %v", err)
	}
	pts := r2.all()
	if len(pts) != 1 {
		t.Fatalf("reloaded ring has %d points, want 1", len(pts))
	}
	if pts[0].Down != 400 || pts[0].Up != 8 {
		t.Errorf("reloaded minute = %+v, want down 400 up 8", pts[0])
	}
}

func TestWanPeakRingLoadDropsStale(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wan-peaks.json")
	fresh := time.Now().Add(-time.Hour).Truncate(time.Minute).Unix()
	stale := time.Now().Add(-48 * time.Hour).Unix()
	body, _ := json.Marshal([]wanPeakPoint{{T: stale, Down: 999}, {T: fresh, Down: 42}})
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	r := newWanPeakRing()
	if err := r.setPath(p); err != nil {
		t.Fatalf("setPath: %v", err)
	}
	pts := r.all()
	if len(pts) != 1 || pts[0].T != fresh || pts[0].Down != 42 {
		t.Fatalf("all() = %+v, want only the fresh point (t=%d, down 42)", pts, fresh)
	}
}
