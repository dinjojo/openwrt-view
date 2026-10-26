package netify

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// fakeNetifyd serves the wire contract: length-framed newline JSON.
func fakeNetifyd(t *testing.T, events [][]byte) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "netifyd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for _, ev := range events {
			hdr, _ := json.Marshal(map[string]int64{"length": int64(len(ev))})
			conn.Write(append(hdr, '\n'))
			conn.Write(append(ev, '\n'))
		}
		// hold the connection open so consume() doesn't spin
		buf := make([]byte, 1)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	cleanup := func() { ln.Close(); <-done }
	return sock, cleanup
}

func feed(t *testing.T, events ...string) *Collector {
	t.Helper()
	raw := make([][]byte, 0, len(events))
	for _, e := range events {
		raw = append(raw, []byte(e))
	}
	sock, cleanup := fakeNetifyd(t, raw)
	defer cleanup()
	c := New(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// The error is expected: ctx cancellation unblocks the read by
	// closing the connection. What matters is that all events landed
	// in the collector first — they are written at accept time, well
	// before the timeout.
	_ = c.consume(ctx)
	return c
}

const defs = `{"type":"definitions","applications":{"133":"netify.netflix","91":"netify.youtube"}}`

func TestFlowLifecycleAndPurgeDelta(t *testing.T) {
	c := feed(t,
		defs,
		`{"type":"flow","interface":"lan","internal":true,"flow":{"digest":"f1","detected_application":133,"detected_application_name":"netify.netflix","host_server_name":"www.netflix.com","local_mac":"AA:BB:CC:DD:EE:FF","local_ip":"192.168.1.10","other_ip":"1.2.3.4"}}`,
		// two live updates: 1 MB down (other) + 10 KB up (local)
		`{"type":"flow_stats","interface":"lan","internal":true,"flow":{"digest":"f1","local_bytes":10000,"other_bytes":1000000,"total_bytes":1010000}}`,
		`{"type":"flow_stats","interface":"lan","internal":true,"flow":{"digest":"f1","local_bytes":2000,"other_bytes":200000,"total_bytes":1212000}}`,
		// purge: final total exceeds the accumulated 1,212,000 by
		// 88,000, split along the flow's 12,000 up : 1,200,000 down
		// ratio (871 of it up, the rounding remainder down).
		`{"type":"flow_purge","interface":"lan","internal":true,"flow":{"digest":"f1","local_bytes":0,"other_bytes":0,"total_bytes":1300000}}`,
	)
	snap := c.Snapshot()
	if len(snap.Apps) != 1 {
		t.Fatalf("apps = %d, want 1", len(snap.Apps))
	}
	row := snap.Apps[0]
	if row.Tag != "netify.netflix" || row.Name != "Netflix" {
		t.Errorf("app = %q/%q, want netify.netflix/Netflix", row.Tag, row.Name)
	}
	if row.Down != 1287129 || row.Up != 12871 {
		t.Errorf("down/up = %d/%d, want 1287129/12871", row.Down, row.Up)
	}
	if row.Host != "netflix.com" {
		t.Errorf("host = %q, want netflix.com", row.Host)
	}
	if len(row.Device) != 1 || row.Device[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("device rows = %+v", row.Device)
	}
	if snap.Unknown != 0 {
		t.Errorf("unknown = %d, want 0", snap.Unknown)
	}
}

func TestWanCaptureIgnored(t *testing.T) {
	c := feed(t,
		defs,
		`{"type":"flow","interface":"wan","internal":false,"flow":{"digest":"w1","detected_application":133,"detected_application_name":"netify.netflix","local_mac":"00:11:22:33:44:55"}}`,
		`{"type":"flow_stats","interface":"wan","internal":false,"flow":{"digest":"w1","local_bytes":999999,"other_bytes":888888,"total_bytes":1888877}}`,
	)
	snap := c.Snapshot()
	if len(snap.Apps) != 0 {
		t.Errorf("WAN capture leaked into aggregates: %+v", snap.Apps)
	}
}

func TestUnknownAppGoesToUnknownPool(t *testing.T) {
	c := feed(t,
		`{"type":"flow","interface":"lan","internal":true,"flow":{"digest":"u1","detected_application":0,"local_mac":"aa:bb:cc:dd:ee:ff"}}`,
		`{"type":"flow_stats","interface":"lan","internal":true,"flow":{"digest":"u1","local_bytes":500,"other_bytes":1500,"total_bytes":2000}}`,
	)
	snap := c.Snapshot()
	if snap.Unknown != 2000 {
		t.Errorf("unknown = %d, want 2000", snap.Unknown)
	}
	if len(snap.Apps) != 0 {
		t.Errorf("unidentified flows must not create app rows: %+v", snap.Apps)
	}
}

func TestFrameHeadersSkipped(t *testing.T) {
	c := feed(t,
		`{"length":42}`, // header line alone: skipped, no panic
		defs,
		`{"type":"flow","interface":"lan","internal":true,"flow":{"digest":"f9","detected_application":91,"detected_application_name":"netify.youtube","local_mac":"aa:bb:cc:dd:ee:ff"}}`,
	)
	// no assertion beyond consume() not hanging or panicking; identity stored
	c.mu.Lock()
	f := c.flows["f9"]
	c.mu.Unlock()
	if f == nil || f.appTag != "netify.youtube" {
		t.Errorf("flow identity not stored: %+v", f)
	}
}

func TestAppLabel(t *testing.T) {
	for in, want := range map[string]string{
		"netify.netflix":      "Netflix",
		"netify.google_video": "Google Video",
		"TLS":                 "TLS",
		"netify.openwrt":      "Openwrt",
	} {
		if got := appLabel(in); got != want {
			t.Errorf("appLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrendSeriesRingAndSnapshot(t *testing.T) {
	c := New("/nonexistent.sock")

	// Bytes credited through the real path land in both the aggregate and
	// the trend ring.
	c.mu.Lock()
	f := &flow{appTag: "netify.youtube", mac: "aa:bb:cc:dd:ee:ff"}
	c.addAttribute(f, 700, 100)
	c.addAttribute(f, 300, 50) // same bucket accumulates
	c.addAttribute(&flow{appTag: "netify.ntp", mac: "aa:bb:cc:dd:ee:ff"}, 10, 10)
	c.mu.Unlock()

	// Ring slides forward; a credit a few buckets older than the new
	// frontier survives in the ring, though it falls outside the
	// 120-minute window the UI is shown.
	now := time.Now().Unix() / seriesBucketSecs
	future := now + seriesKeep - 10
	c.mu.Lock()
	c.addSeriesAt("netify.youtube", 1, 2, future)
	s := c.series["netify.youtube"]
	if s.base != future-seriesKeep+1 {
		t.Errorf("ring base = %d, want %d", s.base, future-seriesKeep+1)
	}
	var ringDown, ringUp int64
	for i := range s.down {
		ringDown += s.down[i]
		ringUp += s.up[i]
	}
	c.mu.Unlock()
	if ringDown != 1001 || ringUp != 152 { // 700+300+1 down, 100+50+2 up
		t.Errorf("full-ring sums = %d/%d, want 1001/152", ringDown, ringUp)
	}

	snap := c.Snapshot()
	var yt *AppRow
	for i := range snap.Apps {
		if snap.Apps[i].Tag == "netify.youtube" {
			yt = &snap.Apps[i]
		}
	}
	if yt == nil || yt.Trend == nil {
		t.Fatalf("youtube row/trend missing: %+v", yt)
	}
	if yt.Trend.BucketSec != int(seriesBucketSecs) {
		t.Errorf("bucket_sec = %d, want %d", yt.Trend.BucketSec, seriesBucketSecs)
	}
	if len(yt.Trend.Down) != seriesEmit || len(yt.Trend.Up) != seriesEmit {
		t.Fatalf("emitted series length = %d/%d, want %d each", len(yt.Trend.Down), len(yt.Trend.Up), seriesEmit)
	}
	var sumDown, sumUp int64
	for _, v := range yt.Trend.Down {
		sumDown += v
	}
	for _, v := range yt.Trend.Up {
		sumUp += v
	}
	if sumDown != 1 || sumUp != 2 {
		// The earlier credits are 710 minutes old — inside the ring but
		// outside the emitted 2h tail; only the frontier credit shows.
		t.Errorf("emitted sums = %d/%d, want 1/2", sumDown, sumUp)
	}
	// No slide happened for ntp, so its credit is still the newest bucket.
	var ntp *AppRow
	for i := range snap.Apps {
		if snap.Apps[i].Tag == "netify.ntp" {
			ntp = &snap.Apps[i]
		}
	}
	if ntp == nil || ntp.Trend == nil || ntp.Trend.Down[len(ntp.Trend.Down)-1] != 10 {
		t.Errorf("ntp trend missing or last bucket wrong: %+v", ntp)
	}
}
