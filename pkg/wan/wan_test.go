package wan

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeUbus installs a fake `ubus` executable as the only thing on PATH. The
// script prints the given output (with shell builtins only) and exits with
// the given code. An empty dir (install=false) simulates ubus being absent.
func fakeUbus(t *testing.T, install bool, output string, exit int) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if install {
		writeUbus(t, dir, output, exit)
	}
	return dir
}

func writeUbus(t *testing.T, dir, output string, exit int) {
	t.Helper()
	data := filepath.Join(dir, "ubus.out")
	if err := os.WriteFile(data, []byte(output), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"while IFS= read -r l || [ -n \"$l\" ]; do printf '%s\\n' \"$l\"; done < '" + data + "'\n" +
		"exit " + strconv.Itoa(exit) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ubus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestNewTakesSynchronousSnapshot(t *testing.T) {
	tests := []struct {
		name    string
		install bool
		output  string
		exit    int
		want    State
	}{
		{
			name:    "pppoe up with address",
			install: true,
			output:  `{"up":true,"proto":"pppoe","uptime":3725,"ipv4-address":[{"address":"100.64.1.2","mask":32},{"address":"10.0.0.1"}]}`,
			want:    State{Available: true, Up: true, Proto: "pppoe", UptimeSec: 3725, Addr: "100.64.1.2"},
		},
		{
			name:    "session down, no addresses",
			install: true,
			output:  `{"up":false,"proto":"pppoe","uptime":0,"ipv4-address":[]}`,
			want:    State{Available: true, Up: false, Proto: "pppoe"},
		},
		{
			name:    "missing ipv4 field",
			install: true,
			output:  `{"up":true,"proto":"dhcp","uptime":12}`,
			want:    State{Available: true, Up: true, Proto: "dhcp", UptimeSec: 12},
		},
		{
			name:    "invalid json",
			install: true,
			output:  `Command failed: Not found`,
			want:    State{},
		},
		{
			name:    "ubus exits non-zero",
			install: true,
			output:  `{"up":true,"proto":"pppoe"}`,
			exit:    4,
			want:    State{},
		},
		{
			name:    "ubus not installed",
			install: false,
			want:    State{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeUbus(t, tc.install, tc.output, tc.exit)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			before := time.Now()
			got := New(ctx).Snapshot()

			if got.At.Before(before) || time.Since(got.At) > time.Minute {
				t.Errorf("At = %v, want a timestamp from this refresh", got.At)
			}
			got.At = time.Time{}
			if got != tc.want {
				t.Errorf("Snapshot() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRefreshTracksSessionTransitions(t *testing.T) {
	dir := fakeUbus(t, true, `{"up":true,"proto":"pppoe","uptime":100,"ipv4-address":[{"address":"100.64.0.9"}]}`, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := New(ctx)
	if s := p.Snapshot(); !s.Up || s.Addr != "100.64.0.9" {
		t.Fatalf("initial snapshot = %+v, want up with address", s)
	}

	steps := []struct {
		name   string
		output string
		exit   int
		want   State
	}{
		{"isp drops session", `{"up":false,"proto":"pppoe","uptime":0}`, 0,
			State{Available: true, Proto: "pppoe"}},
		{"ubus temporarily fails", ``, 1, State{}},
		{"session re-established with new address", `{"up":true,"proto":"pppoe","uptime":5,"ipv4-address":[{"address":"100.64.7.7"}]}`, 0,
			State{Available: true, Up: true, Proto: "pppoe", UptimeSec: 5, Addr: "100.64.7.7"}},
	}
	for _, st := range steps {
		writeUbus(t, dir, st.output, st.exit)
		p.refresh()
		got := p.Snapshot()
		got.At = time.Time{}
		if got != st.want {
			t.Errorf("%s: Snapshot() = %+v, want %+v", st.name, got, st.want)
		}
	}
}

func TestSnapshotConcurrentWithRefresh(t *testing.T) {
	fakeUbus(t, true, `{"up":true,"proto":"pppoe","uptime":1}`, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := New(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if s := p.Snapshot(); s.Proto != "pppoe" {
					t.Errorf("Snapshot().Proto = %q, want pppoe", s.Proto)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			p.refresh()
		}
	}()
	wg.Wait()
}
