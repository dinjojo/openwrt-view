package tzloc

import (
	"testing"
	"time"
	_ "time/tzdata" // as in main: no dependency on the host's zoneinfo
)

func TestLoad(t *testing.T) {
	ref := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		in      string
		offset  int // seconds east of UTC
		wantErr bool
	}{
		{in: "UTC", offset: 0},
		{in: "Asia/Kolkata", offset: 5*3600 + 30*60},
		{in: "America/Argentina/Buenos Aires", offset: -3 * 3600}, // LuCI spelling
		{in: "IST-5:30", offset: 5*3600 + 30*60},
		{in: "<+0530>-5:30", offset: 5*3600 + 30*60},
		{in: "UTC0", offset: 0},
		{in: "EST5", offset: -5 * 3600},
		{in: "CET-1CEST,M3.5.0,M10.5.0/3", wantErr: true}, // DST rule: refuse to guess
		{in: "Nowhere/Atlantis", wantErr: true},
		{in: "X-1", wantErr: true}, // abbreviation too short
	}
	for _, c := range cases {
		loc, err := Load(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Load(%q) = %v, want error", c.in, loc)
			}
			continue
		}
		if err != nil {
			t.Errorf("Load(%q): %v", c.in, err)
			continue
		}
		if _, off := ref.In(loc).Zone(); off != c.offset {
			t.Errorf("Load(%q) offset = %d, want %d", c.in, off, c.offset)
		}
	}
	if loc, err := Load("Local"); err != nil || loc != time.Local {
		t.Errorf("Load(Local) = %v, %v", loc, err)
	}
	if loc, err := Load(""); err != nil || loc != time.Local {
		t.Errorf("Load(\"\") = %v, %v", loc, err)
	}
}
