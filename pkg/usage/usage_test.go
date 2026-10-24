package usage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyTotals(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "sub")) // created on first write
	loc := time.FixedZone("ICT", 7*3600)
	d := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, loc) }
	const G = 1_000_000_000

	writes := []struct {
		at      time.Time
		samples []Sample
	}{
		// Oct 19: a day outside a 3-day window, serving only as baseline.
		{d(19, 23, 45), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 10 * G, Tx: 1 * G}}},
		// Oct 20: first sample continues from the Oct 19 baseline.
		{d(20, 0, 0), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 11 * G, Tx: 1 * G}}},
		{d(20, 12, 0), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 12 * G, Tx: 2 * G}, {MAC: "AA:BB:CC:DD:EE:02", Rx: 5 * G, Tx: 0}}},
		{d(20, 23, 45), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 13 * G, Tx: 2 * G}, {MAC: "AA:BB:CC:DD:EE:02", Rx: 7 * G, Tx: G / 2}}},
		// Oct 21: no file (monitor down all day).
		// Oct 22: counter reset for :01 (nlbwmon period roll-over).
		{d(22, 8, 0), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 14 * G, Tx: 2 * G}}},
		{d(22, 8, 15), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 1 * G, Tx: 0}}},
		{d(22, 9, 0), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 3 * G, Tx: G / 10}}},
	}
	for _, w := range writes {
		if err := s.Append(w.at, w.samples); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "sub", "usage-2026-10-20.jsonl")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("usage file: %v %v", fi, err)
	}

	days := s.Daily(3, d(22, 10, 0))
	if len(days) != 2 || days[0].Date != "2026-10-20" || days[1].Date != "2026-10-22" {
		t.Fatalf("days = %+v, want Oct 20 and Oct 22 only", days)
	}
	want20 := map[string]ClientDay{
		"AA:BB:CC:DD:EE:01": {RxGB: 3, TxGB: 1}, // 13-10 (baseline from Oct 19), 2-1
		"AA:BB:CC:DD:EE:02": {RxGB: 2, TxGB: 0.5},
	}
	for mac, w := range want20 {
		if got := days[0].Clients[mac]; got != w {
			t.Errorf("Oct 20 %s = %+v, want %+v", mac, got, w)
		}
	}
	// Oct 22: 14-13 = 1 (from Oct 20's last, Oct 21 missing), reset → 0, then 3-1 = 2.
	if got := days[1].Clients["AA:BB:CC:DD:EE:01"]; got != (ClientDay{RxGB: 3, TxGB: 0.1}) {
		t.Errorf("Oct 22 = %+v, want rx 3 tx 0.1", got)
	}

	// Window of 1 day: Oct 22 baseline is Oct 21 (missing) → first sample only seeds.
	days = s.Daily(1, d(22, 10, 0))
	if len(days) != 1 || days[0].Clients["AA:BB:CC:DD:EE:01"] != (ClientDay{RxGB: 2, TxGB: 0.1}) {
		t.Errorf("1-day window = %+v", days)
	}
}

func TestDailyEmptyDir(t *testing.T) {
	days := New(filepath.Join(t.TempDir(), "none")).Daily(7, time.Now())
	if days == nil || len(days) != 0 {
		t.Fatalf("want empty non-nil, got %#v", days)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	old := time.Now().AddDate(0, 0, -40)
	if err := s.Append(old, []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(time.Now(), []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 2}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName(old))); !os.IsNotExist(err) {
		t.Fatal("40-day-old file should have been pruned")
	}
}

func TestDayKeysFollowLocation(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	cases := []struct {
		name string
		at   time.Time // instant, given in UTC as a UTC process would see it
		loc  *time.Location
		file string
	}{
		{"IST morning is the next IST day", time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC), ist, "usage-2026-10-22.jsonl"},
		{"IST just before midnight", time.Date(2026, 10, 22, 18, 29, 0, 0, time.UTC), ist, "usage-2026-10-22.jsonl"},
		{"no location: the time's own zone", time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC), nil, "usage-2026-10-21.jsonl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			s := New(dir)
			if c.loc != nil {
				s.SetLocation(c.loc)
			}
			if err := s.Append(c.at, []Sample{{MAC: "aa:bb:cc:dd:ee:01", Rx: 1}}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, c.file)); err != nil {
				t.Fatalf("want %s: %v", c.file, err)
			}
			days := s.Daily(1, c.at)
			if len(days) != 1 || "usage-"+days[0].Date+".jsonl" != c.file {
				t.Errorf("Daily = %+v, want the %s day", days, c.file)
			}
		})
	}
}
