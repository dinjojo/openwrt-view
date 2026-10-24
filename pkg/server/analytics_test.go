package server

import "testing"

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		// Previously supported inputs (regression).
		{"415Mbit", 415e6},
		{"1Gbit", 1e9},
		{"500Kbit", 500e3},
		{"500kbit", 500e3},
		{"2.5Gbit", 2.5e9},
		{"  415Mbit  ", 415e6},
		// Bare bit unit.
		{"1000bit", 1000},
		// bps = BYTES per second, so ×8 to get bits.
		{"100bps", 800},
		{"50Mbps", 400e6},
		{"50mbps", 400e6},
		{"1Kbps", 8e3},
		{"1Gbps", 8e9},
		// Tera prefix.
		{"1Tbit", 1e12},
		{"1tbit", 1e12},
		{"1.5Tbit", 1.5e12},
		{"1Tbps", 8e12},
		// Unknown / garbage.
		{"", 0},
		{"Mbit", 0},
		{"415", 0},
		{"415Mbyte", 0},
		{"415Xbit", 0},
		{"415Pbit", 0},
		{"fast", 0},
		{"unlimited", 0},
	}
	for _, c := range cases {
		if got := parseBandwidth(c.in); got != c.want {
			t.Errorf("parseBandwidth(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
