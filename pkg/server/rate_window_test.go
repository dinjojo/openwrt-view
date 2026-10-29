package server

import "testing"

func TestRateWindow(t *testing.T) {
	cases := map[string]string{
		"15s":   "20s", // clamped: 10 s scrapes need >= 2 samples
		"30s":   "30s",
		"45s":   "45s",
		"120s":  "120s",
		"600s":  "600s",
		"1800s": "1800s",
		"garbo": "20s", // unparsable falls back to the safe minimum
	}
	for in, want := range cases {
		if got := rateWindow(in); got != want {
			t.Errorf("rateWindow(%q) = %q, want %q", in, got, want)
		}
	}
}
