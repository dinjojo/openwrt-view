package types

import (
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func sampleStats() CakeStats {
	return CakeStats{
		Interface: "eth0", Handle: "8001:", Direction: "egress", Bandwidth: "40Mbit",
		DiffservMode: "diffserv4", RTT: "100ms", Overhead: "34", DualMode: "dual-srchost",
		FwmarkMask: "0x0", NATEnabled: true, ATMMode: "ptm", MPU: "84", WashEnabled: true,
		MemLimit: "4Mb", RawHeader: "qdisc cake 8001: root refcnt 2 bandwidth 40Mbit",
		SentBytes: math.MaxUint64, SentPkts: 1 << 40, Dropped: 12, Overlimits: 34, Requeues: 1,
		BacklogBytes: "0b", BacklogPkts: 0, MemoryUsed: "1Mb", MemoryTotal: "4Mb",
		CapacityEst: "40Mbit", MinNetSize: "42", MaxNetSize: "1514", MinAdjSize: "84",
		MaxAdjSize: "1548", AvgHdrOffset: "14",
		Tiers: []CakeTier{
			{Name: "Bulk", Thresh: "2500Kbit", Target: "7.3ms", Interval: "102ms", PkDelay: "0us",
				AvDelay: "0us", SpDelay: "0us", Backlog: "0b", Pkts: 1, Bytes: 2, WayInds: 3,
				WayMiss: 4, WayCols: 5, Drops: 6, Marks: 7, AckDrop: 8, SpFlows: 9, BkFlows: 10,
				UnFlows: 11, MaxLen: 1514, Quantum: 300},
			{Name: "Voice \"q\" <tier>", Pkts: math.MaxUint64},
		},
		UpdatedAt:    time.Date(2026, 10, 22, 15, 4, 5, 123456789, time.UTC),
		TxBytesPerS:  1250.5,
		DropsPerS:    0.5,
		MarksPerS:    0,
		MaxAvDelayMs: 1.5,
		MaxPkDelayMs: 3.25,
	}
}

// jsonKeys returns the sorted top-level keys of a JSON object.
func jsonKeys(t *testing.T, b []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, b)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The generated easyjson code must stay in sync with the struct tags: a
// field added to types.go without regenerating would silently vanish from
// the API. Compare the easyjson key set against reflection-based
// encoding/json on a method-less copy of each type.
func TestEasyJSONMatchesStructTags(t *testing.T) {
	type plainStats CakeStats
	type plainTier CakeTier
	type plainSample HistorySample
	type plainResp StatsResponse

	st := sampleStats()
	cases := []struct {
		name  string
		easy  func() ([]byte, error)
		plain any
	}{
		{"CakeStats", st.MarshalJSON, plainStats(st)},
		{"CakeTier", st.Tiers[0].MarshalJSON, plainTier(st.Tiers[0])},
		{"HistorySample", HistorySample{T: 1, Tx: 2, Av: 3, Pk: 4, Dr: 5}.MarshalJSON, plainSample(HistorySample{T: 1})},
		{"StatsResponse", StatsResponse{UpdatedAt: "x"}.MarshalJSON, plainResp(StatsResponse{UpdatedAt: "x"})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eb, err := c.easy()
			if err != nil {
				t.Fatal(err)
			}
			pb, err := json.Marshal(c.plain)
			if err != nil {
				t.Fatal(err)
			}
			got, want := jsonKeys(t, eb), jsonKeys(t, pb)
			missing, extra := diffKeys(got, want)
			for _, k := range missing {
				t.Errorf("easyjson output is missing struct-tag key %q", k)
			}
			for _, k := range extra {
				t.Errorf("easyjson emits key %q that has no struct tag", k)
			}
		})
	}
}

func diffKeys(got, want []string) (missing, extra []string) {
	g, w := map[string]bool{}, map[string]bool{}
	for _, k := range got {
		g[k] = true
	}
	for _, k := range want {
		w[k] = true
		if !g[k] {
			missing = append(missing, k)
		}
	}
	for _, k := range got {
		if !w[k] {
			extra = append(extra, k)
		}
	}
	return missing, extra
}

// MarksPerS was once missing from the generated easyjson code; guard the
// round trip so a stale types_easyjson.go is caught.
func TestMarksPerSSerialized(t *testing.T) {
	b, err := CakeStats{MarksPerS: 2.5}.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var out CakeStats
	if err := out.UnmarshalJSON([]byte(`{"marks_per_s":2.5}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"marks_per_s":2.5`) || out.MarksPerS != 2.5 {
		t.Errorf("marks_per_s not round-tripped: encoded %s, decoded %v", b, out.MarksPerS)
	}
}

func TestCakeStatsRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   CakeStats
	}{
		{"fully populated", sampleStats()},
		{"zero value", CakeStats{UpdatedAt: time.Time{}.UTC()}},
		{"no tiers", func() CakeStats { s := sampleStats(); s.Tiers = nil; return s }()},
		{"unicode strings", CakeStats{Interface: "ifb4eth0", RawHeader: "naïve\ttab\nline ✓", UpdatedAt: time.Unix(0, 0).UTC()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := c.in.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			var out CakeStats
			if err := out.UnmarshalJSON(b); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, b)
			}
			if !out.UpdatedAt.Equal(c.in.UpdatedAt) {
				t.Errorf("UpdatedAt = %v, want %v", out.UpdatedAt, c.in.UpdatedAt)
			}
			out.UpdatedAt, c.in.UpdatedAt = time.Time{}, time.Time{}
			if !reflect.DeepEqual(out, c.in) {
				t.Errorf("round trip mismatch\n got %+v\nwant %+v", out, c.in)
			}
			// Must also decode with the standard library (other clients).
			var std map[string]any
			if err := json.Unmarshal(b, &std); err != nil {
				t.Errorf("stdlib cannot parse easyjson output: %v", err)
			}
		})
	}
}

func TestCakeStatsWireFormat(t *testing.T) {
	b, err := json.Marshal(sampleStats()) // dispatches to easyjson MarshalJSON
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"interface":"eth0"`,
		`"atm_mode":"ptm"`,
		`"nat_enabled":true`,
		`"sent_bytes":18446744073709551615`, // uint64 max must not lose precision
		`"updated_at":"2026-10-22T15:04:05.123456789Z"`,
		`"tx_bytes_per_s":1250.5`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("encoded JSON missing %s\n%s", want, s)
		}
	}
}

func TestCakeStatsUnmarshalLenient(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		check   func(t *testing.T, s CakeStats)
	}{
		{"unknown fields ignored", `{"interface":"eth0","bogus":{"a":[1,2]},"pkts_extra":3}`, false,
			func(t *testing.T, s CakeStats) {
				if s.Interface != "eth0" {
					t.Errorf("Interface = %q", s.Interface)
				}
			}},
		{"null tiers", `{"tiers":null}`, false,
			func(t *testing.T, s CakeStats) {
				if s.Tiers != nil {
					t.Errorf("Tiers = %#v, want nil", s.Tiers)
				}
			}},
		{"empty tiers", `{"tiers":[]}`, false,
			func(t *testing.T, s CakeStats) {
				if s.Tiers == nil || len(s.Tiers) != 0 {
					t.Errorf("Tiers = %#v, want empty non-nil", s.Tiers)
				}
			}},
		{"empty object", `{}`, false, func(t *testing.T, s CakeStats) {
			if !reflect.DeepEqual(s, CakeStats{}) {
				t.Errorf("got %+v", s)
			}
		}},
		{"truncated", `{"interface":"eth0"`, true, nil},
		{"wrong type", `{"sent_bytes":"lots"}`, true, nil},
		{"negative uint", `{"dropped":-1}`, true, nil},
		{"bad time", `{"updated_at":"not a time"}`, true, nil},
		{"not an object", `[1,2]`, true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var s CakeStats
			err := s.UnmarshalJSON([]byte(c.in))
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if c.check != nil {
				c.check(t, s)
			}
		})
	}
}

func TestStatsResponseRoundTrip(t *testing.T) {
	cases := []StatsResponse{
		{},
		{Interfaces: []CakeStats{}, UpdatedAt: "2026-10-22T15:04:05Z"},
		{Interfaces: []CakeStats{sampleStats(), {Interface: "ifb4eth0", Direction: "ingress"}}, UpdatedAt: "now"},
	}
	for i, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out StatsResponse
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("case %d: %v\n%s", i, err, b)
		}
		for j := range out.Interfaces {
			if !out.Interfaces[j].UpdatedAt.Equal(in.Interfaces[j].UpdatedAt) {
				t.Errorf("case %d iface %d time mismatch", i, j)
			}
			out.Interfaces[j].UpdatedAt = in.Interfaces[j].UpdatedAt
		}
		if len(in.Interfaces) == 0 && len(out.Interfaces) == 0 {
			out.Interfaces = in.Interfaces // nil vs [] both mean "none"
		}
		if !reflect.DeepEqual(out, in) {
			t.Errorf("case %d mismatch\n got %+v\nwant %+v", i, out, in)
		}
	}
}

func TestHistoryRoundTrip(t *testing.T) {
	in := HistoryResponse{
		"eth0":     {{T: 1_700_000_000, Tx: 1.5e6, Av: 0.25, Pk: 1.75, Dr: 0}},
		"ifb4eth0": {{T: 1, Tx: 0, Av: 0, Pk: 0, Dr: 3.5}, {T: 2, Tx: 9e9, Av: 100, Pk: 200, Dr: 0.001}},
		"empty":    {},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out HistoryResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("mismatch\n got %+v\nwant %+v", out, in)
	}

	// Short field names are part of the charting contract.
	sb, _ := HistorySample{T: 5, Tx: 1, Av: 2, Pk: 3, Dr: 4}.MarshalJSON()
	if got, want := string(sb), `{"t":5,"tx":1,"av":2,"pk":3,"dr":4}`; got != want {
		t.Errorf("HistorySample JSON = %s, want %s", got, want)
	}
}
