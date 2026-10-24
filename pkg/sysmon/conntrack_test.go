package sysmon

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiffRate(t *testing.T) {
	cases := []struct {
		name      string
		cur, prev uint64
		dt        float64
		want      float64
	}{
		{"steady", 100, 100, 30, 0},
		{"growth", 160, 100, 30, 2},
		{"fractional", 101, 100, 4, 0.25},
		{"counter reset clamps to zero", 5, 1000, 30, 0},
		{"from zero", 30, 0, 30, 1},
		{"drop by one is a reset, not a uint64 wrap", 999, 1000, 30, 0},
		{"reset from near max", 0, math.MaxUint64, 30, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := diffRate(c.cur, c.prev, c.dt); math.Abs(got-c.want) > 1e-9 {
				t.Errorf("diffRate(%d, %d, %v) = %v, want %v", c.cur, c.prev, c.dt, got, c.want)
			}
		})
	}
}

func TestTrimBytes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"123", "123"},
		{"123\n", "123"},
		{"123 \t\r\n", "123"},
		{"\n\n", ""},
		{" 12", " 12"}, // only trailing whitespace is stripped
	}
	for _, c := range cases {
		if got := string(trimBytes([]byte(c.in))); got != c.want {
			t.Errorf("trimBytes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadInt(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name    string
		path    string
		want    int64
		wantErr bool
	}{
		{"kernel style newline", write("count", "4096\n"), 4096, false},
		{"no newline", write("max", "262144"), 262144, false},
		{"trailing spaces", write("sp", "7  \n"), 7, false},
		{"zero", write("zero", "0\n"), 0, false},
		{"garbage", write("bad", "abc\n"), 0, true},
		{"empty", write("empty", ""), 0, true},
		{"missing file", filepath.Join(dir, "nope"), 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readInt(c.path)
			if (err != nil) != c.wantErr {
				t.Fatalf("readInt err = %v, wantErr %v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Errorf("readInt = %d, want %d", got, c.want)
			}
		})
	}
}

func TestHexVal(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"00000000", 0},
		{"0000000a", 10},
		{"000000ff", 255},
		{"FFFFFFFF", 0xffffffff},
		{"", 0},
		{"zz", 0},
		{"-1", 0},
	}
	for _, c := range cases {
		if got := hexVal(c.in); got != c.want {
			t.Errorf("hexVal(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSplitFields(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   \t ", nil},
		{"a", []string{"a"}},
		{"entries  clashres found", []string{"entries", "clashres", "found"}},
		{"\t00000001 0000000a\t", []string{"00000001", "0000000a"}},
		{" lead trail ", []string{"lead", "trail"}},
	}
	for _, c := range cases {
		if got := splitFields(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitFields(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
