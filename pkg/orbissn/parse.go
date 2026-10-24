package orbissn

import (
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Station is one Wi-Fi client as reported by `wlanconfig athX list sta`.
// Numeric fields are pointers so a value that failed to parse is omitted
// from the JSON instead of showing up as a misleading 0.
type Station struct {
	DBm    *int   `json:"dbm,omitempty"`
	MinDBm *int   `json:"min_dbm,omitempty"`
	MaxDBm *int   `json:"max_dbm,omitempty"`
	TxRate *int   `json:"txrate,omitempty"` // Mbit/s
	RxRate *int   `json:"rxrate,omitempty"` // Mbit/s
	Mode   string `json:"mode,omitempty"`   // e.g. "11AC_VHT80"
	Assoc  string `json:"assoc,omitempty"`  // association time as printed, e.g. "15:09:21"
	Band   string `json:"band"`             // "2.4G" or "5G"
}

// noiseFloor converts the QCA driver's RSSI column (dB above the nominal
// -95 dBm noise floor) into dBm.
const noiseFloor = -95

var (
	assocRe  = regexp.MustCompile(`^\d{1,3}:\d{2}:\d{2}$`)
	modeTail = "IEEE80211_MODE_"
)

// parseStations parses `wlanconfig athX list sta` output. Columns are
// located by name from the header line (firmware versions differ in which
// columns they print). Multi-word columns such as IEs can shift trailing
// fields, so MODE and ASSOCTIME are found by pattern rather than index.
// Rows whose ADDR column is not a MAC are skipped as junk. Keys are
// uppercase MACs. The band comes from each row's CHAN column (which radio
// maps to which band differs across firmware); the fallback is only used
// when CHAN is missing or out of range.
func parseStations(out, fallbackBand string) map[string]Station {
	res := map[string]Station{}
	cols := map[string]int{"ADDR": 0, "CHAN": 2, "TXRATE": 3, "RXRATE": 4, "RSSI": 5, "MINRSSI": 6, "MAXRSSI": 7}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if hasField(f, "ADDR") {
			cols = map[string]int{}
			for i, name := range f {
				if _, dup := cols[name]; !dup {
					cols[name] = i
				}
			}
			continue
		}
		ai, ok := cols["ADDR"]
		if !ok || ai >= len(f) {
			continue
		}
		hw, err := net.ParseMAC(f[ai])
		if err != nil || len(hw) != 6 {
			continue
		}
		st := Station{Band: fallbackBand}
		if ch, ok := colAt(f, cols, "CHAN"); ok {
			if n, err := strconv.Atoi(strings.TrimSuffix(ch, "G")); err == nil && n > 0 {
				st.Band = bandFromChan(n)
			}
		}
		st.TxRate = rateAt(f, cols, "TXRATE")
		st.RxRate = rateAt(f, cols, "RXRATE")
		st.DBm = rssiAt(f, cols, "RSSI")
		st.MinDBm = rssiAt(f, cols, "MINRSSI")
		st.MaxDBm = rssiAt(f, cols, "MAXRSSI")
		for _, tok := range f[ai+1:] {
			switch {
			case strings.HasPrefix(tok, modeTail) && st.Mode == "":
				st.Mode = strings.TrimPrefix(tok, modeTail)
			case assocRe.MatchString(tok) && st.Assoc == "":
				st.Assoc = tok
			}
		}
		res[strings.ToUpper(hw.String())] = st
	}
	return res
}

// bandFromChan maps a Wi-Fi channel number to a plain band label.
func bandFromChan(ch int) string {
	if ch <= 14 {
		return "2.4G"
	}
	return "5G"
}

func hasField(f []string, name string) bool {
	for _, s := range f {
		if s == name {
			return true
		}
	}
	return false
}

func colAt(f []string, cols map[string]int, name string) (string, bool) {
	i, ok := cols[name]
	if !ok || i >= len(f) {
		return "", false
	}
	return f[i], true
}

// rateAt parses rates like "780M", "866Mbps", "1.2G" into whole Mbit/s.
func rateAt(f []string, cols map[string]int, name string) *int {
	s, ok := colAt(f, cols, name)
	if !ok {
		return nil
	}
	mult := 1.0
	s = strings.TrimSuffix(strings.TrimSuffix(s, "bps"), "b")
	switch {
	case strings.HasSuffix(s, "M"):
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		s, mult = strings.TrimSuffix(s, "G"), 1000
	case strings.HasSuffix(s, "K"):
		s, mult = strings.TrimSuffix(s, "K"), 0.001
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return nil
	}
	n := int(math.Round(v * mult))
	return &n
}

// rssiAt converts an RSSI column to dBm: positive values are dB above the
// noise floor (QCA convention), negative values are taken as dBm already.
func rssiAt(f []string, cols map[string]int, name string) *int {
	s, ok := colAt(f, cols, name)
	if !ok {
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	if v >= 0 {
		v += noiseFloor
	}
	return &v
}
