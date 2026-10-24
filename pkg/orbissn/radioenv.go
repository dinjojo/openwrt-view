package orbissn

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// RadioEnv is one Orbi radio's RF environment as reported by the qca
// driver's `iwconfig athX`. The Signal level field is deliberately not
// exposed: on an AP with no associations it just echoes the noise floor.
// The Rx invalid counters are cumulative since the radio came up.
type RadioEnv struct {
	Iface        string  `json:"iface"`
	Band         string  `json:"band"` // "2.4G" or "5G", from the frequency
	FreqGHz      float64 `json:"freq_ghz"`
	NoiseDBm     int     `json:"noise_dbm"`
	Quality      int     `json:"quality"`     // Link Quality numerator
	QualityMax   int     `json:"quality_max"` // Link Quality denominator
	NwidRejects  int64   `json:"nwid_rejects"`
	CryptRejects int64   `json:"crypt_rejects"`
	FragRejects  int64   `json:"frag_rejects"`
}

var (
	iwFreqRe    = regexp.MustCompile(`Frequency[:=]\s*([0-9.]+)\s*GHz`)
	iwNoiseRe   = regexp.MustCompile(`Noise level[:=]\s*(-?[0-9]+)\s*dBm`)
	iwQualityRe = regexp.MustCompile(`Link Quality[:=]\s*([0-9]+)/([0-9]+)`)
	iwNwidRe    = regexp.MustCompile(`Rx invalid nwid[:=]\s*([0-9]+)`)
	iwCryptRe   = regexp.MustCompile(`Rx invalid crypt[:=]\s*([0-9]+)`)
	iwFragRe    = regexp.MustCompile(`Rx invalid frag[:=]\s*([0-9]+)`)
)

// parseIwconfig parses one `iwconfig <iface>` block. It fails (ok=false)
// unless the frequency, noise level and link quality are all present —
// a down VAP or "No such device" yields nothing rather than zeros. The
// Rx invalid counters default to 0 when a firmware omits them.
func parseIwconfig(iface, out string) (RadioEnv, bool) {
	out = strings.ReplaceAll(out, "\r", "")
	re := RadioEnv{Iface: iface}
	m := iwFreqRe.FindStringSubmatch(out)
	if m == nil {
		return re, false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil || f <= 0 {
		return re, false
	}
	re.FreqGHz = math.Round(f*1000) / 1000
	if f < 5 {
		re.Band = "2.4G"
	} else {
		re.Band = "5G"
	}
	m = iwNoiseRe.FindStringSubmatch(out)
	if m == nil {
		return re, false
	}
	if re.NoiseDBm, err = strconv.Atoi(m[1]); err != nil {
		return re, false
	}
	m = iwQualityRe.FindStringSubmatch(out)
	if m == nil {
		return re, false
	}
	re.Quality, _ = strconv.Atoi(m[1])
	re.QualityMax, _ = strconv.Atoi(m[2])
	re.NwidRejects = counterOf(iwNwidRe, out)
	re.CryptRejects = counterOf(iwCryptRe, out)
	re.FragRejects = counterOf(iwFragRe, out)
	return re, true
}

func counterOf(re *regexp.Regexp, out string) int64 {
	m := re.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	return n
}
