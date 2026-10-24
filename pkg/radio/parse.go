package radio

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// surveyEntry is one channel block from `iw dev <iface> survey dump`.
// Times are cumulative milliseconds; HasTimes is false when the driver
// printed no active/busy times for the channel (common for channels the
// card has not visited yet).
type surveyEntry struct {
	FreqMHz  int
	InUse    bool
	NoiseDBm *int
	ActiveMS int64
	BusyMS   int64
	HasTimes bool
}

var (
	surveyFreqRe  = regexp.MustCompile(`^frequency:\s*([0-9]+)(?:\.[0-9]+)?\s*MHz(.*)$`)
	surveyNoiseRe = regexp.MustCompile(`^noise:\s*(-?[0-9]+)\s*dBm`)
	surveyTimeRe  = regexp.MustCompile(`^channel (active|busy) time:\s*([0-9]+)\s*ms`)
)

// parseSurvey parses `iw dev <iface> survey dump`. Blocks start at a
// "Survey data from" line; a block without a frequency is dropped.
func parseSurvey(out string) []surveyEntry {
	var res []surveyEntry
	var cur *surveyEntry
	var gotActive, gotBusy bool
	flush := func() {
		if cur != nil && cur.FreqMHz > 0 {
			cur.HasTimes = gotActive && gotBusy
			res = append(res, *cur)
		}
		cur, gotActive, gotBusy = nil, false, false
	}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "Survey data from") {
			flush()
			cur = &surveyEntry{}
			continue
		}
		if cur == nil {
			continue
		}
		if m := surveyFreqRe.FindStringSubmatch(l); m != nil {
			cur.FreqMHz, _ = strconv.Atoi(m[1])
			cur.InUse = strings.Contains(m[2], "[in use]")
			continue
		}
		if m := surveyNoiseRe.FindStringSubmatch(l); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				cur.NoiseDBm = &n
			}
			continue
		}
		if m := surveyTimeRe.FindStringSubmatch(l); m != nil {
			v, err := strconv.ParseInt(m[2], 10, 64)
			if err != nil {
				continue
			}
			if m[1] == "active" {
				cur.ActiveMS, gotActive = v, true
			} else {
				cur.BusyMS, gotBusy = v, true
			}
		}
	}
	flush()
	return res
}

// Neighbour is one access point seen by the scan.
type Neighbour struct {
	SSID      string  `json:"ssid"` // empty for hidden networks
	BSSID     string  `json:"bssid"`
	SignalDBm float64 `json:"signal_dbm"`
	FreqMHz   int     `json:"freq_mhz"`
	Band      string  `json:"band"`
	Channel   int     `json:"channel"`
}

var (
	bssRe    = regexp.MustCompile(`^BSS ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)
	freqRe   = regexp.MustCompile(`^freq:\s*([0-9]+)(?:\.[0-9]+)?`)
	signalRe = regexp.MustCompile(`^signal:\s*(-?[0-9]+(?:\.[0-9]+)?)\s*dBm`)
)

// parseScan parses `iw dev <iface> scan` / `scan dump` output into
// neighbours sorted strongest first. Entries without a frequency are
// dropped. The channel is computed from the frequency rather than taken
// from the (optional) DS Parameter set / HT operation IEs.
func parseScan(out string) []Neighbour {
	var res []Neighbour
	var cur *Neighbour
	flush := func() {
		if cur != nil && cur.FreqMHz > 0 {
			cur.Band = bandOf(cur.FreqMHz)
			cur.Channel = channelOf(cur.FreqMHz)
			res = append(res, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		l := strings.TrimSpace(line)
		if m := bssRe.FindStringSubmatch(l); m != nil && strings.HasPrefix(line, "BSS ") {
			flush()
			cur = &Neighbour{BSSID: strings.ToUpper(m[1])}
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case freqRe.MatchString(l):
			m := freqRe.FindStringSubmatch(l)
			cur.FreqMHz, _ = strconv.Atoi(m[1])
		case signalRe.MatchString(l):
			m := signalRe.FindStringSubmatch(l)
			v, _ := strconv.ParseFloat(m[1], 64)
			cur.SignalDBm = math.Round(v*10) / 10
		case strings.HasPrefix(l, "SSID:") && cur.SSID == "":
			cur.SSID = strings.TrimSpace(strings.TrimPrefix(l, "SSID:"))
		}
	}
	flush()
	sort.SliceStable(res, func(i, j int) bool { return res[i].SignalDBm > res[j].SignalDBm })
	return res
}

// bandOf maps a centre frequency in MHz to a band label.
func bandOf(mhz int) string {
	switch {
	case mhz < 5000:
		return "2.4G"
	case mhz >= 5925:
		return "6G"
	default:
		return "5G"
	}
}

// channelOf maps a centre frequency in MHz to its IEEE channel number
// (0 when unknown).
func channelOf(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz == 5935:
		return 2
	case mhz >= 5950 && mhz <= 7125:
		return (mhz - 5950) / 5
	case mhz >= 5000 && mhz <= 5895:
		return (mhz - 5000) / 5
	}
	return 0
}
