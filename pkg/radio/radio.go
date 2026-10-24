// Package radio watches the local RF environment through a Wi-Fi dongle on
// the router itself (intended: a USB AR9271 in monitor mode). It is
// dormant unless an interface is configured.
//
// Every 30 s it reads `iw dev <iface> survey dump` and turns the cumulative
// channel busy/active times into per-band utilisation (Δbusy / Δactive
// between two polls). Every 10 minutes it also scans for neighbouring
// access points (`iw dev <iface> scan`, falling back to `scan dump` for
// the cached results when a fresh scan is refused).
package radio

import (
	"context"
	"errors"
	"log"
	"math"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	surveyEvery = 30 * time.Second
	scanEvery   = 600 * time.Second
	cmdTimeout  = 20 * time.Second
)

// Channel is one surveyed channel.
type Channel struct {
	FreqMHz  int      `json:"freq_mhz"`
	Channel  int      `json:"channel"`
	InUse    bool     `json:"in_use"`
	UtilPct  *float64 `json:"util_pct"`  // null until two polls with progress
	NoiseDBm *int     `json:"noise_dbm"` // null when the driver gave none
}

// Band aggregates the channels of one band.
type Band struct {
	Band string `json:"band"` // "2.4G", "5G" or "6G"
	// UtilPct is Σ Δbusy / Σ Δactive over the band's channels between the
	// last two polls (null until then, or when no channel advanced).
	UtilPct *float64 `json:"util_pct"`
	// FreqMHz/NoiseDBm come from the in-use channel when it is in this
	// band, otherwise from the channel with the most active time.
	FreqMHz  int       `json:"freq_mhz"`
	NoiseDBm *int      `json:"noise_dbm"`
	Channels []Channel `json:"channels"`
}

// Status is the /api/radio body.
type Status struct {
	OK         bool        `json:"ok"`
	Iface      string      `json:"iface"`
	Err        string      `json:"err"`
	Bands      []Band      `json:"bands"`
	Neighbours []Neighbour `json:"neighbours"`
	At         int64       `json:"at"` // unix seconds of the last survey attempt (0 = never)
}

// runner executes `iw` with the given arguments.
type runner func(ctx context.Context, args ...string) (string, error)

// Collector polls one interface. A nil or unconfigured collector is safe
// to use and reports ok:false.
type Collector struct {
	iface string
	run   runner

	mu         sync.RWMutex
	status     Status
	prev       map[int]surveyEntry // last survey, by frequency
	lastErr    string
	lastScanOK *bool
}

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

// New returns a collector for iface ("" disables it). Names that are not
// valid Linux interface names are rejected (collector stays disabled and
// reports why).
func New(iface string) *Collector {
	c := &Collector{iface: iface, run: execIW, prev: map[int]surveyEntry{}}
	c.status = Status{Iface: iface, Err: "radio interface not configured", Bands: []Band{}, Neighbours: []Neighbour{}}
	if iface != "" && !ifaceRe.MatchString(iface) {
		c.iface = ""
		c.status.Err = "invalid radio interface name"
	}
	return c
}

// Enabled reports whether an interface is configured.
func (c *Collector) Enabled() bool { return c != nil && c.iface != "" }

// Snapshot returns the latest status (never nil slices).
func (c *Collector) Snapshot() Status {
	if c == nil {
		return Status{Err: "radio interface not configured", Bands: []Band{}, Neighbours: []Neighbour{}}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

// Run polls until ctx is done; it returns immediately when disabled.
func (c *Collector) Run(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	c.survey(ctx)
	c.scan(ctx)
	st := time.NewTicker(surveyEvery)
	defer st.Stop()
	sc := time.NewTicker(scanEvery)
	defer sc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-st.C:
			c.survey(ctx)
		case <-sc.C:
			c.scan(ctx)
		}
	}
}

func (c *Collector) survey(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, cmdTimeout)
	defer cancel()
	out, err := c.run(ctx, "dev", c.iface, "survey", "dump")
	if parent.Err() != nil {
		return
	}
	entries := parseSurvey(out)
	if err == nil && len(entries) == 0 {
		err = errors.New("no survey data")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.At = time.Now().Unix()
	if err != nil {
		msg := "survey: " + shortErr(err)
		c.status.OK, c.status.Err = false, msg
		c.status.Bands = []Band{}
		c.prev = map[int]surveyEntry{}
		if msg != c.lastErr {
			log.Printf("[radio] %s failed: %s", c.iface, msg)
		}
		c.lastErr = msg
		return
	}
	if c.lastErr != "" {
		log.Printf("[radio] %s survey working", c.iface)
	}
	c.lastErr = ""
	c.status.Bands = computeBands(c.prev, entries)
	c.status.OK, c.status.Err = true, ""
	next := make(map[int]surveyEntry, len(entries))
	for _, e := range entries {
		next[e.FreqMHz] = e
	}
	c.prev = next
}

func (c *Collector) scan(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, cmdTimeout)
	defer cancel()
	out, err := c.run(ctx, "dev", c.iface, "scan")
	ns := parseScan(out)
	if (err != nil || len(ns) == 0) && ctx.Err() == nil {
		// A monitor-mode or busy interface refuses a fresh scan; the
		// cached results may still be there.
		out, err = c.run(ctx, "dev", c.iface, "scan", "dump")
		ns = parseScan(out)
	}
	if parent.Err() != nil {
		return
	}
	ok := err == nil
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		if ns == nil {
			ns = []Neighbour{}
		}
		c.status.Neighbours = ns
	}
	if c.lastScanOK == nil || *c.lastScanOK != ok {
		if !ok {
			log.Printf("[radio] %s scan failed: %s", c.iface, shortErr(err))
		} else if c.lastScanOK != nil {
			log.Printf("[radio] %s scan working", c.iface)
		}
	}
	c.lastScanOK = &ok
}

// computeBands derives per-channel and per-band utilisation from two
// consecutive surveys. A channel whose counters went backwards (driver
// reset) or did not advance contributes no utilisation.
func computeBands(prev map[int]surveyEntry, cur []surveyEntry) []Band {
	type acc struct {
		band           Band
		dBusy, dActive int64
		bestActive     int64
		haveInUse      bool
		anyDelta       bool
	}
	byBand := map[string]*acc{}
	for _, e := range cur {
		name := bandOf(e.FreqMHz)
		a := byBand[name]
		if a == nil {
			a = &acc{band: Band{Band: name, Channels: []Channel{}}, bestActive: -1}
			byBand[name] = a
		}
		ch := Channel{FreqMHz: e.FreqMHz, Channel: channelOf(e.FreqMHz), InUse: e.InUse, NoiseDBm: e.NoiseDBm}
		if p, ok := prev[e.FreqMHz]; ok && p.HasTimes && e.HasTimes {
			da, db := e.ActiveMS-p.ActiveMS, e.BusyMS-p.BusyMS
			if da > 0 && db >= 0 && db <= da {
				u := round1(100 * float64(db) / float64(da))
				ch.UtilPct = &u
				a.dBusy += db
				a.dActive += da
				a.anyDelta = true
			}
		}
		a.band.Channels = append(a.band.Channels, ch)
		switch {
		case e.InUse:
			a.band.FreqMHz, a.band.NoiseDBm, a.haveInUse = e.FreqMHz, e.NoiseDBm, true
		case !a.haveInUse && e.ActiveMS > a.bestActive:
			a.band.FreqMHz, a.band.NoiseDBm, a.bestActive = e.FreqMHz, e.NoiseDBm, e.ActiveMS
		}
	}
	out := make([]Band, 0, len(byBand))
	for _, a := range byBand {
		if a.anyDelta && a.dActive > 0 {
			u := round1(100 * float64(a.dBusy) / float64(a.dActive))
			a.band.UtilPct = &u
		}
		sort.Slice(a.band.Channels, func(i, j int) bool { return a.band.Channels[i].FreqMHz < a.band.Channels[j].FreqMHz })
		out = append(out, a.band)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FreqMHz < out[j].FreqMHz })
	return out
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// execIW runs iw and folds stderr into the error.
func execIW(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "iw", args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return string(out), errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		if ctx.Err() != nil {
			return string(out), errors.New("timed out")
		}
	}
	return string(out), err
}

// shortErr returns the first line of an error, truncated.
func shortErr(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}
