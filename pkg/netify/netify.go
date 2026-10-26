// Package netify consumes the Netify Agent's (netifyd) JSON export socket
// and aggregates its DPI-classified flows into per-application, per-device
// byte totals — the "which device used which app" data that per-MAC
// accounting (eBPF, nlbwmon) cannot answer, because TLS hides everything
// but the handshake.
//
// Wire contract, pinned to netifyd 4.4.7 as packaged by OpenWrt 25.12
// (ground truth documented in VolanticSystems/luci-app-appflow's DESIGN.md
// and confirmed here against the live agent):
//
//   - connect to unix:/var/run/netifyd/netifyd.sock
//   - newline-delimited JSON; each payload line is preceded by a
//     {"length": N} frame-header line (skipped)
//   - events: agent_hello, definitions (id→tag maps), agent_status,
//     flow (on detection; re-fires when the detection is refined),
//     flow_stats (per-flow counter deltas), flow_purge (final event;
//     its local/other bytes are always zero and total_bytes is the
//     flow's final cumulative count)
//   - app identities are "netify.<slug>" tags resolved through the
//     definitions event's application id→tag map
//
// Only internal-side (LAN) events are aggregated. netifyd captures both
// the LAN and WAN sides of every NATed flow as separate flows; counting
// the WAN side too would double-count and its MAC is the router's, not
// the client's. The LAN capture already attributes to the real client.
package netify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// flow is our record of one netifyd flow.
type flow struct {
	appID     int64
	appTag    string // "netify.netflix"; resolved per event or from definitions
	hostName  string // SNI / server hostname when nDPI knows it
	mac       string // client MAC on the internal capture
	up, down  int64  // bytes attributed so far (deltas from flow_stats)
	lastTotal int64  // last seen total_bytes (cumulative for the flow)
	lastSeen  time.Time
}

// AggKey is one app × device aggregate.
type aggKey struct {
	tag string
	mac string
}

type aggEntry struct {
	down, up int64
}

// Snapshot is the aggregate view served to the UI.
type Snapshot struct {
	Started time.Time `json:"started"` // when aggregation began
	Flows   int       `json:"flows"`   // flows currently tracked
	Apps    []AppRow  `json:"apps"`    // sorted by total bytes, descending
	Unknown int64     `json:"unknown"` // bytes with no app identity yet
}

// AppRow is one application's totals with its per-device breakdown.
type AppRow struct {
	Tag    string      `json:"tag"`             // netify tag, e.g. "netify.netflix"
	Name   string      `json:"name"`            // display name, e.g. "Netflix"
	Host   string      `json:"host"`            // most-seen SNI hostname for it
	Down   int64       `json:"down"`            // bytes to clients
	Up     int64       `json:"up"`              // bytes from clients
	Total  int64       `json:"total"`           // down + up
	Trend  *Trend      `json:"trend,omitempty"` // per-minute series for the sparkline
	Device []DeviceRow `json:"device"`          // sorted by total, descending
}

// Trend is an app's recent traffic: parallel down/up series, oldest
// first, one value per BucketSec.
type Trend struct {
	BucketSec int     `json:"bucket_sec"`
	Down      []int64 `json:"down"`
	Up        []int64 `json:"up"`
}

// DeviceRow is one device's share of one app.
type DeviceRow struct {
	MAC   string `json:"mac"`
	Down  int64  `json:"down"`
	Up    int64  `json:"up"`
	Total int64  `json:"total"`
}

// Collector connects to netifyd and aggregates. All exported methods are
// safe for concurrent use.
type Collector struct {
	mu        sync.Mutex
	sockPath  string
	defApps   map[int64]string // application id -> tag (definitions event)
	flows     map[string]*flow
	agg       map[aggKey]*aggEntry
	hostOf    map[string]string     // app tag -> most-seen hostname
	series    map[string]*appSeries // app tag -> per-minute traffic ring
	unknown   int64                 // bytes without an app identity yet
	started   time.Time
	connected bool
}

// New creates a Collector for the netifyd socket at sockPath.
func New(sockPath string) *Collector {
	return &Collector{
		sockPath: sockPath,
		defApps:  map[int64]string{},
		flows:    map[string]*flow{},
		agg:      map[aggKey]*aggEntry{},
		hostOf:   map[string]string{},
		series:   map[string]*appSeries{},
		started:  time.Now(),
	}
}

// Run connects (with backoff) and consumes events until ctx is done.
// A missing socket file (netifyd not installed) is logged once and then
// waited on silently; connection drops after a working session are
// logged each time.
func (c *Collector) Run(ctx context.Context) {
	notifiedMissing := false
	for {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Stat(c.sockPath); err != nil {
			if !notifiedMissing {
				log.Printf("[netify] %s absent (is netifyd installed?); waiting for it silently", c.sockPath)
				notifiedMissing = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			continue
		}
		notifiedMissing = false
		backoff := 15 * time.Second
		if err := c.consume(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[netify] %v (retrying in %s)", err, backoff)
		}
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// consume reads frames from one socket connection until it drops.
func (c *Collector) consume(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.sockPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("[netify] connected to %s", c.sockPath)

	// Unblock the scanner on cancellation: reads alone would block
	// forever on an idle socket.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	type frame struct {
		Length int64 `json:"length"`
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024) // definitions lines are ~50KB
	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		var f frame
		if json.Unmarshal(line, &f) == nil && f.Length > 0 {
			continue // frame header; the payload is the next line
		}
		c.dispatch(line)
	}
	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
	return sc.Err()
}

// rawEvent carries only the fields shared by all events.
type rawEvent struct {
	Type      string          `json:"type"`
	Interface string          `json:"interface"`
	Internal  bool            `json:"internal"`
	Flow      json.RawMessage `json:"flow"`
}

// dispatch parses one payload line.
func (c *Collector) dispatch(line []byte) {
	var ev rawEvent
	if json.Unmarshal(line, &ev) != nil {
		return
	}
	switch ev.Type {
	case "definitions":
		c.storeDefinitions(line)
	case "flow":
		if ev.Internal {
			c.storeFlow(ev.Flow)
		}
	case "flow_stats", "flow_purge":
		if ev.Internal {
			c.flowBytes(ev.Flow, ev.Type == "flow_purge")
		}
	}
}

// definitionsEvent carries the id→tag maps. Applications and protocols
// are separate id spaces that collide, so only the application map is
// kept.
type definitionsEvent struct {
	Applications map[string]string `json:"applications"`
}

func (c *Collector) storeDefinitions(line []byte) {
	var ev definitionsEvent
	if json.Unmarshal(line, &ev) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, tag := range ev.Applications {
		// keys are decimal ids; ignore unparseable ones
		var id int64
		if _, err := fmt.Sscanf(k, "%d", &id); err != nil {
			continue
		}
		c.defApps[id] = tag
	}
}

// flowEvent mirrors the flow fact of `flow` and `flow_stats` events.
// The ports and addresses appear only on `flow`; counters only on
// `flow_stats`/`flow_purge`.
type flowEvent struct {
	Digest                  string `json:"digest"`
	DetectedApplication     int64  `json:"detected_application"`
	DetectedApplicationName string `json:"detected_application_name"`
	HostServerName          string `json:"host_server_name"`
	LocalMac                string `json:"local_mac"`
	LocalBytes              int64  `json:"local_bytes"`
	OtherBytes              int64  `json:"other_bytes"`
	TotalBytes              int64  `json:"total_bytes"`
}

// storeFlow upserts a flow's identity (mac, app, hostname).
func (c *Collector) storeFlow(raw json.RawMessage) {
	var ev flowEvent
	if json.Unmarshal(raw, &ev) != nil || ev.Digest == "" {
		return
	}
	mac := normalizeMAC(ev.LocalMac)
	if mac == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.flows[ev.Digest]
	if f == nil {
		if len(c.flows) >= 8192 { // flow table cap; LRU-ish by lastSeen
			c.pruneFlowsLocked()
		}
		f = &flow{}
		c.flows[ev.Digest] = f
	}
	f.mac = mac
	f.appID = ev.DetectedApplication
	if ev.DetectedApplicationName != "" {
		f.appTag = ev.DetectedApplicationName
	} else if tag := c.defApps[ev.DetectedApplication]; tag != "" {
		f.appTag = tag
	}
	if ev.HostServerName != "" {
		f.hostName = ev.HostServerName
	}
	f.lastSeen = time.Now()
}

// flowBytes applies one counter update. netifyd 4.4.7 quirk: flow_stats
// local/other bytes are deltas while the flow lives, but the final
// flow_purge reports zeros for both and only total_bytes is the flow's
// final cumulative count. The unaccounted tail is recovered by
// distributing the purge delta along the flow's observed directional
// split (50/50 before any split is known).
func (c *Collector) flowBytes(raw json.RawMessage, purge bool) {
	var ev flowEvent
	if json.Unmarshal(raw, &ev) != nil || ev.Digest == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	f := c.flows[ev.Digest]
	if f == nil {
		// Stats for a flow established before we connected: netifyd
		// never sends its identity, so its bytes go to the app-less
		// pool on the router's own row until the flow ends.
		if !purge {
			c.unknown += ev.LocalBytes + ev.OtherBytes
		}
		return
	}

	if purge {
		accumulated := f.up + f.down
		if delta := ev.TotalBytes - accumulated; delta > 0 {
			var upShare int64
			if accumulated > 0 {
				upShare = delta * f.up / accumulated
			} else {
				upShare = delta / 2
			}
			c.addAttribute(f, delta-upShare, upShare)
		}
		delete(c.flows, ev.Digest)
		return
	}

	if ev.LocalBytes > 0 || ev.OtherBytes > 0 {
		c.addAttribute(f, ev.OtherBytes, ev.LocalBytes)
	}
	if ev.TotalBytes > f.lastTotal {
		f.lastTotal = ev.TotalBytes
	}
	f.lastSeen = time.Now()
}

// addAttribute posts bytes to the flow's app × device aggregate.
func (c *Collector) addAttribute(f *flow, down, up int64) {
	f.down += down
	f.up += up
	if f.appTag == "" {
		c.unknown += down + up
		return
	}
	k := aggKey{tag: f.appTag, mac: f.mac}
	a := c.agg[k]
	if a == nil {
		a = &aggEntry{}
		c.agg[k] = a
	}
	a.down += down
	a.up += up
	if h := hostBase(f.hostName); h != "" {
		c.hostOf[f.appTag] = h
	}
	c.addSeriesAt(f.appTag, down, up, time.Now().Unix()/seriesBucketSecs)
}

// ── Per-app trend series ──────────────────────────────────────────────
// A fixed ring of one-minute buckets per app tag: cheap to maintain,
// small enough to keep 12h in memory while the UI is shown the last 2h.
const (
	seriesBucketSecs int64 = 60
	seriesKeep             = 720 // minutes retained in memory (12h)
	seriesEmit             = 120 // minutes served to the UI (2h)
)

type appSeries struct {
	base int64   // absolute bucket index of slot 0
	down []int64 // ring of seriesKeep slots
	up   []int64
}

// addSeriesAt credits a delta to the bucket at absolute index bucket,
// advancing the ring (zeroing evicted slots) when time has moved on.
func (c *Collector) addSeriesAt(tag string, down, up int64, bucket int64) {
	s := c.series[tag]
	if s == nil {
		// The current bucket is the ring's last slot, so the emitted
		// tail (the newest seriesEmit slots) is live from the first byte.
		s = &appSeries{base: bucket - (seriesKeep - 1), down: make([]int64, seriesKeep), up: make([]int64, seriesKeep)}
		c.series[tag] = s
	}
	if bucket >= s.base+seriesKeep { // ring full: slide forward
		shift := bucket - (s.base + seriesKeep) + 1
		if shift >= seriesKeep {
			clear(s.down)
			clear(s.up)
			s.base = bucket
		} else {
			copy(s.down, s.down[shift:])
			copy(s.up, s.up[shift:])
			clear(s.down[seriesKeep-shift:])
			clear(s.up[seriesKeep-shift:])
			s.base += shift
		}
	}
	if bucket < s.base { // ancient, already-evicted bucket: fold into the oldest slot
		bucket = s.base
	}
	pos := bucket - s.base
	s.down[pos] += down
	s.up[pos] += up
}

// idleFlow is how long a flow may go without updates before its table
// entry is dropped (its bytes are already in the aggregates).
const idleFlow = 15 * time.Minute

func (c *Collector) pruneFlowsLocked() {
	now := time.Now()
	for d, f := range c.flows {
		if now.Sub(f.lastSeen) > idleFlow {
			delete(c.flows, d)
		}
	}
	// Still over the cap: drop the oldest half.
	if len(c.flows) >= 8192 {
		type fs struct {
			d string
			t time.Time
		}
		all := make([]fs, 0, len(c.flows))
		for d, f := range c.flows {
			all = append(all, fs{d, f.lastSeen})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
		for i := 0; i < len(all)/2; i++ {
			delete(c.flows, all[i].d)
		}
	}
}

// Snapshot returns the aggregates, sorted for display. rowsByDevice
// optionally filters to one client MAC.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	type appAcc struct {
		down, up int64
		dev      map[string]*aggEntry
	}
	byApp := map[string]*appAcc{}
	for k, e := range c.agg {
		a := byApp[k.tag]
		if a == nil {
			a = &appAcc{dev: map[string]*aggEntry{}}
			byApp[k.tag] = a
		}
		a.down += e.down
		a.up += e.up
		d := a.dev[k.mac]
		if d == nil {
			d = &aggEntry{}
			a.dev[k.mac] = d
		}
		d.down += e.down
		d.up += e.up
	}

	snap := Snapshot{Started: c.started, Flows: len(c.flows)}
	for tag, a := range byApp {
		row := AppRow{Tag: tag, Name: appLabel(tag), Host: c.hostOf[tag], Down: a.down, Up: a.up, Total: a.down + a.up}
		if s := c.series[tag]; s != nil {
			n := seriesKeep
			if seriesEmit < n {
				n = seriesEmit
			}
			trend := Trend{BucketSec: int(seriesBucketSecs), Down: make([]int64, n), Up: make([]int64, n)}
			copy(trend.Down, s.down[seriesKeep-n:])
			copy(trend.Up, s.up[seriesKeep-n:])
			row.Trend = &trend
		}
		for mac, e := range a.dev {
			row.Device = append(row.Device, DeviceRow{MAC: mac, Down: e.down, Up: e.up, Total: e.down + e.up})
		}
		sort.Slice(row.Device, func(i, j int) bool { return row.Device[i].Total > row.Device[j].Total })
		snap.Apps = append(snap.Apps, row)
	}
	sort.Slice(snap.Apps, func(i, j int) bool { return snap.Apps[i].Total > snap.Apps[j].Total })
	snap.Unknown = c.unknown
	return snap
}

// appLabel turns the netify tag into a display name: "netify.netflix"
// -> "Netflix". Tags without the prefix pass through untouched.
func appLabel(tag string) string {
	t := strings.TrimPrefix(tag, "netify.")
	if t == "" || t == tag {
		return tag
	}
	words := strings.Fields(strings.NewReplacer("_", " ", ".", " ", "-", " ").Replace(t))
	for i, p := range words {
		if p != "" {
			words[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(words, " ")
}

// hostBase reduces an SNI to its base domain (one label + TLD is too
// coarse for e.g. co.uk, so keep the last two labels; good enough for
// display hints like "netflix.com").
func hostBase(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if i := strings.LastIndex(host, "."); i >= 0 {
		if j := strings.LastIndex(host[:i], "."); j >= 0 {
			return host[j+1:]
		}
		return host
	}
	return host
}

// normalizeMAC lower-cases and colon-formats a MAC from netifyd.
func normalizeMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 17 || strings.Count(s, ":") != 5 {
		return ""
	}
	return s
}
