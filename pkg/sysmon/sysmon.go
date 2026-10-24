// Package sysmon polls router subsystems that sit outside the CAKE data
// path: the Cloudflare WARP exit tunnel (WireGuard), system clock drift
// (SNTP against the public pool), and NVMe storage health (smartctl) with
// reboot tracking. Each poller keeps a small mutex-guarded snapshot that
// health checks read without blocking the poll loop.
package sysmon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/log"
)

// ---------- WARP exit tunnel ----------

// WarpState is the latest WARP tunnel snapshot from `wg show wg0 dump`.
type WarpState struct {
	Available  bool      // wg0 exists and wg answered for it
	PeerCount  int       // configured peers (1 for this WARP setup)
	Endpoint   string    // remote peer endpoint, e.g. 162.159.192.1:2408
	Handshake  time.Time // zero if the peer never completed a handshake
	RxBytes    uint64
	TxBytes    uint64
	RxPerS     float64 // bytes/s, computed by diffing consecutive polls
	TxPerS     float64
	RatesKnown bool // false until a second poll exists to diff against
	At         time.Time
}

// WarpPoller refreshes the tunnel snapshot every 10 seconds. Rates are
// 10-second averages of the wg byte counters — fresh enough to feel live,
// still smooth enough to read.
type WarpPoller struct {
	mu       sync.RWMutex
	state    WarpState
	prevRx   uint64
	prevTx   uint64
	prevRxOK bool
}

// NewWarp starts the poller with a synchronous first snapshot.
func NewWarp(ctx context.Context) *WarpPoller {
	p := &WarpPoller{}
	p.refresh()
	go p.loop(ctx)
	return p
}

// Snapshot returns the latest known tunnel state.
func (p *WarpPoller) Snapshot() WarpState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *WarpPoller) loop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh()
		}
	}
}

// wgDump lines: first row is the interface (pubkey, privkey, port, fwmark),
// each following row is one peer (pubkey, presharedkey, endpoint,
// allowed-ips, latest-handshake unix, rx bytes, tx bytes, keepalive).
func (p *WarpPoller) refresh() {
	st := WarpState{At: time.Now()}
	out, err := exec.Command("wg", "show", "wg0", "dump").Output()
	if err == nil {
		for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) < 5 {
				continue
			}
			if i == 0 {
				continue // interface row
			}
			st.Available = true
			st.PeerCount++
			st.Endpoint = f[2]
			if hs, err := strconv.ParseInt(f[4], 10, 64); err == nil && hs > 0 {
				st.Handshake = time.Unix(hs, 0)
			}
			if len(f) > 5 {
				st.RxBytes, _ = strconv.ParseUint(f[5], 10, 64)
			}
			if len(f) > 6 {
				st.TxBytes, _ = strconv.ParseUint(f[6], 10, 64)
			}
		}
	}

	// Derive flow rates by diffing against the previous poll. The counters
	// tell us the tunnel carries traffic; without the diff we could not tell
	// a healthy idle tunnel from one that silently stopped passing packets.
	if st.Available && st.PeerCount > 0 {
		if p.prevRxOK {
			elapsed := 30.0
			if !p.state.At.IsZero() {
				elapsed = st.At.Sub(p.state.At).Seconds()
			}
			if elapsed > 0 {
				// diffRate yields 0 when a counter goes backwards (wg
				// restart / peer re-added) instead of wrapping the uint64.
				st.RxPerS = diffRate(st.RxBytes, p.prevRx, elapsed)
				st.TxPerS = diffRate(st.TxBytes, p.prevTx, elapsed)
				st.RatesKnown = true
			}
		}
		p.prevRx, p.prevTx, p.prevRxOK = st.RxBytes, st.TxBytes, true
	}

	p.mu.Lock()
	p.state = st
	p.mu.Unlock()
}

// ---------- Clock drift (SNTP) ----------

// ClockState is the latest clock-offset measurement. The primary reference
// is SNTP against the public pool; some ISPs block UDP/123, so the poller
// falls back to the HTTP Date header from an anycast endpoint. HTTP Date
// only has second resolution, so HTTP-sourced measurements get looser
// thresholds in the health check.
type ClockState struct {
	Available bool
	OffsetMs  float64 // positive = router clock behind reference time
	Server    string
	Source    string // "sntp" or "http"
	CheckedAt time.Time
}

// ClockPoller measures drift every 5 minutes.
type ClockPoller struct {
	mu    sync.RWMutex
	state ClockState
}

// NewClock starts the poller with a synchronous first measurement.
func NewClock(ctx context.Context) *ClockPoller {
	p := &ClockPoller{}
	p.refresh()
	go p.loop(ctx)
	return p
}

// Snapshot returns the latest known clock state.
func (p *ClockPoller) Snapshot() ClockState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *ClockPoller) loop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh()
		}
	}
}

// ntpServers are queried by hostname so the pool can rotate IPs.
var ntpServers = []string{"pool.ntp.org:123", "time.google.com:123"}

// httpDateServers are anycast edges that reliably emit a Date header.
var httpDateServers = []string{"https://www.google.com", "https://1.1.1.1"}

func (p *ClockPoller) refresh() {
	now := time.Now()
	for _, srv := range ntpServers {
		off, ok := sntpOffset(srv)
		if !ok {
			continue
		}
		p.mu.Lock()
		p.state = ClockState{Available: true, OffsetMs: off, Server: srv, Source: "sntp", CheckedAt: now}
		p.mu.Unlock()
		return
	}
	// UDP/123 is blocked on some ISPs — fall back to the HTTP Date header,
	// which large anycast edges answer reliably (second resolution only).
	for _, srv := range httpDateServers {
		off, ok := httpDateOffset(srv)
		if !ok {
			continue
		}
		p.mu.Lock()
		p.state = ClockState{Available: true, OffsetMs: off, Server: srv, Source: "http", CheckedAt: now}
		p.mu.Unlock()
		return
	}
	p.mu.Lock()
	p.state = ClockState{Available: false, CheckedAt: now}
	p.mu.Unlock()
}

// httpDateOffset reads the Date header of an HTTPS endpoint and returns the
// offset between reference time and the local clock, in milliseconds.
func httpDateOffset(url string) (float64, bool) {
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Head(url)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	date := resp.Header.Get("Date")
	if date == "" {
		return 0, false
	}
	serverTime, err := http.ParseTime(date)
	if err != nil {
		return 0, false
	}
	return serverTime.Sub(time.Now()).Seconds() * 1000, true
}

// sntpOffset sends one SNTPv4 client request and returns the clock offset in
// milliseconds, estimated as server time minus the midpoint of the local
// send/receive timestamps.
func sntpOffset(server string) (float64, bool) {
	d := &net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.Dial("udp", server)
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	req := make([]byte, 48)
	req[0] = 0x24 // leap=0, version=4, mode=3 (client)
	binary.BigEndian.PutUint32(req[12:], uint32(rand.Int31n(1<<31-1)))

	send := time.Now()
	if _, err := conn.Write(req); err != nil {
		return 0, false
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, false
	}
	recv := time.Now()

	// Server transmit timestamp: seconds + fraction since NTP era 1900.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	if secs == 0 {
		return 0, false // kiss-of-death / zero timestamp
	}
	serverTime := time.Unix(int64(secs)-2208988800, int64(float64(frac)/4294967296*1e9))
	offset := serverTime.Sub(send.Add(recv.Sub(send)/2)).Seconds() * 1000
	return offset, true
}

// ---------- NVMe storage health + reboot tracking ----------

// DiskState is the latest NVMe SMART snapshot plus boot tracking.
type DiskState struct {
	Available      bool    // smartctl present and device readable
	PercentUsed    float64 // NVMe "percentage used" (wear indicator)
	AvailableSpare float64 // percent of reserved blocks remaining; meaningful only if SpareKnown
	// SpareKnown is true when the SMART output actually contained an
	// available-spare value. A plain float64 can't tell an absent field from
	// a genuine 0%, so consumers must check this before judging the spare.
	SpareKnown      bool
	MediaErrors     uint64
	CriticalWarning uint64
	TempC           float64
	UnsafeShutdowns uint64 // lifetime count of unclean shutdowns (power cuts)
	// Boot tracking: the monitor notices when the router came back up.
	BootID        string    // current kernel boot_id
	LastReboot    time.Time // zero if no reboot was observed by this monitor
	RebootSpotted bool      // true while the reboot is recent (<24h)
}

type bootFile struct {
	BootID string `json:"boot_id"`
}

// statePath persists the last-seen boot_id so a reboot between monitor runs
// is noticed even if the monitor itself was down at the time. /opt holds the
// monitoring data on the NVMe, so it survives reboots.
const statePath = "/opt/monitoring/openwrt-view-boot-state.json"

// DiskPoller refreshes SMART data every 10 minutes.
type DiskPoller struct {
	mu    sync.RWMutex
	state DiskState
}

// NewDisk starts the poller with a synchronous first snapshot.
func NewDisk(ctx context.Context, dev string) *DiskPoller {
	p := &DiskPoller{}
	p.refresh(dev)
	go p.loop(ctx, dev)
	return p
}

// Snapshot returns the latest known disk state.
func (p *DiskPoller) Snapshot() DiskState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *DiskPoller) loop(ctx context.Context, dev string) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh(dev)
		}
	}
}

func (p *DiskPoller) refresh(dev string) {
	st := DiskState{BootID: bootID()}

	// Reboot tracking: compare the current boot_id against the persisted one.
	var prev bootFile
	if b, err := os.ReadFile(statePath); err == nil {
		if json.Unmarshal(b, &prev) == nil && prev.BootID != "" && prev.BootID != st.BootID {
			up := uptimeSec()
			if up > 0 {
				st.LastReboot = time.Now().Add(-time.Duration(up * float64(time.Second)))
				st.RebootSpotted = time.Since(st.LastReboot) < 24*time.Hour
				log.Logger.Info().Time("boot_at", st.LastReboot).Msg("router reboot detected (boot_id changed)")
			}
		}
	}
	if st.LastReboot.IsZero() {
		// Same boot as before — but check whether a reboot is still recent
		// enough to mention (this also survives monitor restarts).
		if _, err := os.ReadFile(statePath); err == nil && prev.BootID != "" && prev.BootID == st.BootID {
			up := uptimeSec()
			if up > 0 && up < 24*3600 {
				st.LastReboot = time.Now().Add(-time.Duration(up * float64(time.Second)))
				st.RebootSpotted = true
			}
		}
	}
	if b, err := json.Marshal(bootFile{BootID: st.BootID}); err == nil {
		_ = os.MkdirAll("/opt/monitoring", 0o755)
		_ = os.WriteFile(statePath, b, 0o644)
	}

	if out, err := exec.Command("nvme", "smart-log", "-o", "json", dev).Output(); err == nil {
		parseNvmeCLI(out, &st)
	} else if out, err := exec.Command("smartctl", "-A", "-j", dev).Output(); err == nil {
		parseSmartctl(out, &st)
	}

	p.mu.Lock()
	p.state = st
	p.mu.Unlock()
}

// parseNvmeCLI fills st from `nvme smart-log -o json` output. nvme-cli
// reports temperature in Kelvin. Leaves st untouched on undecodable JSON.
func parseNvmeCLI(out []byte, st *DiskState) {
	var raw struct {
		CriticalWarning float64  `json:"critical_warning"`
		Temperature     float64  `json:"temperature"`
		AvailSpare      *float64 `json:"avail_spare"` // pointer: absent vs reported 0
		PercentUsed     float64  `json:"percent_used"`
		MediaErrors     float64  `json:"media_errors"`
		UnsafeShutdowns float64  `json:"unsafe_shutdowns"`
	}
	if json.Unmarshal(out, &raw) != nil {
		return
	}
	st.Available = true
	st.PercentUsed = raw.PercentUsed
	if raw.AvailSpare != nil {
		st.AvailableSpare = *raw.AvailSpare
		st.SpareKnown = true
	}
	st.MediaErrors = uint64(raw.MediaErrors)
	st.CriticalWarning = uint64(raw.CriticalWarning)
	st.UnsafeShutdowns = uint64(raw.UnsafeShutdowns)
	st.TempC = raw.Temperature
	if st.TempC > 200 {
		st.TempC -= 273.15
	}
}

// parseSmartctl fills st from `smartctl -A -j` output (fallback path).
// smartmontools reports temperature in Celsius. Leaves st untouched on
// undecodable JSON.
func parseSmartctl(out []byte, st *DiskState) {
	var raw struct {
		NVMe struct {
			PercentUsed    float64  `json:"percent_used"`
			AvailableSpare *float64 `json:"available_spare"` // pointer: absent vs reported 0
			MediaErrors    uint64   `json:"media_errors"`
			CriticalWarn   uint64   `json:"critical_warning"`
			Temperature    float64  `json:"temperature"`
		} `json:"nvme_smart_health_information_log"`
	}
	if json.Unmarshal(out, &raw) != nil {
		return
	}
	st.Available = true
	st.PercentUsed = raw.NVMe.PercentUsed
	if raw.NVMe.AvailableSpare != nil {
		st.AvailableSpare = *raw.NVMe.AvailableSpare
		st.SpareKnown = true
	}
	st.MediaErrors = raw.NVMe.MediaErrors
	st.CriticalWarning = raw.NVMe.CriticalWarn
	st.TempC = raw.NVMe.Temperature
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func uptimeSec() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	up, _ := strconv.ParseFloat(fields[0], 64)
	return up
}

// ---------- Firewall counters (unsolicited WAN traffic) ----------

// FWState is the latest snapshot of the passive WAN firewall counters that
// sit at the end of the input_wan/forward_wan chains (installed via
// /usr/share/nftables.d/ruleset-post/40-openwrt-view.nft). They count exactly
// the packets fw4 is about to policy-drop: unsolicited internet noise.
type FWState struct {
	Available      bool
	InDropsPerMin  float64 // unsolicited inbound, per minute
	FwdDropsPerMin float64 // unsolicited forwarded, per minute
	Median         float64 // median recent total rate — the network's own baseline
	TotalIn        uint64
	TotalFwd       uint64
	At             time.Time
}

// fwHistCap keeps ~2h of per-poll rates for the deviation-based verdict.
const fwHistCap = 240

// FWPoller refreshes the counters every 30 seconds and keeps a rolling rate
// history so the health check can compare "now" against this network's own
// normal background-scan level instead of a fixed threshold.
type FWPoller struct {
	mu     sync.RWMutex
	state  FWState
	prevIn uint64
	prevFw uint64
	prevOK bool
	hist   []float64 // per-minute total rates, most recent last
}

// NewFW starts the poller with a synchronous first snapshot.
func NewFW(ctx context.Context) *FWPoller {
	p := &FWPoller{}
	p.refresh()
	go p.loop(ctx)
	return p
}

// Snapshot returns the latest known firewall counter state.
func (p *FWPoller) Snapshot() FWState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// History returns a copy of the rolling per-minute rate samples.
func (p *FWPoller) History() []float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]float64, len(p.hist))
	copy(out, p.hist)
	return out
}

func (p *FWPoller) loop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh()
		}
	}
}

// nftCounterPackets runs `nft list chain` and returns the packet count of
// the first rule whose text contains the given needle.
func nftCounterPackets(chain string, needle string) (uint64, bool) {
	out, err := exec.Command("nft", "list", "chain", "inet", "fw4", chain).Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		if i := strings.Index(line, "counter packets "); i >= 0 {
			rest := line[i+len("counter packets "):]
			if j := strings.IndexByte(rest, ' '); j > 0 {
				v, err := strconv.ParseUint(rest[:j], 10, 64)
				return v, err == nil
			}
		}
	}
	return 0, false
}

// medianRate returns the median of the rolling rate samples (the network's
// own background-scan baseline).
func medianRate(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	return sorted[len(sorted)/2]
}

func (p *FWPoller) refresh() {
	st := FWState{At: time.Now()}

	inEnd, okIn := nftCounterPackets("input_wan", "openwrt-view: unsolicited inbound")
	inRej, okRej := nftCounterPackets("reject_from_wan", "jump handle_reject")
	fwEnd, okFw := nftCounterPackets("forward_wan", "openwrt-view: unsolicited forward")
	st.TotalIn = inEnd + inRej
	st.TotalFwd = fwEnd
	st.Available = okIn && okRej && okFw

	if st.Available && p.prevOK {
		elapsed := 30.0
		if !p.state.At.IsZero() {
			elapsed = st.At.Sub(p.state.At).Seconds()
		}
		if elapsed > 0 {
			// Counters reset to zero on firewall reloads. Compare as
			// unsigned before subtracting (diffRate): subtracting first
			// wraps the uint64 to ~1.8e19 and a float clamp never fires.
			// A reset interval reads as 0; the new counter becomes the
			// baseline below.
			st.InDropsPerMin = diffRate(st.TotalIn, p.prevIn, elapsed) * 60
			st.FwdDropsPerMin = diffRate(st.TotalFwd, p.prevFw, elapsed) * 60
			p.hist = append(p.hist, st.InDropsPerMin+st.FwdDropsPerMin)
			if len(p.hist) > fwHistCap {
				p.hist = p.hist[len(p.hist)-fwHistCap:]
			}
			st.Median = medianRate(p.hist)
		}
	}
	p.prevIn, p.prevFw, p.prevOK = st.TotalIn, st.TotalFwd, st.Available

	p.mu.Lock()
	p.state = st
	p.mu.Unlock()
}

// ---------- grouped access for the health package ----------

// Pollers groups all sysmon pollers so the health package takes a single
// (nil-safe) argument.
type Pollers struct {
	Warp  *WarpPoller
	Clock *ClockPoller
	Disk  *DiskPoller
	FW    *FWPoller
	Conn  *ConnPoller
}

// NewAll starts every sysmon poller.
func NewAll(ctx context.Context) *Pollers {
	return &Pollers{
		Warp:  NewWarp(ctx),
		Clock: NewClock(ctx),
		Disk:  NewDisk(ctx, "/dev/nvme0"),
		FW:    NewFW(ctx),
		Conn:  NewConntrack(ctx),
	}
}
