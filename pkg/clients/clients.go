// Package clients collects per-LAN-client traffic accounting from nlbwmon
// (conntrack netlink counters), resolves friendly names from DHCP leases and
// neighbour states, computes live rates and pushes cumulative counters into
// VictoriaMetrics so per-client history is queryable.
package clients

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// Client is one LAN device as reported to the UI.
type Client struct {
	MAC      string  `json:"mac"`
	IP       string  `json:"ip"`
	Name     string  `json:"name"`
	Vendor   string  `json:"vendor,omitempty"` // MAC OUI vendor, may be empty
	Conns    int     `json:"conns"`
	RxTotal  int64   `json:"rx_total"` // bytes this accounting period
	TxTotal  int64   `json:"tx_total"`
	RxRate   float64 `json:"rx_rate"` // bytes/s (averaged over the poll interval)
	TxRate   float64 `json:"tx_rate"`
	Online   bool    `json:"online"`
	LastSeen int64   `json:"last_seen"` // unix ts of last poll with traffic
}

// evictAfter is how long a device may be absent from successful nlbw polls
// before it is dropped from the store (and so from the API table and the
// VictoriaMetrics push). Shorter absences keep the offline-with-history row.
const evictAfter = 24 * time.Hour

type sample struct {
	conns  int
	rx, tx int64
	at     time.Time
}

// nlbwAnchor is the rate baseline for one client: the counters at their
// last observed change plus the rate computed from that change (held
// between nlbwmon's 30s refreshes so panels don't flicker to zero).
type nlbwAnchor struct {
	rx, tx           int64
	at               time.Time
	rateRx, rateTx   float64
	rateAt           time.Time
}

// rateHold is how long a computed rate stays on display after the counters
// stop moving. Must comfortably exceed nlbwmon's refresh_interval (30s).
const rateHold = 45 * time.Second

// Store keeps the latest client snapshot and runs the poller.
type Store struct {
	mu          sync.RWMutex
	clients     map[string]*Client // by MAC
	anchor      map[string]nlbwAnchor // MAC -> counters at the last observed change (rate baseline)
	present     map[string]bool       // MACs listed in the previous successful poll (reappearance resets the rate baseline)
	seen        map[string]time.Time // MAC -> last successful poll listing it (drives eviction; unlike Client.LastSeen it ignores traffic)
	interval    time.Duration
	vmc         *vm.Client
	nlbwPath    string
	leasesAt    time.Time
	leases      map[string]string // MAC -> hostname (refreshed every 10 min)
	staticHosts map[string]string // MAC -> static lease name from /etc/config/dhcp
	hosts       map[string]string // IP -> hostname from /etc/hosts
	vendors     map[string]string // OUI -> vendor name (cached + persisted)
	namesAt     time.Time         // gate for the slow name-resolution cycle
	namesPath   string            // persisted vendor cache
	netSysDir   string            // /sys/class/net, overridable in tests
	httpClient  *http.Client
	havePolled  bool
}

// New creates a Store. vmURL may be empty to disable history pushes.
func New(interval time.Duration, vmURL string) *Store {
	s := &Store{
		clients:     map[string]*Client{},
		anchor:      map[string]nlbwAnchor{},
		present:     map[string]bool{},
		seen:        map[string]time.Time{},
		interval:    interval,
		leases:      map[string]string{},
		staticHosts: map[string]string{},
		hosts:       map[string]string{},
		vendors:     map[string]string{},
		namesPath:   "/tmp/cake-client-names.json",
		netSysDir:   "/sys/class/net",
		nlbwPath:    "/usr/sbin/nlbw",
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
	if p, err := exec.LookPath("nlbw"); err == nil {
		s.nlbwPath = p
	}
	s.loadNamesCache()
	return s
}

// Snapshot returns the current client list sorted by total traffic
// (descending), with MAC as a tie-breaker so the order is deterministic.
func (s *Store) Snapshot() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, *c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := out[i].RxTotal+out[i].TxTotal, out[j].RxTotal+out[j].TxTotal
		if ti != tj {
			return ti > tj
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

// Name returns the friendly name for a MAC (or the short MAC if unknown).
func (s *Store) Name(mac string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.clients[mac]; ok && c.Name != "" {
		return c.Name
	}
	return mac
}

// Available reports whether nlbw data has been collected at least once.
func (s *Store) Available() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients) > 0 || s.havePolled
}

// Reanchor drops every rate baseline, e.g. after the watchdog restarted
// nlbwmon. A restart re-dumps conntrack, which adds the surviving entries'
// byte counters on top of the persisted database — a one-time upward step
// that is bookkeeping, not traffic. Re-anchoring keeps that step from
// being divided into a fake rate spike.
func (s *Store) Reanchor() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.anchor = map[string]nlbwAnchor{}
	s.present = map[string]bool{}
}

// Run starts the poll loop until ctx is cancelled.
func (s *Store) Run(ctx context.Context, vmClient *vm.Client) {
	s.vmc = vmClient
	if err := s.poll(); err != nil {
		log.Printf("[clients] nlbwmon poll failed: %v (is nlbwmon installed?)", err)
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.poll(); err != nil {
				log.Printf("[clients] nlbwmon poll failed: %v", err)
			}
		}
	}
}

// pollTimeout caps one nlbw CSV dump. The nlbw client talks to the nlbwmon
// daemon over a socket and can hang indefinitely — observed live as stray
// `nlbw -c csv` processes piling up and the poll loop frozen on .Output()
// with no data moving. Without a deadline a single hang stops per-client
// collection forever (the watchdog restarting the daemon does not unblock
// a wedged client process).
const pollTimeout = 5 * time.Second

func (s *Store) poll() error {
	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, s.nlbwPath, "-c", "csv", "-g", "mac", "-q").Output()
	if err != nil {
		s.mu.Lock()
		s.havePolled = false
		s.mu.Unlock()
		return err
	}

	now := time.Now()
	type parsed struct {
		mac   string
		conns int
		rx    int64
		tx    int64
	}
	var rows []parsed
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		mac := f[0]
		if !strings.Contains(mac, ":") { // skip header / junk
			continue
		}
		conns, _ := strconv.Atoi(f[1])
		rx, _ := strconv.ParseInt(f[2], 10, 64)
		tx, _ := strconv.ParseInt(f[4], 10, 64)
		rows = append(rows, parsed{mac, conns, rx, tx})
	}

	s.refreshNames()
	online, ips := readNeigh()

	s.mu.Lock()
	s.havePolled = true

	// Traffic the kernel attributes to the router's own interface MACs is
	// not a LAN client — nlbwmon can report the bridge/AP link itself
	// (e.g. a phantom "device-xxxx" row for the OpenWrt bridge). Drop those
	// rows, and forget any entry an earlier version may have recorded.
	self := localMACs(s.netSysDir)
	for mac := range self {
		if c, ok := s.clients[mac]; ok {
			delete(s.clients, c.MAC)
			delete(s.seen, c.MAC)
			delete(s.anchor, c.MAC)
		}
	}
	rows = slices.DeleteFunc(rows, func(r parsed) bool { return self[strings.ToLower(r.mac)] })

	samples := map[string]sample{}
	for _, r := range rows {
		samples[r.mac] = sample{conns: r.conns, rx: r.rx, tx: r.tx, at: now}
	}

	for _, r := range rows {
		c := s.clients[r.mac]
		if c == nil {
			c = &Client{MAC: r.mac}
			s.clients[r.mac] = c
		}
		c.Conns = r.conns
		c.RxTotal = r.rx
		c.TxTotal = r.tx
		c.IP = ips[strings.ToLower(r.mac)]
		if r.mac == "00:00:00:00:00:00" {
			// nlbwmon's catch-all for traffic it cannot attribute to a MAC
			// (locally originated or non-bridge interfaces).
			c.Name = "untracked"
			c.Vendor = ""
		} else {
			c.Name = s.nameFor(r.mac, c.IP)
			c.Vendor = s.vendorFor(r.mac)
		}

		// Rate from the last counter CHANGE, not the last poll: nlbwmon
		// refreshes its counters every refresh_interval (30s), so with a
		// 1s poll loop the raw prev-sample difference is a spike-train —
		// 29 zeros then one huge burst — and every panel reading it
		// (topology links, client table) shows ~0. Dividing by the time
		// the counters actually took to move gives a true average rate,
		// held for rateHold so displays stay steady between refreshes.
		c.RxRate, c.TxRate = 0, 0
		a := s.anchor[r.mac]
		switch {
		case a.at.IsZero() || !s.present[r.mac] || r.rx < a.rx || r.tx < a.tx:
			// First sighting, reappearance after absence (traffic during
			// the gap happened at unknown times), or a counter reset
			// (nlbwmon restart / accounting rollover): re-anchor silently.
			s.anchor[r.mac] = nlbwAnchor{rx: r.rx, tx: r.tx, at: now}
		case r.rx > a.rx || r.tx > a.tx:
			if dt := now.Sub(a.at).Seconds(); dt > 0 {
				a.rateRx = float64(r.rx-a.rx) / dt
				a.rateTx = float64(r.tx-a.tx) / dt
				a.rateAt = now
				c.RxRate, c.TxRate = a.rateRx, a.rateTx
				c.LastSeen = now.Unix()
			}
			a.rx, a.tx, a.at = r.rx, r.tx, now
			s.anchor[r.mac] = a
		default:
			// Counters unchanged since the last change: hold the rate.
			if now.Sub(a.rateAt) < rateHold {
				c.RxRate, c.TxRate = a.rateRx, a.rateTx
			}
		}
		c.Online = online[strings.ToLower(r.mac)] || c.RxRate > 0 || c.TxRate > 0
		s.seen[r.mac] = now
	}

	// Devices absent from this (successful) poll are gone: mark them offline
	// and clear their live figures, but keep totals/name/vendor/LastSeen so
	// the table retains their history. After evictAfter of absence they are
	// dropped entirely so the map and the VM series cannot grow forever.
	for mac, c := range s.clients {
		if _, present := samples[mac]; present {
			continue
		}
		seen, ok := s.seen[mac]
		if !ok { // never recorded (should not happen): start the clock now
			seen = now
			s.seen[mac] = now
		}
		if now.Sub(seen) > evictAfter {
			delete(s.clients, mac)
			delete(s.seen, mac)
			delete(s.anchor, mac)
			continue
		}
		c.Online = false
		c.RxRate, c.TxRate = 0, 0
		c.Conns = 0
	}

	// Rate baselines (anchors) intentionally survive absence so a client
	// that reappears mid-refresh still gets a correct rate denominator;
	// the presence map is what detects the reappearance.
	s.present = make(map[string]bool, len(samples))
	for mac := range samples {
		s.present[mac] = true
	}
	s.mu.Unlock() // release before the (potentially slow) VM import

	if s.vmc != nil {
		s.pushVM(now)
	}
	return nil
}

// pushVM imports cumulative per-client counters into VictoriaMetrics.
func (s *Store) pushVM(now time.Time) {
	s.mu.RLock()
	var b strings.Builder
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	for _, c := range s.clients {
		name := sanitizeLabel(c.Name)
		mac := sanitizeLabel(c.MAC)
		ip := sanitizeLabel(c.IP)
		b.WriteString("client_bytes_total{mac=\"" + mac + "\",name=\"" + name + "\",ip=\"" + ip + "\",dir=\"rx\"} " +
			strconv.FormatInt(c.RxTotal, 10) + " " + ts + "\n")
		b.WriteString("client_bytes_total{mac=\"" + mac + "\",name=\"" + name + "\",ip=\"" + ip + "\",dir=\"tx\"} " +
			strconv.FormatInt(c.TxTotal, 10) + " " + ts + "\n")
		b.WriteString("client_conns{mac=\"" + mac + "\",name=\"" + name + "\"} " +
			strconv.Itoa(c.Conns) + " " + ts + "\n")
	}
	s.mu.RUnlock()
	if b.Len() == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.vmc.Import(ctx, b.String()); err != nil {
		log.Printf("[clients] VM import failed: %v", err)
	}
}

func sanitizeLabel(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}

// refreshNames re-reads fast local sources every 10 minutes and slowly
// resolves MAC vendors for devices that still have no name. Runs only from
// the poll goroutine, so its maps need no extra locking.
func (s *Store) refreshNames() {
	if time.Since(s.namesAt) < 10*time.Minute {
		return
	}
	s.namesAt = time.Now()
	s.refreshLeases()
	s.refreshHosts()
	s.resolveVendors()
}

// refreshLeases re-reads /tmp/dhcp.leases (the DHCP hostname source).
func (s *Store) refreshLeases() {
	out, err := exec.Command("cat", "/tmp/dhcp.leases").Output()
	if err != nil {
		return
	}
	leases := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		mac := strings.ToLower(f[1])
		host := f[3]
		if host == "*" || host == "" {
			continue
		}
		leases[mac] = host
	}
	s.leases = leases
	s.refreshStaticHosts()
}

// refreshStaticHosts reads MAC -> name from the static DHCP lease entries in
// /etc/config/dhcp. Unlike the live lease file, this works for devices that
// are powered off and have never contacted dnsmasq since the lease was added.
func (s *Store) refreshStaticHosts() {
	out, err := exec.Command("cat", "/etc/config/dhcp").Output()
	if err != nil {
		return
	}
	s.parseStaticHosts(string(out))
}

// parseStaticHosts parses UCI dhcp config text into the staticHosts map.
func (s *Store) parseStaticHosts(conf string) {
	static := map[string]string{}
	inHost := false
	var name, mac string
	flush := func() {
		if inHost && name != "" && mac != "" {
			static[mac] = name
		}
		name, mac = "", ""
	}
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "config" && len(f) > 1 && f[1] == "host":
			flush()
			inHost = true
		case f[0] == "config":
			flush()
			inHost = false
		case inHost && f[0] == "option" && len(f) >= 3:
			key := f[1]
			val := strings.Trim(strings.Join(f[2:], " "), "'\"")
			switch key {
			case "name":
				name = val
			case "mac":
				mac = strings.ToLower(val)
			}
		}
	}
	flush()
	s.staticHosts = static
}

// refreshHosts reads static IP -> hostname mappings from /etc/hosts.
func (s *Store) refreshHosts() {
	out, err := exec.Command("cat", "/etc/hosts").Output()
	if err != nil {
		return
	}
	hosts := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		ip := f[0]
		if ip == "127.0.0.1" || ip == "::1" {
			continue
		}
		if hosts[ip] == "" {
			hosts[ip] = f[1]
		}
	}
	s.hosts = hosts
}

// loadNamesCache restores the persisted vendor cache from /tmp.
func (s *Store) loadNamesCache() {
	b, err := os.ReadFile(s.namesPath)
	if err != nil {
		return
	}
	var cache map[string]string
	if json.Unmarshal(b, &cache) == nil {
		s.vendors = cache
	}
}

// saveNamesCache persists the vendor cache so restarts don't re-query.
func (s *Store) saveNamesCache() {
	b, err := json.Marshal(s.vendors)
	if err != nil {
		return
	}
	tmp := s.namesPath + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, s.namesPath)
	}
}

// resolveVendors looks up OUI vendor names for MACs that still have no name.
// Queries the public macvendors API politely (max 3 per cycle, ~1 rps) and
// caches results both in memory and on disk. "unknown" marks MACs with no
// vendor so they are not re-queried.
func (s *Store) resolveVendors() {
	const maxLookups = 3
	n := 0
	for mac := range s.clients {
		oui := macToOUI(mac)
		if oui == "" || oui == "randomized" {
			continue // no OUI, or privacy MAC: a vendor lookup is pointless
		}
		if _, done := s.vendors[oui]; done {
			continue
		}
		if n >= maxLookups {
			break
		}
		vendor := s.queryVendor(oui)
		if vendor != "" {
			// Empty means a transient failure (offline, rate limited):
			// leave the OUI uncached so the next cycle retries.
			s.vendors[oui] = vendor
		}
		n++
		if n < maxLookups {
			time.Sleep(1100 * time.Millisecond) // stay under the 1 rps limit
		}
	}
	if n > 0 {
		s.saveNamesCache()
	}
}

// macToOUI normalizes a MAC to its "aa:bb:cc" prefix, or "" if malformed.
// Locally administered (privacy-randomized) addresses return "randomized".
func macToOUI(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	f := strings.Split(mac, ":")
	if len(f) < 3 {
		return ""
	}
	oui := strings.Join(f[:3], ":")
	first, err := strconv.ParseInt(f[0], 16, 32)
	if err != nil {
		return ""
	}
	if first&0x02 != 0 { // locally administered bit: phone/laptop random MAC
		return "randomized"
	}
	return oui
}

// queryVendor fetches the vendor name for one OUI from macvendors.
func (s *Store) queryVendor(oui string) string {
	resp, err := s.httpClient.Get("https://api.macvendors.com/" + oui)
	if err != nil {
		return "" // offline: retry next cycle
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode == 404 {
		return "unknown" // no vendor for this OUI; cache the negative
	}
	if resp.StatusCode != 200 {
		return "" // rate limited or error: leave uncached, retry later
	}
	return cleanVendor(string(body))
}

// cleanVendor trims legal suffixes: "Apple, Inc." -> "Apple".
func cleanVendor(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, ","); i > 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// zeroMAC is lo's address; nlbwmon's all-zero row is the "untracked"
// catch-all, not the router, so an all-zero interface address is skipped.
const zeroMAC = "00:00:00:00:00:00"

// localMACs returns the lower-case MAC addresses of the host's own network
// interfaces, read from /sys/class/net/*/address. dir is the sysfs net
// directory, overridable in tests. An empty map means "unknown" (the sysfs
// tree is unavailable); in that case nothing is filtered.
func localMACs(dir string) map[string]bool {
	macs := map[string]bool{}
	ifaces, err := os.ReadDir(dir)
	if err != nil {
		return macs
	}
	for _, iface := range ifaces {
		b, err := os.ReadFile(filepath.Join(dir, iface.Name(), "address"))
		if err != nil {
			continue
		}
		if m := strings.ToLower(strings.TrimSpace(string(b))); m != "" && m != zeroMAC {
			macs[m] = true
		}
	}
	return macs
}

// nameFor resolves the friendliest name for a device: DHCP hostname, then
// /etc/hosts by IP, then vendor-derived, then a stable device-xxxx fallback.
func (s *Store) nameFor(mac, ip string) string {
	if name := s.leases[mac]; name != "" {
		return name
	}
	if name := s.staticHosts[mac]; name != "" {
		return name
	}
	if ip != "" {
		if name := s.hosts[ip]; name != "" {
			return name
		}
	}
	oui := macToOUI(mac)
	if vendor := s.vendors[oui]; vendor != "" && vendor != "unknown" {
		return vendor + " " + macSuffix(mac)
	}
	return "device-" + macSuffix(mac)
}

// vendorFor returns the display vendor label, if any.
func (s *Store) vendorFor(mac string) string {
	oui := macToOUI(mac)
	switch oui {
	case "":
		return ""
	case "randomized":
		return "randomized MAC"
	}
	if v := s.vendors[oui]; v != "" && v != "unknown" {
		return v
	}
	return ""
}

// macSuffix returns the last two octets, e.g. "33:44" from fa:69:..:33:44.
func macSuffix(mac string) string {
	f := strings.Split(mac, ":")
	if len(f) < 2 {
		return mac
	}
	return strings.Join(f[len(f)-2:], "")
}

// readNeigh runs `ip neigh show` once and returns both the MACs the kernel
// considers currently reachable on br-lan and a MAC -> IP map (first entry
// per MAC, any device). MAC keys are lower-cased. On error both maps are
// empty.
// staleKeep is how long a STALE neighbour entry may still count as
// "online": the kernel keeps STALE entries for hours after a device
// disappears (a PS5 gone for 5 h still showed a STALE entry), but a
// connected-but-idle device refreshes its entry (or gets traffic) within
// minutes. Beyond this window a STALE entry is a ghost.
const staleKeep = 600 // seconds

func readNeigh() (online map[string]bool, ips map[string]string) {
	online, ips = map[string]bool{}, map[string]string{}
	out, err := exec.Command("ip", "-s", "neigh", "show").Output()
	if err != nil {
		return online, ips
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// format: [IP] [dev IFACE] [lladdr MAC] [router] [used A/B/Cprobes N] [STATE]
		if len(f) < 4 {
			continue
		}
		var dev, mac string
		var usedSec int64 = -1 // -1: no recency stamp
		for i := 1; i+1 < len(f); i++ {
			switch strings.ToLower(f[i]) {
			case "dev":
				dev = f[i+1]
			case "lladdr":
				mac = strings.ToLower(f[i+1])
			case "used":
				// "A/B/Cprobes N": A/B/C are seconds since the entry was
				// last used/updated/confirmed — take the most recent.
				nums := strings.Split(strings.Split(f[i+1], "probes")[0], "/")
				for _, n := range nums {
					if v, err := strconv.ParseInt(n, 10, 64); err == nil && (usedSec < 0 || v < usedSec) {
						usedSec = v
					}
				}
			}
		}
		if mac == "" {
			continue
		}
		if _, ok := ips[mac]; !ok {
			ips[mac] = f[0]
		}
		state := strings.ToLower(f[len(f)-1])
		if dev != "br-lan" {
			continue
		}
		switch {
		case state == "reachable" || state == "delay" || state == "probe":
			online[mac] = true
		case state == "stale" && usedSec >= 0 && usedSec < staleKeep:
			online[mac] = true // recently used despite the STALE state
		}
	}
	return online, ips
}
