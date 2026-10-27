// Package ebpfacct provides per-device traffic accounting with an eBPF
// program attached to a LAN interface's TC hooks. The kernel counts bytes
// per client MAC inline on the packet path, so there is no feed to stall
// and no state to reconstruct: the counters live in a kernel map, survive
// a daemon restart (until the map is closed), and are read here once per
// poll. The program only touches packet data (the Ethernet header), so it
// needs no BTF on the target kernel.
//
// The loader is Linux-only (the only place TC hooks exist); other
// platforms get an Attach that always fails, so the rest of the tree
// builds unchanged on every release target.
package ebpfacct

// Counters is one device's cumulative byte count since the program was
// attached, device-centric: Rx is the client's download (bytes the map
// saw TO its MAC), Tx its upload (bytes FROM its MAC). Monotonic;
// consumers diff across polls.
type Counters struct {
	Rx uint64
	Tx uint64
}

// DestCounters is one destination prefix's cumulative byte count for one
// device: Up = client → remote, Down = remote → client. Monotonic;
// consumers diff across polls.
type DestCounters struct {
	Up   uint64
	Down uint64
}

// DestKey identifies one device-destination pair: the client's MAC in
// colon-separated form and the destination's /24 (IPv4) or /48 (IPv6)
// prefix as text, e.g. "34.54.147.0/24". Only internet destinations
// appear — LAN-, router- and multicast-bound traffic is filtered in the
// kernel program.
type DestKey struct {
	Mac    string
	Prefix string
	Fam    int // 4 or 6
}

// Collector owns the loaded eBPF objects and their TC attachments.
// The implementation is platform-specific (see attach_linux.go).
type Collector struct {
	read      func() (map[string]Counters, error)
	readDests func() (map[DestKey]DestCounters, error)
	close     func()
}

// Read returns every device's cumulative byte counters keyed by MAC
// (lower-case colon-separated). The kernel map is authoritative.
func (c *Collector) Read() (map[string]Counters, error) {
	if c == nil || c.read == nil {
		return nil, ErrNotAttached
	}
	return c.read()
}

// ReadDests returns every device-destination pair's cumulative byte
// counters. The kernel map is authoritative; on non-Linux or before a
// successful attach it reports ErrNotAttached.
func (c *Collector) ReadDests() (map[DestKey]DestCounters, error) {
	if c == nil || c.readDests == nil {
		return nil, ErrNotAttached
	}
	return c.readDests()
}

// Close detaches the TC hooks and unloads the program and map.
func (c *Collector) Close() {
	if c != nil && c.close != nil {
		c.close()
	}
}

// ErrNotAttached is returned when reading a collector on a platform
// without eBPF support or before a successful Attach.
var ErrNotAttached = errNotAttached{}

type errNotAttached struct{}

func (errNotAttached) Error() string {
	return "ebpfacct: collector not attached (unsupported platform or load failure)"
}
