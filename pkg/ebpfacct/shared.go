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

// Collector owns the loaded eBPF objects and their TC attachments.
// The implementation is platform-specific (see attach_linux.go).
type Collector struct {
	read  func() (map[string]Counters, error)
	close func()
}

// Read returns every device's cumulative byte counters keyed by MAC
// (lower-case colon-separated). The kernel map is authoritative.
func (c *Collector) Read() (map[string]Counters, error) {
	if c == nil || c.read == nil {
		return nil, ErrNotAttached
	}
	return c.read()
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
