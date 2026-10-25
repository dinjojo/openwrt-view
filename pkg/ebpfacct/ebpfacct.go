// Package ebpfacct provides per-device traffic accounting with an eBPF
// program attached to a LAN interface's TC hooks. The kernel counts bytes
// per client MAC inline on the packet path, so there is no feed to stall
// and no state to reconstruct: the counters live in a kernel map, survive
// a daemon restart (until the map is closed), and are read here once per
// poll. The program only touches packet data (the Ethernet header), so it
// needs no BTF on the target kernel.
package ebpfacct

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed counters.bpf.o
var bpfFS embed.FS

// Counters is the raw byte count for one device since the program was
// attached. Monotonic; consumers diff across polls.
type Counters struct {
	Rx uint64
	Tx uint64
}

// Collector owns the loaded eBPF objects and their TC attachments.
type Collector struct {
	mu    sync.Mutex
	coll  *ebpf.Collection
	links []link.Link
	iface string
}

// Attach loads the compiled program and pins it to iface's TC hooks.
// The returned Collector must be Closed on shutdown, or the filters stay
// attached until the interface goes away.
func Attach(iface string) (*Collector, error) {
	obj, err := bpfFS.ReadFile("counters.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("embedded eBPF object: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("parse eBPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load eBPF into kernel: %w", err)
	}
	c := &Collector{coll: coll, iface: iface}

	ifIndex, err := net.InterfaceByName(iface)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ebpfacct: find %s: %w", iface, err)
	}
	for _, a := range []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{coll.Programs["count_from_client"], ebpf.AttachTCXIngress},
		{coll.Programs["count_to_client"], ebpf.AttachTCXEgress},
	} {
		if a.prog == nil {
			c.Close()
			return nil, errors.New("ebpfacct: program missing from object file")
		}
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ifIndex.Index,
			Program:   a.prog,
			Attach:    a.attach,
		})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s to %s: %w", a.attach, iface, err)
		}
		c.links = append(c.links, l)
	}
	log.Printf("[ebpfacct] attached per-device counters to %s (tcx ingress+egress)", iface)
	return c, nil
}

// Read returns every device's cumulative byte counters keyed by MAC
// (lower-case colon-separated). The kernel map is authoritative.
func (c *Collector) Read() (map[string]Counters, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.coll.Maps["device_bytes"]
	if m == nil {
		return nil, errors.New("ebpfacct: device_bytes map missing")
	}
	var (
		key  uint64
		val  struct{ Rx, Tx uint64 }
		out  = map[string]Counters{}
		iter = m.Iterate()
	)
	for iter.Next(&key, &val) {
		mac := net.HardwareAddr{
			byte(key >> 40), byte(key >> 32), byte(key >> 24),
			byte(key >> 16), byte(key >> 8), byte(key),
		}.String()
		out[mac] = Counters{Rx: val.Rx, Tx: val.Tx}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Close detaches the TC hooks and unloads the program and map.
func (c *Collector) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.links {
		if err := l.Close(); err != nil {
			log.Printf("[ebpfacct] detach %s: %v", c.iface, err)
		}
	}
	c.links = nil
	c.coll.Close()
}
