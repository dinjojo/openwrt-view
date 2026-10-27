//go:build linux

// Linux implementation: loads the embedded bytecode and attaches it to
// the interface's TC (TCX) hooks. See shared.go for the portable surface.
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

// linuxCollector holds the live kernel objects behind the portable
// Collector surface.
type linuxCollector struct {
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
	lc := &linuxCollector{coll: coll, iface: iface}

	ifIndex, err := net.InterfaceByName(iface)
	if err != nil {
		lc.close()
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
			lc.close()
			return nil, errors.New("ebpfacct: program missing from object file")
		}
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ifIndex.Index,
			Program:   a.prog,
			Attach:    a.attach,
		})
		if err != nil {
			lc.close()
			return nil, fmt.Errorf("attach %s to %s: %w", a.attach, iface, err)
		}
		lc.links = append(lc.links, l)
	}
	log.Printf("[ebpfacct] attached per-device counters to %s (tcx ingress+egress)", iface)

	c := &Collector{}
	c.read = func() (map[string]Counters, error) { return lc.read() }
	c.readDests = func() (map[DestKey]DestCounters, error) { return lc.readDests() }
	c.close = lc.close
	return c, nil
}

// Read returns every device's cumulative byte counters keyed by MAC
// (lower-case colon-separated). The kernel map is authoritative.
func (lc *linuxCollector) read() (map[string]Counters, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	m := lc.coll.Maps["device_bytes"]
	if m == nil {
		return nil, errors.New("ebpfacct: device_bytes map missing")
	}
	var (
		key uint64
		// Field order mirrors struct dev_counters in counters.c:
		// up = bytes FROM the client (its upload), down = bytes TO the
		// client (its download). Counters is device-centric: Rx is the
		// client's download, Tx its upload.
		val  struct{ Up, Down uint64 }
		out  = map[string]Counters{}
		iter = m.Iterate()
	)
	for iter.Next(&key, &val) {
		mac := net.HardwareAddr{
			byte(key >> 40), byte(key >> 32), byte(key >> 24),
			byte(key >> 16), byte(key >> 8), byte(key),
		}.String()
		out[mac] = Counters{Rx: val.Down, Tx: val.Up}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// readDests walks the per-destination map, rendering keys as text.
func (lc *linuxCollector) readDests() (map[DestKey]DestCounters, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	m := lc.coll.Maps["dest_bytes"]
	if m == nil {
		return nil, errors.New("ebpfacct: dest_bytes map missing")
	}
	var (
		key struct {
			Mac    uint64
			Prefix uint64
			Fam    uint32
			Pad    uint32
		}
		val struct{ Up, Down uint64 }
		out = map[DestKey]DestCounters{}
		it  = m.Iterate()
	)
	for it.Next(&key, &val) {
		// The MAC is big-endian in the low 48 bits; the v4 prefix is
		// the address's first three octets in the low three bytes
		// (the u32 is read little-endian); the v6 prefix is the
		// address's first six bytes, copied in wire order.
		mac := net.HardwareAddr{
			byte(key.Mac >> 40), byte(key.Mac >> 32), byte(key.Mac >> 24),
			byte(key.Mac >> 16), byte(key.Mac >> 8), byte(key.Mac),
		}.String()
		fam := int(key.Fam)
		prefix := ""
		switch fam {
		case 4:
			prefix = fmt.Sprintf("%d.%d.%d.0/24", byte(key.Prefix), byte(key.Prefix>>8), byte(key.Prefix>>16))
		case 6:
			prefix = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x::/48",
				byte(key.Prefix), byte(key.Prefix>>8), byte(key.Prefix>>16),
				byte(key.Prefix>>24), byte(key.Prefix>>32), byte(key.Prefix>>40))
		default:
			continue
		}
		out[DestKey{Mac: mac, Prefix: prefix, Fam: fam}] = DestCounters{Up: val.Up, Down: val.Down}
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// close detaches the TC hooks and unloads the program and map.
func (lc *linuxCollector) close() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, l := range lc.links {
		if err := l.Close(); err != nil {
			log.Printf("[ebpfacct] detach %s: %v", lc.iface, err)
		}
	}
	lc.links = nil
	lc.coll.Close()
}
