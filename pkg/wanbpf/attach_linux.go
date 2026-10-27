//go:build linux

// Linux implementation: loads the embedded bytecode and attaches it to
// the WAN device (XDP + tc ingress), the IFB mirror (tc ingress) and the
// LAN bridge (tc ingress + egress). See wanbpf.go for the portable
// surface.
package wanbpf

import (
	"bytes"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed wan.bpf.o
var bpfFS embed.FS

// wanPerCPU mirrors struct wan_stats in wan.c (field order matters).
type wanPerCPU struct {
	Pkts, Bytes, SynPass, ScanDrop, SpoofSeen uint64
}

// qDelayPerCPU mirrors struct q_delay in wan.c.
type qDelayPerCPU struct {
	Hist  [32]uint64
	Count uint64
	SumNs uint64
	MaxNs uint64
}

// portBytes mirrors struct port_bytes in wan.c.
type portBytes struct {
	Rx, Tx uint64
}

type linuxCollector struct {
	mu       sync.Mutex
	coll     *ebpf.Collection
	links    []link.Link
	prevQ    qDelayPerCPU         // last cumulative queue-delay read
	prevP    map[uint16]portBytes // last cumulative service read
	prevSrtt map[uint64]qDelayPerCPU
}

// Attach loads the compiled program and pins it to the given hooks. wan
// is the WAN device (XDP + tc ingress), ifb the CAKE ingress mirror
// (tc ingress), lan the LAN bridge (tc ingress + egress). The XDP gate
// is attached in generic (skb) mode: the NanoPi R6C's stmmac driver has
// no native XDP, and generic mode still keeps the work out of the
// per-packet network stack path. A failed XDP attach is downgraded to a
// warning so the tc collectors keep working.
func Attach(wan, ifb, lan string) (*Collector, error) {
	if wan == "" || ifb == "" || lan == "" {
		return nil, errors.New("wanbpf: attach needs wan, ifb and lan interfaces")
	}
	obj, err := bpfFS.ReadFile("wan.bpf.o")
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
	lc := &linuxCollector{coll: coll, prevP: map[uint16]portBytes{}, prevSrtt: map[uint64]qDelayPerCPU{}}
	hooks := []string{}
	attachErr := func(where string, err error) (*Collector, error) {
		lc.close()
		return nil, fmt.Errorf("wanbpf: attach %s: %w", where, err)
	}

	// XDP gate on the WAN device (generic mode; degrades to a warning).
	if idx, err := ifaceIndex(wan); err == nil {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   coll.Programs["xdp_wan_gate"],
			Interface: idx,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			fmt.Printf("[wanbpf] XDP on %s unavailable (%v); tc collectors only\n", wan, err)
		} else {
			lc.links = append(lc.links, l)
			hooks = append(hooks, "xdp:"+wan)
		}
	} else {
		return attachErr("find "+wan, err)
	}

	// tc ingress on the WAN (arrival stamps + RTT echo collection —
	// TCX_NEXT keeps the classic clsact redirect running after us) and
	// service accounting on the LAN bridge. collect_dl rides the LAN
	// bridge's egress: the post-CAKE departure point every download
	// passes through (the redirected skbs skip tc on the IFB itself).
	if idx, err := ifaceIndex(wan); err == nil {
		for _, prog := range []string{"stamp_dl", "collect_rtt"} {
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: idx, Program: coll.Programs[prog], Attach: ebpf.AttachTCXIngress,
			})
			if err != nil {
				return attachErr(prog+" on "+wan, err)
			}
			lc.links = append(lc.links, l)
		}
		hooks = append(hooks, "tc:"+wan)
	} else {
		return attachErr("find "+wan, err)
	}
	if idx, err := ifaceIndex(lan); err == nil {
		for _, a := range []struct {
			prog string
			att  ebpf.AttachType
		}{
			{"collect_dl", ebpf.AttachTCXEgress},
			{"stamp_ts", ebpf.AttachTCXIngress},
			{"local_from_lan", ebpf.AttachTCXIngress},
			{"local_to_lan", ebpf.AttachTCXEgress},
		} {
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: idx, Program: coll.Programs[a.prog], Attach: a.att,
			})
			if err != nil {
				return attachErr(a.prog+" on "+lan, err)
			}
			lc.links = append(lc.links, l)
		}
		hooks = append(hooks, "tc:"+lan)
	} else {
		return attachErr("find "+lan, err)
	}

	// Tell the service-accounting program which addresses are "the
	// router" on the LAN side.
	if err := fillLocalAddrs(coll, lan); err != nil {
		return attachErr("local addresses of "+lan, err)
	}

	c := &Collector{}
	c.read = func() (*Snapshot, error) { return lc.read(hooks) }
	c.close = lc.close
	return c, nil
}

func ifaceIndex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

// fillLocalAddrs copies the LAN interface's addresses into the maps the
// service programs consult, so only traffic addressed to the router
// itself is counted.
func fillLocalAddrs(coll *ebpf.Collection, lan string) error {
	ifi, err := net.InterfaceByName(lan)
	if err != nil {
		return err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return err
	}
	m4 := coll.Maps["local_addrs4"]
	m6 := coll.Maps["local_addrs6"]
	if m4 == nil || m6 == nil {
		return errors.New("wanbpf: local_addrs maps missing from object file")
	}
	for _, a := range addrs {
		var ipNet *net.IPNet
		switch v := a.(type) {
		case *net.IPNet:
			ipNet = v
		case *net.IPAddr:
			ipNet = &net.IPNet{IP: v.IP}
		}
		if ipNet == nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil {
			var k [4]byte
			copy(k[:], ip4)
			if err := m4.Put(k, uint8(1)); err != nil {
				return err
			}
			continue
		}
		ip16 := ipNet.IP.To16()
		if ip16 != nil {
			var k [16]byte
			copy(k[:], ip16)
			if err := m6.Put(k, uint8(1)); err != nil {
				return err
			}
		}
	}
	return nil
}

// read sums the per-CPU maps and diffs them into one Snapshot.
func (lc *linuxCollector) read(hooks []string) (*Snapshot, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	snap := &Snapshot{Hooks: hooks, Stamp: time.Now().Unix()}

	// WAN gate (per-CPU array, single record).
	var wans []wanPerCPU
	if m := lc.coll.Maps["xdp_stats"]; m != nil {
		if err := m.Lookup(uint32(0), &wans); err == nil {
			for _, w := range wans {
				snap.Wan.Pkts += w.Pkts
				snap.Wan.Bytes += w.Bytes
				snap.Wan.SynPass += w.SynPass
				snap.Wan.ScanDrop += w.ScanDrop
				snap.Wan.SpoofSeen += w.SpoofSeen
			}
		}
	}

	// Queue delay (per-CPU array, single record).
	var qs []qDelayPerCPU
	if m := lc.coll.Maps["q_delay"]; m != nil {
		if err := m.Lookup(uint32(0), &qs); err == nil {
			var cur qDelayPerCPU
			for _, q := range qs {
				cur.Count += q.Count
				cur.SumNs += q.SumNs
				if q.MaxNs > cur.MaxNs {
					cur.MaxNs = q.MaxNs
				}
				for i := range cur.Hist {
					cur.Hist[i] += q.Hist[i]
				}
			}
			dc := cur.Count - lc.prevQ.Count
			if dc > 0 {
				dSum := cur.SumNs - lc.prevQ.SumNs
				snap.QCount = dc
				snap.QAvgNs = dSum / dc
				snap.Hist = make([]uint64, 32)
				for i := range snap.Hist {
					if cur.Hist[i] > lc.prevQ.Hist[i] {
						snap.Hist[i] = cur.Hist[i] - lc.prevQ.Hist[i]
					}
				}
			}
			snap.QMaxNs = cur.MaxNs // map field is reset below per window
			lc.prevQ = cur
			// Reset the kernel's max so the next window reports its own
			// worst delay. A tiny race with in-flight updates is
			// acceptable at a 5 s poll.
			var reset []qDelayPerCPU
			if err := m.Lookup(uint32(0), &reset); err == nil && len(reset) > 0 {
				for i := range reset {
					reset[i].MaxNs = 0
				}
				m.Put(uint32(0), reset)
			}
		}
	}

	// Per-client passive RTT (per-CPU hash keyed by MAC). Same
	// windowed diff as the queue delay; the kernel's per-client max is
	// reset after each read so each window reports its own worst RTT.
	if m := lc.coll.Maps["srtt_hist"]; m != nil {
		var (
			mk   uint64
			vals []qDelayPerCPU
			iter = m.Iterate()
		)
		for iter.Next(&mk, &vals) {
			var cur qDelayPerCPU
			for _, v := range vals {
				cur.Count += v.Count
				cur.SumNs += v.SumNs
				if v.MaxNs > cur.MaxNs {
					cur.MaxNs = v.MaxNs
				}
				for i := range cur.Hist {
					cur.Hist[i] += v.Hist[i]
				}
			}
			prev := lc.prevSrtt[mk]
			dc := cur.Count - min64(prev.Count, cur.Count)
			if cur.Count < prev.Count { // counters reset (attach race): resync
				dc = 0
			}
			r := DeviceRTT{Mac: macString(mk), Count: cur.Count}
			if cur.Count > 0 {
				r.AvgNs = cur.SumNs / cur.Count
			}
			r.MaxNs = cur.MaxNs
			if dc > 0 {
				r.WinCount = dc
				r.WinAvgNs = (cur.SumNs - prev.SumNs) / dc
			}
			if r.WinCount > 0 || r.Count > 0 {
				snap.Srtt = append(snap.Srtt, r)
			}
			lc.prevSrtt[mk] = cur
			// Reset this client's max so the next window reports its
			// own worst sample (same tiny race as the queue delay).
			reset := vals
			for i := range reset {
				reset[i].MaxNs = 0
			}
			if err := m.Put(mk, reset); err != nil {
				break
			}
		}
		sortSrtt(snap.Srtt)
	}

	// Service bytes (LRU keyed by port; the BPF side stores the port's
	// big-endian bytes, so decode explicitly).
	snap.Services = []Service{}
	if m := lc.coll.Maps["local_bytes"]; m != nil {
		var (
			raw  [2]byte
			pb   portBytes
			iter = m.Iterate()
		)
		for iter.Next(&raw, &pb) {
			port := binary.BigEndian.Uint16(raw[:])
			cur := pb
			prev := lc.prevP[port]
			s := Service{
				Port:    port,
				Label:   ServiceLabels[port],
				RxTotal: cur.Rx,
				TxTotal: cur.Tx,
				RxWin:   cur.Rx - min64(prev.Rx, cur.Rx),
				TxWin:   cur.Tx - min64(prev.Tx, cur.Tx),
			}
			if s.Label == "" {
				s.Label = fmt.Sprintf("port %d", port)
			}
			snap.Services = append(snap.Services, s)
			lc.prevP[port] = cur
		}
		sortServices(snap.Services)
	}
	return snap, nil
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// macString renders the map key (MAC packed big-endian in the low 48
// bits) back to its colon-separated form.
func macString(k uint64) string {
	b := []byte{byte(k >> 40), byte(k >> 32), byte(k >> 24), byte(k >> 16), byte(k >> 8), byte(k)}
	return net.HardwareAddr(b).String()
}

// sortSrtt orders clients by windowed sample count, so the talkative
// ones — the ones whose latency the household is actually feeling —
// sit at the top.
func sortSrtt(s []DeviceRTT) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].WinCount > s[j-1].WinCount; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// sortServices keeps the built-in ports in port order ahead of the rest.
func sortServices(s []Service) {
	// Tiny n; insertion sort, stable enough for a status table.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && lessService(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func lessService(a, b Service) bool {
	// Known services first (labelled), then by port.
	if (a.Port != 0 && ServiceLabels[a.Port] != "") != (b.Port != 0 && ServiceLabels[b.Port] != "") {
		return ServiceLabels[a.Port] != ""
	}
	return a.Port < b.Port
}

// close detaches every hook and unloads the objects.
func (lc *linuxCollector) close() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, l := range lc.links {
		l.Close()
	}
	lc.links = nil
	if lc.coll != nil {
		lc.coll.Close()
	}
}
