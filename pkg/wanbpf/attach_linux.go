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
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/dinjojo/openwrt-view/pkg/log"
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
	prevD    map[destKey]destRTT  // last cumulative per-dest RTT read
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
	lc := &linuxCollector{coll: coll, prevP: map[uint16]portBytes{}, prevD: map[destKey]destRTT{}, prevSrtt: map[uint64]qDelayPerCPU{}}
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

	// Per-client passive RTT (hash keyed by MAC). Same windowed diff
	// as the queue delay; the kernel's per-client max is reset after
	// each read so each window reports its own worst RTT.
	if m := lc.coll.Maps["srtt_hist"]; m != nil {
		var (
			mk   uint64
			vals qDelayPerCPU
			iter = m.Iterate()
		)
		for iter.Next(&mk, &vals) {
			cur := vals
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
			// Re-read first: vals is the snapshot Iterate took, and
			// Put would clobber counters the kernel advanced since.
			var reset qDelayPerCPU
			if err := m.Lookup(mk, &reset); err != nil {
				continue
			}
			reset.MaxNs = 0
			if err := m.Put(mk, reset); err != nil {
				break
			}
		}
		if err := iter.Err(); err != nil {
			log.Logger.Warn().Err(err).Msg("srtt walk failed; partial window")
		}
		sortSrtt(snap.Srtt)
	}

	// Per-device × per-destination RTT. Walk is bounded by the map's
	// 2048-entry LRU cap (~100 KB kernel memory, ~2k map ops per 5 s
	// tick — negligible next to the existing walks). Maxima reset per
	// window so each window reports its own worst, same as above.
	if m := lc.coll.Maps["srtt_dest"]; m != nil {
		var (
			k    destKey
			v    destRTT
			iter = m.Iterate()
		)
		var walked []destEntry
		for iter.Next(&k, &v) {
			walked = append(walked, destEntry{k: k, v: v})
		}
		if err := iter.Err(); err != nil {
			log.Logger.Warn().Err(err).Msg("srtt_dest walk failed; partial window")
		}
		byMac := foldDestRTTs(walked, 3, lc.prevD)
		for i := range snap.Srtt {
			snap.Srtt[i].Dests = byMac[snap.Srtt[i].Mac]
		}
		// Reset per-prefix maxima for the next window; fresh lookup
		// before Put so counters advanced meanwhile are not clobbered.
		for _, e := range walked {
			var fresh destRTT
			if m.Lookup(e.k, &fresh) != nil {
				continue // evicted between walk and reset
			}
			fresh.MaxNs = 0
			if err := m.Put(e.k, fresh); err != nil {
				break
			}
		}
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
		if err := iter.Err(); err != nil {
			log.Logger.Warn().Err(err).Msg("local_bytes walk failed; partial window")
		}
		sortServices(snap.Services)
	}
	return snap, nil
}

// Per-destination RTT (LRU keyed by client MAC + destination /24 or
// /48). Same windowed diff discipline as the device table: walked once
// per tick, folded into each device's row, maxima reset for the next
// window.

// destKey mirrors the C struct dest_key.
type destKey struct {
	Mac    uint64
	Prefix uint64
	Fam    uint32
	Pad    uint32
}

// destRTT mirrors the C struct dest_rtt.
type destRTT struct {
	Count uint64
	SumNs uint64
	MaxNs uint64
}

// destEntry is one walked map entry.
type destEntry struct {
	k destKey
	v destRTT
}

// destPrefixString renders the key's prefix: "3.175.86.0/24" for IPv4,
// "2406:da12:0001::/48" for IPv6.
func destPrefixString(k destKey) string {
	if k.Fam == 6 {
		// The C side memcpy'd the address's first 6 bytes into the
		// little-endian u64: byte i of the address is byte i of it.
		return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x::/48",
			byte(k.Prefix), byte(k.Prefix>>8), byte(k.Prefix>>16),
			byte(k.Prefix>>24), byte(k.Prefix>>32), byte(k.Prefix>>40))
	}
	return fmt.Sprintf("%d.%d.%d.0/24", byte(k.Prefix), byte(k.Prefix>>8), byte(k.Prefix>>16))
}

// foldDestRTTs groups walked per-prefix counters by device and keeps
// the `keep` busiest prefixes per device (by windowed sample count).
// Counters in the map are cumulative since the entry was created, so
// each device's previous read (prev) is differenced out — a dest with
// no new samples this window is skipped. prev is advanced in place.
func foldDestRTTs(entries []destEntry, keep int, prev map[destKey]destRTT) map[string][]DestRTT {
	byMac := map[string][]DestRTT{}
	for _, e := range entries {
		if e.v.Count == 0 {
			continue
		}
		p := prev[e.k]
		winC := e.v.Count - min64(p.Count, e.v.Count)
		winS := e.v.SumNs - min64(p.SumNs, e.v.SumNs)
		prev[e.k] = e.v
		if winC == 0 {
			continue // talked in an earlier window only
		}
		byMac[macString(e.k.Mac)] = append(byMac[macString(e.k.Mac)], DestRTT{
			Prefix: destPrefixString(e.k),
			Fam:    int(e.k.Fam),
			Count:  winC,
			AvgNs:  winS / winC,
			MaxNs:  e.v.MaxNs,
		})
	}
	for mac, ds := range byMac {
		sort.Slice(ds, func(i, j int) bool { return ds[i].Count > ds[j].Count })
		if len(ds) > keep {
			ds = ds[:keep]
		}
		byMac[mac] = ds
	}
	return byMac
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
