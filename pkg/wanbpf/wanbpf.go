// Package wanbpf collects WAN-edge and router-local telemetry with eBPF:
//
//   - an XDP gate on the WAN device: line-rate packet/byte totals,
//     spoofed-source observation and per-source SYN rate limiting
//     (port-scan dampening), all before the kernel builds an skb;
//   - per-packet download queue delay, measured as the time a packet
//     spends between arriving on the WAN ingress and being dequeued by
//     the CAKE ingress qdisc on the IFB mirror;
//   - passive per-device round-trip times, measured from the TCP
//     timestamps of each client's own connections (TSval on the LAN
//     leg, echoed TSecver on the WAN leg — no probes);
//   - router-local service accounting on the LAN bridge: bytes between
//     clients and the router's own services (DNS, SSH, LuCI, …) keyed
//     by service port.
//
// The kernel maps are authoritative; the loader is Linux-only and other
// platforms get an Attach that always fails so the tree builds
// unchanged on every release target.
package wanbpf

// WanStats is the XDP gate's cumulative counters since attach.
type WanStats struct {
	Pkts      uint64 `json:"pkts"`
	Bytes     uint64 `json:"bytes"`
	SynPass   uint64 `json:"syn_pass"`
	ScanDrop  uint64 `json:"scan_drop"`
	SpoofSeen uint64 `json:"spoof_seen"`
}

// Service is one router-local service's byte counts. Totals are
// cumulative since attach; the Win fields cover the window between the
// two most recent reads.
type Service struct {
	Port    uint16 `json:"port"`
	Label   string `json:"label"`
	RxTotal uint64 `json:"rx_total"` // from clients into the service
	TxTotal uint64 `json:"tx_total"` // from the service to clients
	RxWin   uint64 `json:"rx_win"`
	TxWin   uint64 `json:"tx_win"`
}

// Snapshot is one read of all collectors. Queue stats are windowed
// (between the two most recent reads); Wan stats are cumulative.
type Snapshot struct {
	Wan      WanStats    `json:"wan"`
	QCount   uint64      `json:"q_count"`  // packets measured in the window
	QAvgNs   uint64      `json:"q_avg_ns"` // windowed mean queue delay
	QMaxNs   uint64      `json:"q_max_ns"` // windowed worst queue delay
	Hist     []uint64    `json:"hist"`     // windowed log2-µs histogram
	Srtt     []DeviceRTT `json:"srtt"`     // per-client passive TCP RTT, windowed
	Services []Service   `json:"services"` // one per observed service port
	Hooks    []string    `json:"hooks"`    // attached hook names, for the UI
	Stamp    int64       `json:"stamp_unix"`
}

// DeviceRTT is one client's passive round-trip samples, measured from
// its own TCP connections' timestamps (no probes). Count and AvgNs are
// cumulative since attach; MaxNs and the Win fields cover the window
// between the two most recent reads.
type DeviceRTT struct {
	Mac      string `json:"mac"`        // client MAC, colon-separated
	Count    uint64 `json:"count"`      // samples since attach
	AvgNs    uint64 `json:"avg_ns"`     // cumulative mean
	MaxNs    uint64 `json:"max_ns"`     // worst sample in the window
	WinCount uint64 `json:"win_count"`  // samples in the window
	WinAvgNs uint64 `json:"win_avg_ns"` // windowed mean
	// Where this device's windowed RTT came from: the busiest
	// destination prefixes, busiest first. Lets the UI distinguish
	// "talks to a far CDN" from "the line is slow".
	Dests []DestRTT `json:"dests,omitempty"`
}

// DestRTT is one destination prefix's windowed RTT for one device.
type DestRTT struct {
	Prefix string `json:"prefix"` // "3.175.86.0/24" or "2406:da12:1::/48"-style v6
	Fam    int    `json:"fam"`    // 4 or 6
	Count  uint64 `json:"count"`  // samples in the window
	AvgNs  uint64 `json:"avg_ns"` // windowed mean for this prefix
	MaxNs  uint64 `json:"max_ns"` // worst sample in the window
}

// Collector owns the loaded eBPF objects and their attachments. The
// implementation is platform-specific (see attach_linux.go).
type Collector struct {
	read  func() (*Snapshot, error)
	close func()
}

// ErrNotAttached is returned when reading a collector on a platform
// without eBPF support or before a successful Attach.
var ErrNotAttached = errNotAttached{}

type errNotAttached struct{}

func (errNotAttached) Error() string {
	return "wanbpf: collector not attached (unsupported platform or load failure)"
}

// Read returns the latest snapshot, diffing the kernel's cumulative
// maps into windowed queue-delay and service stats. The first call
// after Attach reports zero windows (no interval to diff yet).
func (c *Collector) Read() (*Snapshot, error) {
	if c == nil || c.read == nil {
		return nil, ErrNotAttached
	}
	return c.read()
}

// Close detaches every hook and unloads the program and maps.
func (c *Collector) Close() {
	if c != nil && c.close != nil {
		c.close()
	}
}

// ServiceLabels names the router's own listening ports for the UI.
var ServiceLabels = map[uint16]string{
	53:    "DNS",
	853:   "DNS over TLS",
	8888:  "AdGuard Home",
	80:    "LuCI HTTP",
	443:   "HTTPS",
	22:    "SSH",
	11112: "openwrt-view",
	8428:  "VictoriaMetrics",
	51820: "WireGuard",
	1900:  "SSDP",
}
