// TCP-connect WAN RTT monitor. ICMP RTT (collectd ping) is unreliable on
// this network: under heavy load the ISP's interceptor answers echo
// requests before the shaper, so latency reads FASTER exactly when it is
// worst — masking the very bufferbloat the dashboard must warn about. A
// TCP handshake cannot be answered by an interceptor: the SYN-ACK has to
// come from the real host, past the shaper where queue delay lives.
package wan

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// rttTarget is the probe destination. An IP:port with a responsive TLS
// listener; no DNS in the measurement path. Never 1.1.1.1 on this network
// (the ISP intercepts it entirely — see bufferbloat_probe.sh).
const rttTarget = "8.8.8.8:443"

const rttMetric = `wan_connect_rtt_ms{target="8.8.8.8"}`

// RTTMonitor measures WAN round-trip time with TCP connects and pushes the
// reading to VictoriaMetrics so passive latency-under-load detection and
// the Line-health chart work on honest data.
type RTTMonitor struct {
	mu  sync.RWMutex
	ms  float64   // latest median connect RTT, ms (0 = no reading yet)
	at  time.Time // when that reading was taken
	vmc *vm.Client
}

// StartRTTMonitor measures immediately and then every interval until ctx
// is done. vmc may be nil to only measure (no pushes).
func StartRTTMonitor(ctx context.Context, vmc *vm.Client, interval time.Duration) *RTTMonitor {
	m := &RTTMonitor{vmc: vmc}
	m.tick()
	go m.loop(ctx, interval)
	return m
}

// Snapshot returns the latest median connect RTT in ms and when it was
// measured. ms is 0 before the first successful probe.
func (m *RTTMonitor) Snapshot() (float64, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ms, m.at
}

func (m *RTTMonitor) loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick()
		}
	}
}

func (m *RTTMonitor) tick() {
	ms := m.measure()
	if ms <= 0 {
		return
	}
	m.mu.Lock()
	m.ms, m.at = ms, time.Now()
	m.mu.Unlock()
	if m.vmc != nil {
		if err := m.vmc.Import(context.Background(), fmt.Sprintf("%s %g %d", rttMetric, ms, time.Now().Unix())); err != nil {
			log.Printf("[wanrtt] push failed: %v", err)
		}
	}
}

// measure dials rttTarget three times and returns the median connect RTT
// in milliseconds (0 when every dial failed — the line is down).
func (m *RTTMonitor) measure() float64 {
	samples := make([]float64, 0, 3)
	for i := 0; i < 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", rttTarget, 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		samples = append(samples, float64(time.Since(start).Microseconds())/1000)
	}
	if len(samples) == 0 {
		return 0
	}
	sort.Float64s(samples)
	return samples[len(samples)/2]
}
