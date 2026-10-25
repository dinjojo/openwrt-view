package server

import (
	"context"
	"os/exec"
	"time"

	"github.com/rs/zerolog/log"
)

// nlbwmon watchdog: nlbwmon's netlink feed can silently stall — observed
// live, every client counter froze at a byte-identical value for 5+ hours
// while the WAN carried gigabytes, and the process stayed "running" the
// whole time. The health check surfaces the stall; this watchdog goes one
// step further and heals it: when real WAN volume crossed the router while
// no client counter moved for two consecutive probes, restart nlbwmon.
// A restart re-dumps conntrack, so totals continue from live values — the
// only loss is the traffic during the stall itself.
func (s *Server) watchAccounting(ctx context.Context) {
	if s.vmc == nil {
		return
	}
	// Only meaningful on the OpenWrt box where nlbwmon is installed.
	if _, err := exec.LookPath("/etc/init.d/nlbwmon"); err != nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	strikes := 0
	var lastRestart time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wan, err := s.querySum(`sum(increase(node_network_receive_bytes_total{device="pppoe-wan"}[10m]))` +
				` + sum(increase(node_network_transmit_bytes_total{device="pppoe-wan"}[10m]))`)
			if err != nil {
				continue
			}
			cli, err := s.querySum(`sum(increase(client_bytes_total[10m]))`)
			if err != nil {
				continue
			}
			// 5 MB over 10 minutes is noise-level; 1 KB of client counter
			// movement means at least one device was counted.
			if wan < 5e6 || cli >= 1024 {
				strikes = 0
				continue
			}
			strikes++
			// Two strikes (~2 min of confirmation) and at most one restart
			// per hour, so a persistent failure cannot turn into a loop.
			if strikes < 2 || time.Since(lastRestart) < time.Hour {
				continue
			}
			strikes = 0
			lastRestart = time.Now()
			if err := exec.Command("/etc/init.d/nlbwmon", "restart").Run(); err != nil {
				log.Logger.Warn().Err(err).Msg("nlbwmon accounting stuck but restart failed")
				continue
			}
			log.Logger.Warn().Msg("nlbwmon accounting was stuck; restarted nlbwmon")
			// A restart re-dumps conntrack and steps every counter up by
			// the surviving entries' bytes; drop the rate baselines so
			// that bookkeeping step is not read as traffic.
			s.clientStore.Reanchor()
			s.events.Add("monitor", "warn",
				"Per-device accounting (nlbwmon) was stuck — restarted it automatically; per-device counting resumed")
		}
	}
}

// querySum evaluates one instant query and sums the returned vector.
func (s *Server) querySum(query string) (float64, error) {
	qctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pts, err := s.vmc.Query(qctx, query)
	if err != nil {
		return 0, err
	}
	var sum float64
	for _, p := range pts {
		sum += p.Val
	}
	return sum, nil
}
