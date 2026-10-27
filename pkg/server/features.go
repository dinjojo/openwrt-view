package server

import (
	"context"
	"strconv"
	"strings"
	"time"

	fiber "github.com/gofiber/fiber/v3"

	"github.com/dinjojo/openwrt-view/pkg/alerts"
	"github.com/dinjojo/openwrt-view/pkg/health"
	"github.com/dinjojo/openwrt-view/pkg/log"
	"github.com/dinjojo/openwrt-view/pkg/radio"
	"github.com/dinjojo/openwrt-view/pkg/usage"
)

// usageEvery is how often per-client counters are appended to disk.
const usageEvery = 15 * time.Minute

// SetRadioCollector registers the local Wi-Fi dongle collector. Call
// before Run; Run starts it when an interface is configured.
func (s *Server) SetRadioCollector(c *radio.Collector) { s.radio = c }

// SetAlerts registers the push notifier (nil disables alerts). Call
// before Run; every warn/crit event is offered to it.
func (s *Server) SetAlerts(n *alerts.Notifier) { s.alerts = n }

// SetLocation sets the zone whose calendar days bound /api/report rows and
// in which the health check reads the probe cron schedule (the -tz flag;
// it must match the zone cron runs in). Call before Run. Default:
// time.Local.
func (s *Server) SetLocation(loc *time.Location) {
	if loc == nil {
		return
	}
	s.loc = loc
	health.SetLocation(loc)
}

// SetUsageStore registers where per-client daily usage is persisted (nil
// disables). Call before Run.
func (s *Server) SetUsageStore(u *usage.Store) { s.usage = u }

// handleAPIRadio serves the local dongle's survey/scan snapshot;
// ok:false (with err) when unconfigured or failing.
func (s *Server) handleAPIRadio(c fiber.Ctx) error {
	return c.JSON(s.radio.Snapshot())
}

// configPayload is the /api/config body: UI-relevant, secret-free settings.
type configPayload struct {
	Alerts alerts.Config `json:"alerts"`
}

func (s *Server) handleAPIConfig(c fiber.Ctx) error {
	return c.JSON(configPayload{Alerts: s.alerts.Config()})
}

// usagePayload is the /api/usage body.
type usagePayload struct {
	Days      []usage.Day `json:"days"`       // oldest first; days without data are absent
	DaysTotal int         `json:"days_total"` // the window asked for
}

func (s *Server) handleAPIUsage(c fiber.Ctx) error {
	n := 7
	if v := c.Query("days"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 {
			return c.Status(400).SendString(`{"error":"days must be a positive integer"}`)
		}
		n = min(p, 400)
	}
	out := usagePayload{Days: []usage.Day{}, DaysTotal: n}
	if s.usage != nil {
		out.Days = s.usage.Daily(n, time.Now())
	}
	return c.JSON(out)
}

// recordUsage appends the client store's cumulative counters to the
// usage files every 15 minutes (first write once the client poller has
// produced data).
func (s *Server) recordUsage(ctx context.Context) {
	if s.usage == nil {
		return
	}
	write := func() bool {
		snap := s.clientStore.Snapshot()
		if len(snap) == 0 {
			return false
		}
		samples := make([]usage.Sample, 0, len(snap))
		for _, cl := range snap {
			samples = append(samples, usage.Sample{MAC: strings.ToUpper(cl.MAC), Rx: cl.RxTotal, Tx: cl.TxTotal})
		}
		if err := s.usage.Append(time.Now(), samples); err != nil {
			log.Logger.Warn().Err(err).Str("dir", s.usage.Dir()).Msg("usage snapshot failed")
		}
		return true
	}
	// Seed shortly after start so a restart does not lose a quarter hour.
	seed := time.NewTimer(time.Minute)
	defer seed.Stop()
	t := time.NewTicker(usageEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-seed.C:
			if !write() {
				seed.Reset(time.Minute)
			}
		case <-t.C:
			write()
		}
	}
}
