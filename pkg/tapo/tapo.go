// Package tapo polls a TP-Link Tapo smart plug over its local KAS/KLAP API.
// The plug authenticates with the Tapo account credentials, hashed locally;
// nothing leaves the LAN. Credentials come from a root-only conf file that is
// passed via -tapo-conf, so they never appear on a command line.
package tapo

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tess1o/tapo-go"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// Config is one plug's connection settings.
type Config struct {
	Host string // plug IP, e.g. 192.168.1.242
	User string // Tapo account email
	Pass string // Tapo account password
}

// State is the latest plug snapshot.
type State struct {
	Available bool      `json:"available"` // last poll reached the plug
	On        bool      `json:"on"`        // relay state at the last good poll
	Model     string    `json:"model,omitempty"`
	Name      string    `json:"name,omitempty"` // decoded plug nickname
	Rssi      int       `json:"rssi"`           // Wi-Fi RSSI in dBm (negative)
	OnForS    int       `json:"on_for_s"`       // seconds the relay has been on
	PowerW    float64   `json:"power_w"`        // live power, only when HasPower
	HasPower  bool      `json:"has_power"`      // model reports energy usage
	At        time.Time `json:"at"`             // last good poll
}

// plugClient is the slice of the upstream device the poller needs.
type plugClient interface {
	DeviceInfo(ctx context.Context) (*tapo.DeviceInfoResponse, error)
	GetEnergyUsage(ctx context.Context) (*tapo.EnergyUsageResponse, error)
}

// clientFactory opens an authenticated session with the plug. The upstream
// library performs the handshake inside its constructor.
type clientFactory func(ctx context.Context) (plugClient, error)

// Poller refreshes the plug snapshot every interval and pushes gauges to
// VictoriaMetrics. It keeps one authenticated session and re-dials only when
// the plug rejects it — the plug rate-limits fresh handshakes (HTTP 403), so
// logging in from scratch every poll eventually locks itself out.
type Poller struct {
	mu      sync.RWMutex
	conf    Config
	st      State
	everOK  bool          // at least one good poll since start
	epm     int           // energy usage support: 0 unknown, 1 yes, -1 no
	epmNext time.Time     // when to retry EPM after a failure
	client  plugClient    // live session, nil until first dial
	factory clientFactory // pluggable for tests
	vmc     *vm.Client
}

// New creates the poller and takes its first snapshot in the background so
// server startup never blocks on an unreachable plug.
func New(conf Config, vmc *vm.Client) *Poller {
	p := &Poller{
		conf: conf,
		vmc:  vmc,
		factory: func(ctx context.Context) (plugClient, error) {
			return tapo.NewSmartPlug(ctx, conf.Host, conf.User, conf.Pass, tapo.Options{})
		},
	}
	go p.refresh()
	return p
}

// SetVMClient wires VictoriaMetrics (called from the server once it is up).
func (p *Poller) SetVMClient(c *vm.Client) { p.vmc = c }

// Snapshot returns the latest state.
func (p *Poller) Snapshot() State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.st
}

// Run polls until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh()
		}
	}
}

// refresh takes one poll. A failed poll marks the plug unavailable but keeps
// the last known values, mirroring how the other pollers degrade. The session
// is reused across polls; on a rejected or expired session it is re-dialed
// once before the poll counts as failed.
func (p *Poller) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	p.mu.RLock()
	c := p.client
	p.mu.RUnlock()
	var err error
	if c == nil {
		c, err = p.dial(ctx)
		if err != nil {
			p.fail(err)
			return
		}
		p.setClient(c)
	}

	info, err := c.DeviceInfo(ctx)
	if err != nil {
		// Session expired or rejected (the plug answers 403): one fresh
		// handshake before giving up on this poll.
		p.setClient(nil)
		c, derr := p.dial(ctx)
		if derr != nil {
			p.fail(derr)
			return
		}
		p.setClient(c)
		info, err = c.DeviceInfo(ctx)
		if err != nil {
			p.fail(err)
			return
		}
	}

	st := State{
		Available: true,
		On:        info.Result.DeviceOn,
		Model:     strings.TrimSpace(info.Result.Model),
		Name:      decodeNickname(info.Result.Nickname),
		Rssi:      info.Result.Rssi,
		OnForS:    info.Result.OnTime,
		At:        time.Now(),
	}

	// Energy usage is a P110/P115-class feature; the P116M answers with an
	// error code instead. Try until it fails, then back off to hourly retries.
	if p.epmSupported() {
		eu, err := c.GetEnergyUsage(ctx)
		if err == nil && eu != nil && eu.ErrorCode == 0 {
			p.setEPM(true)
			st.HasPower = true
			st.PowerW = float64(eu.Result.CurrentPower) / 1000.0
		} else {
			changed := p.setEPM(false)
			if changed {
				p.logEPM(err)
			}
		}
	}

	p.mu.Lock()
	p.st = st
	p.everOK = true
	p.mu.Unlock()
	p.pushVM(st)
}

func (p *Poller) dial(ctx context.Context) (plugClient, error) {
	return p.factory(ctx)
}

func (p *Poller) setClient(c plugClient) {
	p.mu.Lock()
	p.client = c
	p.mu.Unlock()
}

func (p *Poller) fail(err error) {
	p.mu.Lock()
	p.st.Available = false
	p.st.At = time.Now()
	ever := p.everOK
	p.mu.Unlock()
	if ever {
		log.Printf("[tapo] poll failed, keeping last state: %v", err)
	} else {
		log.Printf("[tapo] first poll failed: %v", err)
	}
}

func (p *Poller) epmSupported() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	switch p.epm {
	case 0, 1: // unknown (probe it) or known-supported
		return true
	default: // known-unsupported: retry after the hourly backoff
		return time.Now().After(p.epmNext)
	}
}

// setEPM records an EPM success/failure and reports whether the support
// state changed (used to log transitions once instead of every poll).
func (p *Poller) setEPM(ok bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		was := p.epm
		p.epm = 1
		return was != 1
	}
	if p.epm == 1 {
		// worked before; treat this poll as transient, retry on the next one
		return false
	}
	was := p.epm
	p.epm = -1
	p.epmNext = time.Now().Add(time.Hour)
	return was != -1
}

func (p *Poller) logEPM(err error) {
	why := "model may not support it"
	if err != nil {
		why = err.Error()
	}
	log.Printf("[tapo] energy usage unavailable on %s; retrying hourly (%s)", p.conf.Host, why)
}

// decodeNickname decodes the base64 UTF-8 nickname Tapo reports.
func decodeNickname(nick string) string {
	if nick == "" {
		return ""
	}
	if raw, err := base64.StdEncoding.DecodeString(nick); err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s
		}
	}
	return strings.TrimSpace(nick)
}

// pushVM imports the plug gauges: relay state, live power when the model
// supports it, and Wi-Fi RSSI. Called from the poll goroutine only.
func (p *Poller) pushVM(st State) {
	if p.vmc == nil {
		return
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	model := st.Model
	if model == "" {
		model = "unknown"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("tapo_plug_on{host=%q,model=%q,name=%q} %d %s\n",
		escapeLabel(p.conf.Host), escapeLabel(model), escapeLabel(st.Name), bool01(st.On), ts))
	if st.HasPower {
		b.WriteString(fmt.Sprintf("tapo_plug_power_watts{host=%q,model=%q,name=%q} %s %s\n",
			escapeLabel(p.conf.Host), escapeLabel(model), escapeLabel(st.Name),
			strconv.FormatFloat(st.PowerW, 'f', -1, 64), ts))
	}
	b.WriteString(fmt.Sprintf("tapo_plug_rssi{host=%q,model=%q} %d %s\n",
		escapeLabel(p.conf.Host), escapeLabel(model), st.Rssi, ts))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.vmc.Import(ctx, b.String()); err != nil {
		log.Printf("[tapo] VM import failed: %v", err)
	}
}

func bool01(v bool) int {
	if v {
		return 1
	}
	return 0
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}
