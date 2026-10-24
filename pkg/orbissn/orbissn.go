// Package orbissn polls the Orbi's Linux shell (SSH or telnet) for
// per-client Wi-Fi radio stats that the SOAP API does not expose:
// `wlanconfig athX list sta` gives per-station RSSI, PHY rates, 802.11
// mode and association time.
//
// Only read-only commands are run. Credentials are never logged and never
// appear in error strings: every error is passed through a scrubber
// before it is stored or logged.
package orbissn

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Status is the shell-poll health reported to the UI. All fields empty
// means shell access is not configured (the UI hides the feature).
type Status struct {
	OK  bool   `json:"ok"`
	Via string `json:"via"` // "ssh" or "telnet"
	Err string `json:"err"` // short, credential-free error
}

// Snapshot is the latest shell-poll result.
type Snapshot struct {
	At       time.Time          `json:"-"`
	Stations map[string]Station `json:"stations"` // keyed by uppercase MAC
	Shell    Status             `json:"shell"`
	// RadioEnv is the per-radio RF environment from `iwconfig athX`
	// (noise floor, link quality, invalid-frame counters). Radios whose
	// output failed to parse are omitted; empty when the shell is down.
	RadioEnv []RadioEnv `json:"radioenv"`
	// SatelliteInfo is the raw `satelliteinfo wifi` output (best-effort,
	// not parsed or exported yet).
	SatelliteInfo string `json:"-"`
}

// Config selects the transports. Host defaults (in main) to the SOAP Orbi
// host. SSH is used when SSHPass is set (SSHUser defaults to "root");
// telnet when TelnetPass is set (user = SSHUser, else "root"). When both
// are configured SSH is tried first and telnet is the fallback.
type Config struct {
	Host       string
	SSHUser    string
	SSHPass    string
	TelnetPass string
}

// shell is one connected session able to run commands.
type shell interface {
	Run(ctx context.Context, cmd string) (string, error)
	Close() error
}

type transport struct {
	name string
	dial func(ctx context.Context) (shell, error)
}

const (
	pollEvery  = 60 * time.Second
	pollBudget = 30 * time.Second
	cmdTimeout = 10 * time.Second
)

// Poller runs the shell poll once a minute.
type Poller struct {
	mu         sync.RWMutex
	snap       Snapshot
	transports []transport
	secrets    []string
	onEvent    func(kind, sev, msg string)
	lastOK     *bool // nil until the first poll completed
}

// New builds a poller; it is disabled (Enabled false) when no transport
// is configured or the host is empty.
func New(cfg Config) *Poller {
	p := &Poller{snap: Snapshot{Stations: map[string]Station{}}}
	if cfg.Host == "" {
		return p
	}
	user := cfg.SSHUser
	if user == "" {
		user = "root"
	}
	if cfg.SSHPass != "" {
		p.transports = append(p.transports, transport{"ssh", newSSHDialer(net.JoinHostPort(cfg.Host, "22"), user, cfg.SSHPass)})
	}
	if cfg.TelnetPass != "" {
		p.transports = append(p.transports, transport{"telnet", newTelnetDialer(net.JoinHostPort(cfg.Host, "23"), user, cfg.TelnetPass)})
	}
	for _, s := range []string{cfg.SSHUser, cfg.SSHPass, cfg.TelnetPass} {
		if len(s) >= 3 { // scrubbing 1-2 char strings would mangle every message
			p.secrets = append(p.secrets, s)
		}
	}
	return p
}

// Enabled reports whether any shell transport is configured.
func (p *Poller) Enabled() bool { return p != nil && len(p.transports) > 0 }

// SetEventHook registers the callback fired when shell polling starts or
// stops working.
func (p *Poller) SetEventHook(fn func(kind, sev, msg string)) {
	if p != nil {
		p.onEvent = fn
	}
}

// Snapshot returns the latest result. Nil or unconfigured pollers report
// an empty station map and an all-empty Status.
func (p *Poller) Snapshot() Snapshot {
	if p == nil {
		return Snapshot{Stations: map[string]Station{}, RadioEnv: []RadioEnv{}}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	snap := p.snap // Stations/RadioEnv are replaced, never mutated, after commit
	if snap.RadioEnv == nil {
		snap.RadioEnv = []RadioEnv{}
	}
	return snap
}

// Run blocks, polling once a minute until ctx is done.
func (p *Poller) Run(ctx context.Context) {
	if !p.Enabled() {
		return
	}
	p.refresh(ctx)
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refresh(ctx)
		}
	}
}

func (p *Poller) refresh(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, pollBudget)
	defer cancel()
	snap := p.poll(ctx)
	if parent.Err() != nil {
		return // shutting down: don't report a spurious failure
	}
	p.mu.Lock()
	p.snap = snap
	prev := p.lastOK
	ok := snap.Shell.OK
	p.lastOK = &ok
	p.mu.Unlock()

	if prev == nil || *prev != ok {
		if ok {
			log.Printf("[orbissn] shell polling working via %s", snap.Shell.Via)
		} else {
			log.Printf("[orbissn] shell polling failed: %s", snap.Shell.Err)
		}
	}
	if prev != nil && *prev != ok && p.onEvent != nil {
		if ok {
			p.onEvent("wifi", "info", "Orbi shell polling working again via "+snap.Shell.Via)
		} else {
			p.onEvent("wifi", "info", "Orbi shell polling failed: "+snap.Shell.Err)
		}
	}
}

// poll tries each transport in order until one yields station data.
func (p *Poller) poll(ctx context.Context) Snapshot {
	snap := Snapshot{At: time.Now(), Stations: map[string]Station{}}
	var errs []string
	for _, tr := range p.transports {
		sh, err := tr.dial(ctx)
		if err != nil {
			errs = append(errs, tr.name+": "+p.scrub(err))
			continue
		}
		res, err := collect(ctx, sh)
		sh.Close()
		if err != nil {
			errs = append(errs, tr.name+": "+p.scrub(err))
			continue
		}
		snap.Stations, snap.SatelliteInfo, snap.RadioEnv = res.stations, res.sat, res.radioEnv
		snap.Shell = Status{OK: true, Via: tr.name}
		return snap
	}
	via := ""
	if len(p.transports) > 0 {
		via = p.transports[0].name
	}
	snap.Shell = Status{OK: false, Via: via, Err: truncate(strings.Join(errs, "; "), 160)}
	return snap
}

// Radios to poll for station lists. Which athX maps to which band differs
// across firmware (on Voxel RBR50, 2.4 GHz clients land on ath1 and 5 GHz
// clients on ath2), so every radio is polled and the band is derived from
// each row's CHAN column; the label here is only a fallback.
var radios = []string{"ath0", "ath1", "ath2"}

// collected is everything one successful shell session produced.
type collected struct {
	stations map[string]Station
	sat      string
	radioEnv []RadioEnv
}

// collect runs the read-only commands on one session. It succeeds when at
// least one radio's station list was read; the radio-environment and
// satellite commands are best-effort.
func collect(ctx context.Context, sh shell) (collected, error) {
	stations := map[string]Station{}
	ranAny := false
	for _, iface := range radios {
		out, err := sh.Run(ctx, "wlanconfig "+iface+" list sta")
		if err != nil && ctx.Err() == nil {
			out, err = sh.Run(ctx, "wlanconfig "+iface+" list stat") // older firmware spelling
		}
		if err != nil {
			if ctx.Err() != nil {
				return collected{}, errors.New("poll timed out")
			}
			continue
		}
		ranAny = true
		// A station row on the backhaul radio is the satellite's own
		// STA, not a client; it is keyed by MAC like the rest and the
		// UI joins stations to client devices by MAC, so satellites
		// are naturally excluded from client views. An idle radio
		// simply contributes no rows.
		for mac, st := range parseStations(out, "") {
			stations[mac] = st
		}
	}
	if !ranAny {
		return collected{}, errors.New("wlanconfig failed on all radios")
	}
	env := []RadioEnv{}
	for _, iface := range radios {
		if ctx.Err() != nil {
			break
		}
		// iwconfig exits non-zero on some builds even when it printed the
		// block, so parse whatever came back and let the parser decide.
		out, _ := sh.Run(ctx, "iwconfig "+iface)
		if re, ok := parseIwconfig(iface, out); ok {
			env = append(env, re)
		}
	}
	sat, _ := sh.Run(ctx, "satelliteinfo wifi")
	return collected{stations: stations, sat: sat, radioEnv: env}, nil
}

// scrub turns an error into a short message with any configured secret
// replaced, as a defence in depth against libraries echoing input.
func (p *Poller) scrub(err error) string {
	msg := err.Error()
	for _, s := range p.secrets {
		msg = strings.ReplaceAll(msg, s, "***")
	}
	return truncate(msg, 120)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// cmdDeadline is the earlier of now+cmdTimeout and the context deadline.
func cmdDeadline(ctx context.Context) time.Time {
	d := time.Now().Add(cmdTimeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}
