package sysmon

// Policy-routing (pbr) monitoring. pbr writes one nft rule per enabled
// policy into table inet fw4, tags it with the policy name as a comment and
// — with nft_rule_counter '1' in /etc/config/pbr — gives it a per-rule
// counter. Reading those counters yields per-policy traffic without
// touching the data path. The poller joins them with /etc/config/pbr so
// disabled policies (no nft rule) still appear, greyed out, in the
// dashboard instead of silently disappearing.

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PbrPolicyState is one pbr policy and its live counters.
type PbrPolicyState struct {
	Name       string  `json:"name"`
	Exit       string  `json:"exit"`        // egress interface from the config: wg0, wan, ignore…
	Match      string  `json:"match"`       // human-readable selector summary from the config
	Enabled    bool    `json:"enabled"`     // enabled in /etc/config/pbr
	Active     bool    `json:"active"`      // has a live nft rule with a counter
	Bytes      uint64  `json:"bytes"`       // lifetime bytes matched by the policy rule
	Packets    uint64  `json:"packets"`     // lifetime packets matched
	BytesPerS  float64 `json:"bytes_per_s"` // matched-traffic rate, 15 s average
	RatesKnown bool    `json:"rates_ok"`    // false until a second poll exists to diff against
}

// pbrCfg is one `config policy` block from /etc/config/pbr.
type pbrCfg struct {
	Name    string
	Exit    string
	Src     string
	Dst     string
	Ports   string
	Enabled bool
}

// pbrRule is one `goto pbr_mark_*` rule found in table inet fw4.
type pbrRule struct {
	Match   string
	Bytes   uint64
	Packets uint64
}

// PbrPoller refreshes the policy snapshot every 15 seconds. Rates are
// 15-second averages of the nft byte counters — the rules move slowly
// (a single client's WARP traffic), so faster polling buys nothing.
type PbrPoller struct {
	mu        sync.RWMutex
	st        []PbrPolicyState
	available bool
	prevBytes map[string]uint64 // policy name → bytes at the previous poll
	prevOK    bool
	prevAt    time.Time
}

// pbrConfigPath is where pbr keeps its UCI config; a var so tests can
// point the poller at a fixture.
var pbrConfigPath = "/etc/config/pbr"

// NewPbr starts the poller with a synchronous first snapshot.
func NewPbr(ctx context.Context) *PbrPoller {
	p := &PbrPoller{}
	p.refresh()
	go p.loop(ctx)
	return p
}

// Snapshot returns the latest known policy states, config order preserved.
func (p *PbrPoller) Snapshot() []PbrPolicyState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]PbrPolicyState, len(p.st))
	copy(out, p.st)
	return out
}

// Available reports whether pbr answered (nft present, table readable).
func (p *PbrPoller) Available() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

func (p *PbrPoller) loop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
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

func (p *PbrPoller) refresh() {
	cfgs := parsePbrConfig(readFile(pbrConfigPath))
	out, err := exec.Command("nft", "list", "table", "inet", "fw4").Output()
	now := time.Now()
	if err != nil {
		// No nft or no fw4 table: nothing to report this round. Keep the
		// last snapshot so a transient failure doesn't blank the panel.
		p.mu.Lock()
		p.available = false
		p.mu.Unlock()
		return
	}
	rules := parseNftPbr(string(out))

	states := make([]PbrPolicyState, 0, len(cfgs)+len(rules))
	seen := map[string]bool{}
	for _, c := range cfgs {
		st := PbrPolicyState{
			Name:    c.Name,
			Exit:    c.Exit,
			Match:   pbrMatchSummary(c),
			Enabled: c.Enabled,
		}
		if r, ok := rules[c.Name]; ok {
			// A live rule means traffic really is being matched — even for
			// a policy the config marks disabled (stale rule), show the
			// truth: active + counters, with the disabled tag alongside.
			st.Active = true
			st.Bytes, st.Packets = r.Bytes, r.Packets
			seen[c.Name] = true
		}
		states = append(states, st)
	}
	// Rules without a matching config block (hand-edited nft, config since
	// removed) still carry traffic — show them rather than drop them.
	for name, r := range rules {
		if seen[name] {
			continue
		}
		states = append(states, PbrPolicyState{
			Name: name, Match: r.Match, Enabled: true, Active: true,
			Bytes: r.Bytes, Packets: r.Packets,
		})
	}

	prev, prevAt, prevOK := p.prevBytes, p.prevAt, p.prevOK
	for i := range states {
		if !states[i].Active {
			continue
		}
		if pb, ok := prev[states[i].Name]; ok && prevOK {
			elapsed := now.Sub(prevAt).Seconds()
			if elapsed > 0 && states[i].Bytes >= pb {
				states[i].BytesPerS = float64(states[i].Bytes-pb) / elapsed
				states[i].RatesKnown = true
			}
		}
	}

	cur := map[string]uint64{}
	for _, s := range states {
		if s.Active {
			cur[s.Name] = s.Bytes
		}
	}

	p.mu.Lock()
	p.st = states
	p.available = true
	p.prevBytes = cur
	p.prevAt = now
	p.prevOK = true
	p.mu.Unlock()
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// parsePbrConfig reads the UCI text format of /etc/config/pbr and returns
// the `config policy` blocks in file order. Only policies matter here; the
// `config pbr 'config'` global block and includes are skipped. A missing
// `enabled` option means enabled (OpenWrt boolean convention).
func parsePbrConfig(content string) []pbrCfg {
	var out []pbrCfg
	var cur *pbrCfg
	flush := func() {
		if cur != nil && cur.Name != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "config "):
			flush()
			kind := strings.TrimSpace(strings.TrimPrefix(line, "config "))
			kind = strings.Fields(kind)[0]
			if kind == "policy" {
				cur = &pbrCfg{Enabled: true}
			}
		case cur != nil && strings.HasPrefix(line, "option "):
			rest := strings.TrimPrefix(line, "option ")
			sp := strings.SplitN(rest, " ", 2)
			if len(sp) != 2 {
				break
			}
			key := strings.Trim(sp[0], "'\"")
			val := strings.Trim(sp[1], "'\"")
			switch key {
			case "name":
				cur.Name = val
			case "interface":
				cur.Exit = val
			case "src_addr", "src_mac":
				cur.Src = joinOpt(cur.Src, val)
			case "dest_addr":
				cur.Dst = joinOpt(cur.Dst, val)
			case "src_port", "dest_port":
				cur.Ports = joinOpt(cur.Ports, val)
			case "enabled":
				cur.Enabled = val == "1"
			}
		}
	}
	flush()
	return out
}

// joinOpt appends a value to a space-separated summary field. UCI may hold
// several values in one option ('plex.tv my.plexapp.com') or in repeated
// list entries; both end up as one readable string.
func joinOpt(cur, val string) string {
	if cur == "" {
		return val
	}
	return cur + ", " + val
}

var (
	nftCounterRe = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
	nftCommentRe = regexp.MustCompile(`comment "([^"]*)"`)
	nftGotoRe    = regexp.MustCompile(`goto \S+`)
)

// matchClean converts the raw nft match expressions into the short form the
// panel shows: "ip saddr 192.168.1.104 tcp sport 8096" → "192.168.1.104
// tcp sport 8096". Family prefixes carry no information the interface name
// doesn't already give.
var matchClean = strings.NewReplacer(
	"ip saddr ", "", "ip daddr ", "",
	"ip6 saddr ", "", "ip6 daddr ", "",
	"ether saddr ", "mac ", "ether daddr ", "mac ",
)

// parseNftPbr extracts the pbr policy rules — those jumping to a
// pbr_mark chain with a counter — from `nft list table inet fw4` output,
// keyed by the comment (the policy name). Everything else (the mark-set
// rules inside the chains, fw4's own counters) is ignored.
func parseNftPbr(content string) map[string]pbrRule {
	out := map[string]pbrRule{}
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "goto pbr_mark_") || !strings.Contains(line, "counter") {
			continue
		}
		cm := nftCommentRe.FindStringSubmatch(line)
		if cm == nil || strings.TrimSpace(cm[1]) == "" {
			continue // untagged rule — cannot be attributed to a policy
		}
		// Match text = the rule line minus the parts that carry no
		// selector information: the counter, the jump target and the
		// comment that keys the map.
		match := line
		for _, junk := range []string{
			nftCounterRe.FindString(line),
			nftCommentRe.FindString(line),
			nftGotoRe.FindString(line),
		} {
			match = strings.ReplaceAll(match, junk, "")
		}
		r := pbrRule{Match: strings.TrimSpace(matchClean.Replace(match))}
		if m := nftCounterRe.FindStringSubmatch(line); m != nil {
			r.Packets, _ = strconv.ParseUint(m[1], 10, 64)
			r.Bytes, _ = strconv.ParseUint(m[2], 10, 64)
		}
		out[cm[1]] = r
	}
	return out
}

// pbrMatchSummary renders the config-side selectors as the one-line match
// description shown under each policy name.
func pbrMatchSummary(c pbrCfg) string {
	var parts []string
	if c.Src != "" {
		parts = append(parts, "from "+c.Src)
	}
	if c.Ports != "" {
		parts = append(parts, "ports "+c.Ports)
	}
	if c.Dst != "" {
		parts = append(parts, "to "+c.Dst)
	}
	if len(parts) == 0 {
		return "all traffic"
	}
	return strings.Join(parts, ", ")
}
