package sysmon

import (
	"context"
	"strings"
	"testing"
)

// Fixtures mirror the real router: /etc/config/pbr with a mix of enabled
// and disabled policies, and the pbr chains `nft list table inet fw4`
// prints for them (one goto rule per enabled policy, counter + comment).

const pbrCfgFixture = `
config pbr 'config'
	option enabled '1'
	option nft_rule_counter '1'
	list supported_interface 'wg0'

config dns_policy
	option name 'Redirect Local IP DNS'
	option src_addr '192.168.1.5'
	option dest_dns '1.1.1.1'
	option enabled '0'

config policy
	option name 'Ignore Local Requests'
	option interface 'ignore'
	option dest_addr '10.0.0.0/24 10.0.1.0/24 192.168.100.0/24 192.168.1.0/24'
	option enabled '0'

config policy
	option name 'Sony TV via WARP'
	option src_addr '192.168.1.104'
	option interface 'wg0'
	option enabled '1'

config policy
	option name 'Plex Remote'
	option dest_addr 'plex.tv'
	option src_port '8096 32400'
	option interface 'wan'

config policy
	option name 'Old Rule'
	option interface 'wan'
	option enabled '0'
`

// Sony TV and Plex Remote are enabled → goto rules with counters. The
// fixture also keeps a rule for the config-disabled 'Ignore Local
// Requests' (a stale rule) to prove the join stays truthful without
// duplicating the row. The mark-set rules inside the
// pbr_mark chains and fw4's own counters must be ignored.
const nftFixture = `table inet fw4 {
	chain pbr_prerouting {
		meta mark & 0x00ff0000 != 0x00000000 counter packets 5751676 bytes 8829887380 return
		ip saddr 192.168.1.104 counter packets 195290 bytes 16773300 goto pbr_mark_0x020000 comment "Sony TV via WARP"
		ip daddr 10.0.0.0/24 counter packets 42 bytes 4200 goto pbr_mark_0x010000 comment "Ignore Local Requests"
		counter packets 7 bytes 700 goto pbr_mark_0x030000 comment "Plex Remote"
		meta mark & 0x00ff0000 != 0x00000000 counter packets 100 bytes 10000 return
	}
	chain pbr_mark_0x020000 {
		counter packets 195290 bytes 16773300 meta mark set meta mark & 0xff02ffff | 0x00020000
		return
	}
	chain pbr_dstnat {
	}
}
`

// withPbrFixtures points the poller at a temp config and installs a fake
// nft whose output is nft ("" → nft fails, as on a box without the tool).
func withPbrFixtures(t *testing.T, cfg, nftOut string) {
	t.Helper()
	if nftOut == "" {
		fakeBin(t, "nft", "exit 1")
	} else {
		fakeBin(t, "nft", "cat <<'NFT_EOF'\n"+nftOut+"\nNFT_EOF")
	}
	writeFile(t, pbrConfigPath, cfg) // pbrConfigPath set below
}

func TestParsePbrConfig(t *testing.T) {
	got := parsePbrConfig(pbrCfgFixture)
	if len(got) != 4 {
		t.Fatalf("want 4 policies, got %d: %+v", len(got), got)
	}
	if got[0].Name != "Ignore Local Requests" || got[0].Enabled {
		t.Errorf("policy 0 = %+v, want disabled 'Ignore Local Requests'", got[0])
	}
	if got[0].Exit != "ignore" || got[0].Dst == "" {
		t.Errorf("policy 0 exit/dest not parsed: %+v", got[0])
	}
	if !got[1].Enabled || got[1].Exit != "wg0" || got[1].Src != "192.168.1.104" {
		t.Errorf("policy 1 (Sony TV) not parsed: %+v", got[1])
	}
	// Missing enabled option → enabled by OpenWrt convention.
	if !got[2].Enabled || got[2].Ports != "8096 32400" || got[2].Dst != "plex.tv" {
		t.Errorf("policy 2 not parsed / should default to enabled: %+v", got[2])
	}
	// The global `config pbr` block and dns_policy must not leak in.
	for _, p := range got {
		if p.Name == "" || p.Exit == "" {
			t.Errorf("non-policy block leaked as a policy: %+v", p)
		}
	}
}

func TestParseNftPbr(t *testing.T) {
	rules := parseNftPbr(nftFixture)
	if len(rules) != 3 {
		t.Fatalf("want 3 policy rules, got %d: %+v", len(rules), rules)
	}
	warp := rules["Sony TV via WARP"]
	if warp.Bytes != 16773300 || warp.Packets != 195290 {
		t.Errorf("Sony TV counters wrong: %+v", warp)
	}
	// The match text must not carry the counter/goto/comment noise.
	if strings.Contains(warp.Match, "counter") || strings.Contains(warp.Match, "goto") ||
		strings.Contains(warp.Match, "comment") {
		t.Errorf("match text not cleaned: %q", warp.Match)
	}
	if !strings.Contains(warp.Match, "192.168.1.104") {
		t.Errorf("match text lost the selector: %q", warp.Match)
	}
}

func TestPbrPollerRatesAndJoin(t *testing.T) {
	oldPath := pbrConfigPath
	pbrConfigPath = t.TempDir() + "/pbr"
	t.Cleanup(func() { pbrConfigPath = oldPath })
	withPbrFixtures(t, pbrCfgFixture, nftFixture)

	p := &PbrPoller{}
	p.refresh()
	got := p.Snapshot()
	if len(got) != 4 {
		t.Fatalf("want 4 policies joined, got %d: %+v", len(got), got)
	}
	sony := got[1]
	if sony.Name != "Sony TV via WARP" || !sony.Active || !sony.Enabled {
		t.Fatalf("Sony TV policy not joined/active: %+v", sony)
	}
	if sony.RatesKnown || sony.BytesPerS != 0 {
		t.Errorf("first poll must not claim rates: %+v", sony)
	}
	// 'Ignore Local Requests' is disabled in the config but has a live nft
	// rule in the fixture → truthfully active, no duplicate row.
	ignore := got[0]
	if ignore.Enabled || !ignore.Active || ignore.Bytes != 4200 {
		t.Errorf("stale-rule policy join wrong: %+v", ignore)
	}
	// 'Old Rule' is disabled with no nft rule → present but inactive.
	old := got[3]
	if old.Name != "Old Rule" || old.Enabled || old.Active {
		t.Errorf("disabled policy without rule reported active: %+v", old)
	}

	// Second poll with more bytes → rate known. Bump the Sony counter
	// instead of waiting 15 s; elapsed is wall-clock, so only assert the
	// rate exists and is positive.
	bumped := strings.Replace(nftFixture, "16773300 goto", "19173300 goto", 1)
	withPbrFixtures(t, pbrCfgFixture, bumped)
	p.refresh()
	got = p.Snapshot()
	sony = got[1]
	if !sony.Active || !sony.RatesKnown || sony.BytesPerS <= 0 {
		t.Fatalf("second poll should yield a positive rate: %+v", sony)
	}
	if sony.Bytes != 19173300 {
		t.Errorf("counter not refreshed: %+v", sony)
	}
}

func TestPbrPollerNoNft(t *testing.T) {
	oldPath := pbrConfigPath
	pbrConfigPath = t.TempDir() + "/pbr"
	t.Cleanup(func() { pbrConfigPath = oldPath })
	withPbrFixtures(t, pbrCfgFixture, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewPbr(ctx)
	if p.Available() {
		t.Error("available must be false when nft fails")
	}
	if len(p.Snapshot()) != 0 {
		t.Errorf("failed poll must not produce states: %+v", p.Snapshot())
	}
}
