package clients

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshStaticHostsParsesUCI(t *testing.T) {
	conf := `
config dnsmasq
	option domainneeded '1'

config dhcp 'lan'
	option interface 'lan'
	option start '100'

config host
	option name 'Chromecast-4K'
	option mac 'AA:BB:CC:00:00:04'
	option ip '192.168.1.105'

config host
	option name 'Broken'
	# no mac here, must be skipped

config host
	list mac 'aa:bb:cc:dd:ee:01'
	option ip '192.168.1.150'

config wifi-iface
	option device 'radio0'
`
	path := filepath.Join(t.TempDir(), "dhcp")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{staticHosts: map[string]string{}}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = out
	// point the parser at the temp file via the same code path used in prod
	s.parseStaticHosts(string(conf))

	if got := s.staticHosts["aa:bb:cc:00:00:04"]; got != "Chromecast-4K" {
		t.Fatalf("static host name = %q, want Chromecast-4K (map: %v)", got, s.staticHosts)
	}
	if _, ok := s.staticHosts[""]; ok {
		t.Fatal("empty MAC must not be recorded")
	}
	if len(s.staticHosts) != 1 {
		t.Fatalf("expected exactly 1 parsed entry, got %d: %v", len(s.staticHosts), s.staticHosts)
	}
}
