package clients

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// fakeEnv replaces PATH with a temp dir holding fake `nlbw`, `ip` and `cat`
// executables, so poll() runs end to end without a router. Scripts use only
// shell builtins because nothing else is on PATH.
type fakeEnv struct {
	t   *testing.T
	dir string
}

func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	e := &fakeEnv{t: t, dir: dir}
	e.set("nlbw", "", 0)
	e.set("neigh", "", 0)
	e.set("leases", "", 0)
	e.set("hosts", "", 0)
	e.script("nlbw", "nlbw")
	e.script("ip", "neigh")
	e.writeFile("cat", "#!/bin/sh\ncase \"$1\" in\n"+
		"*dhcp.leases) f=leases ;;\n*hosts) f=hosts ;;\n*) exit 1 ;;\nesac\n"+
		e.emit("$f"))
	return e
}

func (e *fakeEnv) writeFile(name, content string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, name), []byte(content), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

// emit prints data/<name>.out and exits with the code in data/<name>.exit.
func (e *fakeEnv) emit(name string) string {
	d := e.dir + "/data-"
	return "while IFS= read -r l || [ -n \"$l\" ]; do printf '%s\\n' \"$l\"; done < \"" + d + name + ".out\"\n" +
		"read -r code < \"" + d + name + ".exit\"\nexit $code\n"
}

func (e *fakeEnv) script(cmd, data string) {
	e.writeFile(cmd, "#!/bin/sh\n"+e.emit(data))
}

// set replaces the output and exit code of one fake data source.
func (e *fakeEnv) set(name, out string, exit int) {
	e.writeFile("data-"+name+".out", out)
	e.writeFile("data-"+name+".exit", string(rune('0'+exit))+"\n")
}

// newTestStore builds a Store isolated from /tmp and the real network.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := New(time.Hour, "")
	s.namesPath = filepath.Join(t.TempDir(), "names.json")
	s.vendors = map[string]string{}
	s.httpClient = &http.Client{Transport: failTransport{t}}
	return s
}

type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected network request to %s", r.URL)
	return nil, io.ErrUnexpectedEOF
}

// redirectTransport sends every request to the httptest server instead.
type redirectTransport struct{ target *url.URL }

func (rt redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme = rt.target.Scheme
	r.URL.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func vendorServer(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &http.Client{Transport: redirectTransport{u}, Timeout: 5 * time.Second}
}

func TestMacToOUI(t *testing.T) {
	tests := []struct{ mac, want string }{
		{"00:1A:2B:3C:4D:5E", "00:1a:2b"},
		{"  a4:83:e7:01:02:03 ", "a4:83:e7"},
		{"fa:69:11:22:33:44", "randomized"}, // locally administered bit set
		{"02:00:00:00:00:01", "randomized"},
		{"aa:bb", ""},
		{"", ""},
		{"zz:bb:cc:dd:ee:ff", ""},
	}
	for _, tc := range tests {
		if got := macToOUI(tc.mac); got != tc.want {
			t.Errorf("macToOUI(%q) = %q, want %q", tc.mac, got, tc.want)
		}
	}
}

func TestCleanVendor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Apple, Inc.", "Apple"},
		{"  Samsung Electronics Co.,Ltd \n", "Samsung Electronics Co."},
		{"Raspberry Pi Trading Ltd", "Raspberry Pi Trading Ltd"},
		{",leading comma", ",leading comma"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := cleanVendor(tc.in); got != tc.want {
			t.Errorf("cleanVendor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{`my "laptop"`, `my \"laptop\"`},
		{`back\slash`, `back\\slash`},
		{"multi\nline", "multi line"},
	}
	for _, tc := range tests {
		if got := sanitizeLabel(tc.in); got != tc.want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNameAndVendorResolution(t *testing.T) {
	s := newTestStore(t)
	s.leases = map[string]string{"00:11:22:33:44:55": "nas"}
	s.hosts = map[string]string{"192.168.1.20": "printer"}
	s.vendors = map[string]string{"a4:83:e7": "Apple", "00:aa:bb": "unknown"}

	tests := []struct {
		name, mac, ip       string
		wantName, wantVendr string
	}{
		{"dhcp lease wins", "00:11:22:33:44:55", "192.168.1.20", "nas", ""},
		{"hosts by ip", "00:99:88:77:66:55", "192.168.1.20", "printer", ""},
		{"vendor plus suffix", "a4:83:e7:01:9d:b0", "", "Apple 9db0", "Apple"},
		{"negative vendor cache falls back", "00:aa:bb:cc:12:34", "", "device-1234", ""},
		{"randomized mac", "fa:69:11:22:33:44", "", "device-3344", "randomized MAC"},
		{"malformed mac", "junk", "", "device-junk", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.nameFor(tc.mac, tc.ip); got != tc.wantName {
				t.Errorf("nameFor = %q, want %q", got, tc.wantName)
			}
			if got := s.vendorFor(tc.mac); got != tc.wantVendr {
				t.Errorf("vendorFor = %q, want %q", got, tc.wantVendr)
			}
		})
	}
}

func TestQueryVendor(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"found", 200, "Apple, Inc.", "Apple"},
		{"no vendor is cached negatively", 404, `{"errors":{"detail":"Not Found"}}`, "unknown"},
		{"rate limited is left uncached", 429, "Too Many Requests", ""},
		{"server error", 500, "boom", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			s := newTestStore(t)
			s.httpClient = vendorServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			if got := s.queryVendor("a4:83:e7"); got != tc.want {
				t.Errorf("queryVendor = %q, want %q", got, tc.want)
			}
			if gotPath != "/a4:83:e7" {
				t.Errorf("request path = %q, want /a4:83:e7", gotPath)
			}
		})
	}

	t.Run("offline", func(t *testing.T) {
		s := newTestStore(t)
		srv := httptest.NewServer(http.NotFoundHandler())
		u, _ := url.Parse(srv.URL)
		srv.Close() // connection refused
		s.httpClient = &http.Client{Transport: redirectTransport{u}, Timeout: time.Second}
		if got := s.queryVendor("a4:83:e7"); got != "" {
			t.Errorf("queryVendor offline = %q, want empty", got)
		}
	})
}

func TestVendorCachePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "names.json")
	a := newTestStore(t)
	a.namesPath = path
	a.vendors = map[string]string{"a4:83:e7": "Apple", "00:aa:bb": "unknown"}
	a.saveNamesCache()

	b := newTestStore(t)
	b.namesPath = path
	b.loadNamesCache()
	if len(b.vendors) != 2 || b.vendors["a4:83:e7"] != "Apple" || b.vendors["00:aa:bb"] != "unknown" {
		t.Errorf("reloaded vendors = %v", b.vendors)
	}

	if err := os.WriteFile(path, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newTestStore(t)
	c.namesPath = path
	c.vendors = map[string]string{"keep": "me"}
	c.loadNamesCache()
	if c.vendors["keep"] != "me" {
		t.Errorf("corrupt cache clobbered vendors: %v", c.vendors)
	}
}

func TestRefreshNamesFromLocalSourcesAndVendorAPI(t *testing.T) {
	env := newFakeEnv(t)
	env.set("leases", "1700000000 AA:BB:CC:00:00:01 192.168.1.10 phone *\n"+
		"1700000000 00:11:22:33:44:55 192.168.1.11 nas *\n"+
		"1700000000 00:11:22:33:44:66 192.168.1.12 * *\nshort line\n", 0)
	env.set("hosts", "127.0.0.1 localhost\n::1 localhost\n# 10.0.0.1 commented\n"+
		"192.168.1.20 printer printer.lan\n192.168.1.20 duplicate\n", 0)

	s := newTestStore(t)
	var queried []string
	var mu sync.Mutex
	s.httpClient = vendorServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queried = append(queried, r.URL.Path)
		mu.Unlock()
		_, _ = io.WriteString(w, "Apple, Inc.")
	})
	s.vendors["00:11:22"] = "Cached Vendor" // already known: must not be re-queried
	s.clients["a4:83:e7:01:02:03"] = &Client{MAC: "a4:83:e7:01:02:03"}
	s.clients["00:11:22:33:44:55"] = &Client{MAC: "00:11:22:33:44:55"}

	s.refreshNames()

	wantLeases := map[string]string{"aa:bb:cc:00:00:01": "phone", "00:11:22:33:44:55": "nas"}
	if len(s.leases) != len(wantLeases) {
		t.Errorf("leases = %v, want %v", s.leases, wantLeases)
	}
	for k, v := range wantLeases {
		if s.leases[k] != v {
			t.Errorf("leases[%q] = %q, want %q", k, s.leases[k], v)
		}
	}
	if len(s.hosts) != 1 || s.hosts["192.168.1.20"] != "printer" {
		t.Errorf("hosts = %v, want only 192.168.1.20 -> printer", s.hosts)
	}
	if len(queried) != 1 || queried[0] != "/a4:83:e7" {
		t.Errorf("vendor lookups = %v, want exactly [/a4:83:e7]", queried)
	}
	if s.vendors["a4:83:e7"] != "Apple" {
		t.Errorf("vendors = %v, want a4:83:e7 -> Apple", s.vendors)
	}
	reloaded := newTestStore(t)
	reloaded.namesPath = s.namesPath
	reloaded.loadNamesCache()
	if reloaded.vendors["a4:83:e7"] != "Apple" {
		t.Errorf("vendor cache not persisted: %v", reloaded.vendors)
	}

	// Within the 10-minute gate nothing is re-read.
	env.set("leases", "1700000000 aa:bb:cc:00:00:09 192.168.1.99 tablet *\n", 0)
	s.refreshNames()
	if s.leases["aa:bb:cc:00:00:09"] != "" {
		t.Error("refreshNames re-read leases inside the 10-minute gate")
	}
}

const nlbwOut = "aa:bb:cc:00:00:01  12  1000  10  500  5\n" +
	"00:11:22:33:44:55  3  9000000  900  100000  80\n" +
	"00:00:00:00:00:00  1  50  1  60  1\n" +
	"mac conns rx_bytes rx_pkts tx_bytes tx_pkts\n" + // header-ish junk
	"incomplete line\n"

const neighOut = "192.168.1.10 dev br-lan lladdr aa:bb:cc:00:00:01 REACHABLE\n" +
	"192.168.1.11 dev br-lan lladdr 00:11:22:33:44:55 FAILED\n" +
	"192.168.1.50 dev br-lan INCOMPLETE\n"

func TestPollBuildsSnapshot(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", nlbwOut, 0)
	env.set("neigh", neighOut, 0)
	s := newTestStore(t)
	s.namesAt = time.Now() // skip the slow name cycle
	s.leases = map[string]string{"aa:bb:cc:00:00:01": "phone"}

	if s.Available() {
		t.Fatal("Available() before first poll = true, want false")
	}
	if err := s.poll(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	if !s.Available() {
		t.Error("Available() after poll = false, want true")
	}

	got := s.Snapshot()
	want := []Client{ // sorted by rx+tx descending
		{MAC: "00:11:22:33:44:55", IP: "192.168.1.11", Name: "device-4455", Conns: 3, RxTotal: 9000000, TxTotal: 100000},
		{MAC: "aa:bb:cc:00:00:01", IP: "192.168.1.10", Name: "phone", Vendor: "randomized MAC", Conns: 12, RxTotal: 1000, TxTotal: 500, Online: true},
		{MAC: "00:00:00:00:00:00", Name: "untracked", Conns: 1, RxTotal: 50, TxTotal: 60},
	}
	if len(got) != len(want) {
		t.Fatalf("Snapshot() has %d clients, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Snapshot()[%d] = %+v\nwant %+v", i, got[i], want[i])
		}
	}

	if n := s.Name("aa:bb:cc:00:00:01"); n != "phone" {
		t.Errorf("Name(known) = %q, want phone", n)
	}
	if n := s.Name("de:ad:be:ef:00:00"); n != "de:ad:be:ef:00:00" {
		t.Errorf("Name(unknown) = %q, want the MAC itself", n)
	}
}

func TestPollComputesRates(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", "aa:bb:cc:00:00:01 1 1000 1 500 1\n", 0)
	s := newTestStore(t)
	s.namesAt = time.Now()

	if err := s.poll(); err != nil {
		t.Fatal(err)
	}
	if c := s.Snapshot()[0]; c.RxRate != 0 || c.TxRate != 0 || c.LastSeen != 0 || c.Online {
		t.Fatalf("first poll has no baseline, got rates %v/%v lastSeen %d online %v", c.RxRate, c.TxRate, c.LastSeen, c.Online)
	}

	steps := []struct {
		name           string
		line           string
		wantRx, wantTx float64
		wantActive     bool
	}{
		{"traffic since last poll", "aa:bb:cc:00:00:01 1 11000 1 2500 1\n", 1000, 200, true},
		{"idle", "aa:bb:cc:00:00:01 1 11000 1 2500 1\n", 0, 0, false},
		{"accounting period reset", "aa:bb:cc:00:00:01 1 10 1 5 1\n", 0, 0, false},
	}
	for _, st := range steps {
		env.set("nlbw", st.line, 0)
		s.mu.Lock()
		s.prevAt = s.prevAt.Add(-10 * time.Second) // pretend a 10s interval
		s.mu.Unlock()
		before := time.Now().Unix()
		if err := s.poll(); err != nil {
			t.Fatalf("%s: poll: %v", st.name, err)
		}
		c := s.Snapshot()[0]
		// elapsed is 10s plus the real time between polls, so allow 2%.
		if math.Abs(c.RxRate-st.wantRx) > st.wantRx*0.02 || math.Abs(c.TxRate-st.wantTx) > st.wantTx*0.02 {
			t.Errorf("%s: rates = %.1f/%.1f, want ~%.1f/%.1f", st.name, c.RxRate, c.TxRate, st.wantRx, st.wantTx)
		}
		if st.wantActive && (c.LastSeen < before || !c.Online) {
			t.Errorf("%s: LastSeen = %d Online = %v, want recent and online", st.name, c.LastSeen, c.Online)
		}
		if !st.wantActive && c.Online {
			t.Errorf("%s: Online = true for idle client not in neigh table", st.name)
		}
	}
}

func TestPollFailure(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", "", 1)
	s := newTestStore(t)
	s.namesAt = time.Now()
	if err := s.poll(); err == nil {
		t.Fatal("poll with failing nlbw returned nil error")
	}
	if s.Available() {
		t.Error("Available() = true after failed poll on empty store")
	}
	if n := len(s.Snapshot()); n != 0 {
		t.Errorf("Snapshot() has %d clients after failure, want 0", n)
	}

	// Recovers once nlbwmon answers again.
	env.set("nlbw", "aa:bb:cc:00:00:01 1 1 1 1 1\n", 0)
	if err := s.poll(); err != nil || !s.Available() {
		t.Errorf("after recovery: err=%v Available=%v", err, s.Available())
	}
}

func TestPollMarksVanishedClientsOffline(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", "aa:bb:cc:00:00:01 4 1000 1 500 1\n00:11:22:33:44:55 2 2000 1 700 1\n", 0)
	env.set("neigh", neighOut, 0)
	s := newTestStore(t)
	s.namesAt = time.Now()
	s.leases = map[string]string{"aa:bb:cc:00:00:01": "phone"}
	if err := s.poll(); err != nil {
		t.Fatal(err)
	}

	// Second poll: the phone has traffic, so it is online with live rates.
	env.set("nlbw", "aa:bb:cc:00:00:01 4 11000 1 2500 1\n00:11:22:33:44:55 2 2000 1 700 1\n", 0)
	s.mu.Lock()
	s.prevAt = s.prevAt.Add(-10 * time.Second)
	s.mu.Unlock()
	if err := s.poll(); err != nil {
		t.Fatal(err)
	}
	phone := func() Client {
		t.Helper()
		for _, c := range s.Snapshot() {
			if c.MAC == "aa:bb:cc:00:00:01" {
				return c
			}
		}
		t.Fatal("phone missing from Snapshot()")
		return Client{}
	}
	before := phone()
	if !before.Online || before.RxRate == 0 || before.TxRate == 0 || before.LastSeen == 0 {
		t.Fatalf("active phone = %+v, want online with rates", before)
	}

	// A failed poll says nothing about presence: state is kept as is.
	env.set("nlbw", "", 1)
	if err := s.poll(); err == nil {
		t.Fatal("poll with failing nlbw returned nil error")
	}
	if c := phone(); c != before {
		t.Errorf("after failed poll phone = %+v, want unchanged %+v", c, before)
	}

	// The phone drops out of nlbw output (still in the neigh table, which
	// must not resurrect it): offline, no live figures, history kept.
	env.set("nlbw", "00:11:22:33:44:55 2 2000 1 700 1\n", 0)
	if err := s.poll(); err != nil {
		t.Fatal(err)
	}
	want := before
	want.Online, want.RxRate, want.TxRate, want.Conns = false, 0, 0, 0
	if c := phone(); c != want {
		t.Errorf("vanished phone = %+v\nwant %+v", c, want)
	}
	if n := len(s.Snapshot()); n != 2 {
		t.Errorf("Snapshot() has %d clients, want 2 (vanished devices stay listed)", n)
	}

	// It comes back: online again, rates measured from the fresh baseline.
	env.set("nlbw", "aa:bb:cc:00:00:01 1 12000 1 3000 1\n", 0)
	if err := s.poll(); err != nil {
		t.Fatal(err)
	}
	if c := phone(); !c.Online || c.Conns != 1 || c.RxTotal != 12000 || c.RxRate != 0 {
		t.Errorf("returning phone = %+v, want online, conns 1, total 12000, no rate yet", c)
	}
}

func TestRunPushesCountersToVictoriaMetrics(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", "aa:bb:cc:00:00:01 7 1000 1 500 1\n", 0)
	env.set("neigh", "192.168.1.10 dev br-lan lladdr aa:bb:cc:00:00:01 REACHABLE\n", 0)

	bodies := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/import/prometheus" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		bodies <- string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := newTestStore(t)
	s.namesAt = time.Now()
	s.leases = map[string]string{"aa:bb:cc:00:00:01": `bob's "pc"`}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx, vm.New(srv.URL))
		close(done)
	}()

	var body string
	select {
	case body = <-bodies:
	case <-time.After(5 * time.Second):
		t.Fatal("no VictoriaMetrics import within 5s")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}

	labels := `mac="aa:bb:cc:00:00:01",name="bob's \"pc\""`
	for _, want := range []string{
		`client_bytes_total{` + labels + `,ip="192.168.1.10",dir="rx"} 1000 `,
		`client_bytes_total{` + labels + `,ip="192.168.1.10",dir="tx"} 500 `,
		`client_conns{` + labels + `} 7 `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("import body missing %q\nbody:\n%s", want, body)
		}
	}
	if n := strings.Count(strings.TrimSpace(body), "\n") + 1; n != 3 {
		t.Errorf("import body has %d lines, want 3", n)
	}

	// Run has returned, so poll() can be driven directly; s.vmc stays set
	// and each successful poll pushes once. A vanished device keeps being
	// exported (frozen totals, zero conns) until it is evicted after 24h.
	const phone, nas = "aa:bb:cc:00:00:01", "00:11:22:33:44:55"
	push := func(step string) string {
		t.Helper()
		if err := s.poll(); err != nil {
			t.Fatalf("%s: poll: %v", step, err)
		}
		select {
		case b := <-bodies:
			return b
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no VictoriaMetrics import within 5s", step)
			return ""
		}
	}
	env.set("nlbw", phone+" 7 1000 1 500 1\n"+nas+" 2 300 1 200 1\n", 0)
	push("both present")
	env.set("nlbw", nas+" 2 300 1 200 1\n", 0)
	for _, st := range []struct {
		name      string
		absent    time.Duration
		wantLines int
		wantPhone bool
	}{
		{"phone absent 23h is still exported", 23 * time.Hour, 6, true},
		{"phone absent over 24h is evicted", 24*time.Hour + time.Minute, 3, false},
		{"evicted phone stays gone", 0, 3, false},
	} {
		if st.absent > 0 {
			s.mu.Lock()
			s.seen[phone] = time.Now().Add(-st.absent)
			s.mu.Unlock()
		}
		body := push(st.name)
		if n := strings.Count(strings.TrimSpace(body), "\n") + 1; n != st.wantLines {
			t.Errorf("%s: import body has %d lines, want %d\n%s", st.name, n, st.wantLines, body)
		}
		if got := strings.Contains(body, `mac="`+phone+`"`); got != st.wantPhone {
			t.Errorf("%s: phone in import = %v, want %v\n%s", st.name, got, st.wantPhone, body)
		}
		if st.wantPhone && !strings.Contains(body, `client_conns{mac="`+phone+`",name="bob's \"pc\""} 0 `) {
			t.Errorf("%s: vanished phone should export zero conns\n%s", st.name, body)
		}
		if !strings.Contains(body, `mac="`+nas+`"`) {
			t.Errorf("%s: present nas missing from import\n%s", st.name, body)
		}
	}
}

func TestPollEvictsLongAbsentClients(t *testing.T) {
	const phone, nas = "aa:bb:cc:00:00:01", "00:11:22:33:44:55"
	tests := []struct {
		name      string
		absent    time.Duration // how long ago the phone was last listed
		present   bool          // phone listed in the current poll
		wantKept  bool
		wantOnlne bool
	}{
		{"absent 1 minute stays listed offline", time.Minute, false, true, false},
		{"absent 23h59m stays listed offline", 24*time.Hour - time.Minute, false, true, false},
		{"absent just over 24h is evicted", 24*time.Hour + time.Second, false, false, false},
		{"absent a week is evicted", 7 * 24 * time.Hour, false, false, false},
		{"old seen time but present again is kept", 48 * time.Hour, true, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv(t)
			env.set("neigh", neighOut, 0)
			env.set("nlbw", phone+" 4 1000 1 500 1\n"+nas+" 2 2000 1 700 1\n", 0)
			s := newTestStore(t)
			s.namesAt = time.Now()
			if err := s.poll(); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.seen[phone] = time.Now().Add(-tc.absent)
			s.mu.Unlock()

			if !tc.present {
				env.set("nlbw", nas+" 2 2000 1 700 1\n", 0)
			}
			if err := s.poll(); err != nil {
				t.Fatal(err)
			}

			var got *Client
			snap := s.Snapshot()
			for i := range snap {
				if snap[i].MAC == phone {
					got = &snap[i]
				}
			}
			if (got != nil) != tc.wantKept {
				t.Fatalf("phone in Snapshot() = %v, want %v: %+v", got != nil, tc.wantKept, snap)
			}
			if got != nil && got.Online != tc.wantOnlne {
				t.Errorf("phone Online = %v, want %v", got.Online, tc.wantOnlne)
			}
			if got != nil && got.RxTotal != 1000 {
				t.Errorf("phone RxTotal = %d, want 1000 (history kept)", got.RxTotal)
			}
			s.mu.RLock()
			_, inMap := s.clients[phone]
			_, inSeen := s.seen[phone]
			s.mu.RUnlock()
			if inMap != tc.wantKept || inSeen != tc.wantKept {
				t.Errorf("phone in clients/seen = %v/%v, want %v", inMap, inSeen, tc.wantKept)
			}
			if s.Name(nas) != "device-4455" {
				t.Errorf("present nas affected by eviction: Name = %q", s.Name(nas))
			}
		})
	}
}

func TestPollReadsNeighbourTableOncePerPoll(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", nlbwOut, 0)
	env.set("neigh", neighOut, 0)
	calls := filepath.Join(env.dir, "ip-calls")
	env.writeFile("ip", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \""+calls+"\"\n"+env.emit("neigh"))
	s := newTestStore(t)
	s.namesAt = time.Now()

	for poll := 1; poll <= 3; poll++ {
		if err := s.poll(); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(calls)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) != poll {
			t.Fatalf("after %d polls of 3 clients: %d ip invocations %q, want %d", poll, len(lines), lines, poll)
		}
		if lines[poll-1] != "-s neigh show" {
			t.Errorf("ip invoked with %q, want \"-s neigh show\"", lines[poll-1])
		}
	}
	// The single read still drives both IP resolution and online status.
	snap := s.Snapshot()
	if snap[0].IP != "192.168.1.11" || snap[0].Online || snap[1].IP != "192.168.1.10" || !snap[1].Online {
		t.Errorf("Snapshot() IP/online from shared neigh read wrong: %+v", snap)
	}
}

func TestReadNeigh(t *testing.T) {
	env := newFakeEnv(t)
	env.set("neigh", "192.168.1.10 dev br-lan lladdr AA:BB:CC:00:00:01 REACHABLE\n"+
		"fe80::1 dev br-lan lladdr aa:bb:cc:00:00:01 STALE\n"+ // second entry: first IP wins
		"192.168.1.11 dev br-lan lladdr 00:11:22:33:44:55 FAILED\n"+
		"10.0.0.2 dev wan lladdr 00:11:22:33:44:66 REACHABLE\n"+ // not br-lan: IP only
		"192.168.1.12 dev br-lan lladdr 00:11:22:33:44:77 router DELAY\n"+
		"192.168.1.13 dev br-lan lladdr 00:11:22:33:44:88\n"+ // no state
		"192.168.1.14 dev br-lan lladdr 00:11:22:33:44:99 used 300/300/280probes 1 STALE\n"+ // STALE but used recently
		"192.168.1.15 dev br-lan lladdr 00:11:22:33:44:aa used 20282/20282/20253probes 1 STALE\n"+ // ghost: device gone ~5h ago
		"192.168.1.50 dev br-lan INCOMPLETE\n", 0)
	online, ips := readNeigh()
	wantIPs := map[string]string{
		"aa:bb:cc:00:00:01": "192.168.1.10",
		"00:11:22:33:44:55": "192.168.1.11",
		"00:11:22:33:44:66": "10.0.0.2",
		"00:11:22:33:44:77": "192.168.1.12",
		"00:11:22:33:44:88": "192.168.1.13",
		"00:11:22:33:44:99": "192.168.1.14",
		"00:11:22:33:44:aa": "192.168.1.15",
	}
	if len(ips) != len(wantIPs) {
		t.Errorf("ips = %v, want %v", ips, wantIPs)
	}
	for k, v := range wantIPs {
		if ips[k] != v {
			t.Errorf("ips[%s] = %q, want %q", k, ips[k], v)
		}
	}
	wantOnline := map[string]bool{
		"aa:bb:cc:00:00:01": true, // REACHABLE
		"00:11:22:33:44:77": true, // DELAY
		"00:11:22:33:44:99": true, // STALE but used 300s ago: still around
		// 00:11:22:33:44:aa STALE used 5h ago: ghost, offline
	}
	if len(online) != len(wantOnline) {
		t.Errorf("online = %v, want %v", online, wantOnline)
	}
	for k := range wantOnline {
		if !online[k] {
			t.Errorf("online[%s] = false, want true", k)
		}
	}

	env.set("neigh", "", 1)
	if online, ips := readNeigh(); len(online) != 0 || len(ips) != 0 {
		t.Errorf("failed ip neigh: online=%v ips=%v, want empty", online, ips)
	}
}

func TestSnapshotOrderIsStable(t *testing.T) {
	// Ties on rx+tx (even with different rx/tx splits) are broken by MAC, so
	// map iteration order never leaks into the table.
	clients := []Client{
		{MAC: "aa:00:00:00:00:05", RxTotal: 100, TxTotal: 0},
		{MAC: "aa:00:00:00:00:01", RxTotal: 50, TxTotal: 50},
		{MAC: "aa:00:00:00:00:03", RxTotal: 0, TxTotal: 100},
		{MAC: "aa:00:00:00:00:09", RxTotal: 5000, TxTotal: 1},
		{MAC: "aa:00:00:00:00:02", RxTotal: 100, TxTotal: 0},
		{MAC: "aa:00:00:00:00:04", RxTotal: 1, TxTotal: 1},
		{MAC: "aa:00:00:00:00:00", RxTotal: 1, TxTotal: 1},
	}
	want := []string{
		"aa:00:00:00:00:09",
		"aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03", "aa:00:00:00:00:05",
		"aa:00:00:00:00:00", "aa:00:00:00:00:04",
	}
	s := newTestStore(t)
	for i := range clients {
		c := clients[i]
		s.clients[c.MAC] = &c
	}
	for round := 0; round < 50; round++ {
		if round%10 == 0 { // rebuild the map so iteration order is reshuffled
			m := map[string]*Client{}
			for k, v := range s.clients {
				m[k] = v
			}
			s.clients = m
		}
		got := s.Snapshot()
		for i := range want {
			if got[i].MAC != want[i] {
				t.Fatalf("round %d: order = %v, want %v", round, macs(got), want)
			}
		}
	}
}

func TestPollKeepsEqualTotalsInPlaceAcrossSnapshots(t *testing.T) {
	env := newFakeEnv(t)
	var b strings.Builder
	for _, m := range []string{"aa:00:00:00:00:04", "aa:00:00:00:00:02", "aa:00:00:00:00:03", "aa:00:00:00:00:01"} {
		b.WriteString(m + " 1 100 1 100 1\n")
	}
	env.set("nlbw", b.String(), 0)
	s := newTestStore(t)
	s.namesAt = time.Now()
	want := []string{"aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03", "aa:00:00:00:00:04"}
	for i := 0; i < 5; i++ {
		if err := s.poll(); err != nil {
			t.Fatal(err)
		}
		if got := macs(s.Snapshot()); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("poll %d: order = %v, want %v", i, got, want)
		}
	}
}

func macs(cs []Client) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.MAC
	}
	return out
}

func TestConcurrentReadsDuringPoll(t *testing.T) {
	env := newFakeEnv(t)
	env.set("nlbw", nlbwOut, 0)
	env.set("neigh", neighOut, 0)
	s := newTestStore(t)
	s.namesAt = time.Now()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.Snapshot()
					_ = s.Name("aa:bb:cc:00:00:01")
					_ = s.Available()
				}
			}
		}()
	}
	for i := 0; i < 5; i++ {
		if err := s.poll(); err != nil {
			t.Errorf("poll %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if n := len(s.Snapshot()); n != 3 {
		t.Errorf("Snapshot() has %d clients, want 3", n)
	}
}

func TestPollExcludesRouterOwnMACs(t *testing.T) {
	netDir := t.TempDir()
	for iface, addr := range map[string]string{
		"br-lan": "aa:bb:cc:00:00:99\n",
		"eth0":   "aa:00:00:00:00:99\n",
	} {
		if err := os.MkdirAll(filepath.Join(netDir, iface), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(netDir, iface, "address"), []byte(addr), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	env := newFakeEnv(t)
	env.set("nlbw", "aa:bb:cc:00:00:99 1 100 1 100 1\naa:00:00:00:00:01 2 300 1 100 1\n", 0)
	env.set("neigh", "", 0)
	s := newTestStore(t)
	s.netSysDir = netDir
	s.namesAt = time.Now()
	if err := s.poll(); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot()
	if len(got) != 1 || got[0].MAC != "aa:00:00:00:00:01" {
		t.Fatalf("Snapshot() = %v, want only aa:00:00:00:00:01 (router's own MAC filtered)", macs(got))
	}
}
