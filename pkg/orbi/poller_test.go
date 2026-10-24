package orbi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

type event struct{ kind, sev, msg string }

type eventLog struct {
	mu  sync.Mutex
	evs []event
}

func (l *eventLog) hook(kind, sev, msg string) {
	l.mu.Lock()
	l.evs = append(l.evs, event{kind, sev, msg})
	l.mu.Unlock()
}

func (l *eventLog) msgs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.evs))
	for i, e := range l.evs {
		out[i] = e.msg
	}
	return out
}

func (l *eventLog) reset() {
	l.mu.Lock()
	l.evs = nil
	l.mu.Unlock()
}

func TestDiffEvents(t *testing.T) {
	sat := Device{MAC: "SAT", Name: "RBS50", ConnType: "-"}
	laptop := Device{MAC: "AA:01", Name: "Laptop", ConnType: "5G", ConnOrbi: ""}
	phone := Device{MAC: "AA:02", Name: "Unknown", DevType: "Phone", ConnType: "2.4G"}
	desk := Device{MAC: "AA:03", Name: "Desk", ConnType: "wired"}

	with := func(d Device, ct, ap string) Device { d.ConnType, d.ConnOrbi = ct, ap; return d }

	steps := []struct {
		name string
		devs []Device
		want []string
	}{
		{"baseline is silent", []Device{sat, laptop, desk}, nil},
		{"wifi join, wired join silent", []Device{sat, laptop, desk, phone, {MAC: "AA:04", Name: "Printer", ConnType: "wired"}},
			[]string{"Wi-Fi client joined: Phone (aa:02) on 2.4 GHz"}},
		{"band move", []Device{sat, with(laptop, "2.4G", ""), desk, phone},
			[]string{"Laptop (aa:01) moved from 5 GHz to 2.4 GHz"}},
		{"roam to satellite", []Device{sat, with(laptop, "2.4G", "SAT"), desk, phone},
			[]string{"Laptop (aa:01) roamed from unknown to RBS50"}},
		{"wifi leave, wired leave silent", []Device{sat, with(laptop, "2.4G", "SAT")},
			[]string{"Wi-Fi client left: Phone (aa:02) (was on 2.4 GHz)"}},
		{"no change", []Device{sat, with(laptop, "2.4G", "SAT")}, nil},
	}
	var log eventLog
	p := New("http://orbi", "admin", "pw", log.hook)
	p.SetNameResolver(func(mac string) string {
		if strings.EqualFold(mac, "aa:02") {
			return "Phone"
		}
		return mac
	})
	for _, s := range steps {
		log.reset()
		p.diffEvents(s.devs)
		got := log.msgs()
		if len(got) != len(s.want) {
			t.Fatalf("%s: events %q, want %q", s.name, got, s.want)
		}
		for i := range got {
			if got[i] != s.want[i] {
				t.Errorf("%s: event %d = %q, want %q", s.name, i, got[i], s.want[i])
			}
		}
	}

	// Without a hook diffEvents must be a harmless no-op.
	q := New("http://orbi", "", "", nil)
	q.diffEvents([]Device{laptop})
	if q.seenOK {
		t.Error("diffEvents without hook should not track state")
	}
}

func TestAPNameFor(t *testing.T) {
	devs := []Device{
		{MAC: "SAT1", Name: "Upstairs", ConnType: "-"},
		{MAC: "CLIENT", Name: "Laptop", ConnType: "5G"},
	}
	p := New("http://orbi", "", "", nil)
	cases := []struct {
		name, mac, model, want string
	}{
		{"empty MAC", "", "RBR50", "unknown"},
		{"satellite in table", "SAT1", "RBR50", "Upstairs"},
		{"client MAC is not an AP", "CLIENT", "RBR50", "RBR50"},
		{"router falls back to model", "ROUTER", "RBR50", "RBR50"},
		{"no model known", "ROUTER", "", "router"},
	}
	for _, tc := range cases {
		p.commit(State{Model: tc.model})
		if got := p.apNameFor(devs, tc.mac); got != tc.want {
			t.Errorf("%s: apNameFor(%q) = %q, want %q", tc.name, tc.mac, got, tc.want)
		}
	}
}

func TestEmitSatEvents(t *testing.T) {
	var log eventLog
	p := New("http://orbi", "", "", nil)
	p.emitSatEvents([]satEvent{{"X", true}}) // no hook: no panic
	p.SetEventHook(log.hook)
	p.emitSatEvents([]satEvent{{"RBS50", false}, {"RBS50", true}})
	want := []event{
		{"satellite", "warn", "RBS50 went offline"},
		{"satellite", "info", "RBS50 is back online"},
	}
	if len(log.evs) != len(want) {
		t.Fatalf("events = %+v", log.evs)
	}
	for i := range want {
		if log.evs[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, log.evs[i], want[i])
		}
	}
}

func TestNewEnabledSnapshot(t *testing.T) {
	var nilP *Poller
	if nilP.Enabled() || nilP.Snapshot().Reachable {
		t.Error("nil poller must be disabled")
	}
	if New("", "", "", nil).Enabled() {
		t.Error("empty URL must disable")
	}
	p := New("http://192.168.1.100///", "admin", "pw", nil)
	if !p.Enabled() || p.url != "http://192.168.1.100" {
		t.Errorf("url = %q", p.url)
	}
	if !p.Snapshot().At.IsZero() {
		t.Error("fresh poller should have zero snapshot")
	}
}

// fakeOrbi emulates the Orbi's HTTP surface used by refresh().
type fakeOrbi struct {
	mu            sync.Mutex
	logins        int
	expireOnce    bool // answer the next authenticated call with ResponseCode 401
	loginFails    bool
	attachStatus  int
	satsBody      string
	radiosBroken  bool
	gotPasswords  []string
	cookieChecked bool
}

const okSats = `<Envelope><Body><GetAllSatellitesResponse><CurrentSatellites>
<satellite><DeviceName>Upstairs</DeviceName><ModelName>RBS50</ModelName><MAC>10:20:30:40:50:60</MAC>
<IP>192.168.1.2</IP><Hop>1</Hop><BHConnStatus>1</BHConnStatus><SignalStrength>-58</SignalStrength><FWVersion>V2.7.3</FWVersion></satellite>
</CurrentSatellites></GetAllSatellitesResponse><ResponseCode>000</ResponseCode></Body></Envelope>`

func (f *fakeOrbi) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/currentsetting.htm" {
			io.WriteString(w, "Firmware=V2.7.5.4\rRegionTag=EU\rModel=RBR50\rDeviceMode=1\r")
			return
		}
		if r.URL.Path != soapPath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		action := r.Header.Get("SOAPAction")
		if action == loginAction {
			f.logins++
			start := strings.Index(string(body), "<Password>") + len("<Password>")
			end := strings.Index(string(body), "</Password>")
			f.gotPasswords = append(f.gotPasswords, string(body)[start:end])
			if f.loginFails {
				io.WriteString(w, "<ResponseCode>401</ResponseCode>")
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "jwt_local", Value: "tok"})
			io.WriteString(w, "<ResponseCode>000</ResponseCode>")
			return
		}
		if r.Header.Get("Cookie") != "jwt_local=tok" {
			t.Errorf("action %s sent cookie %q", action, r.Header.Get("Cookie"))
		} else {
			f.cookieChecked = true
		}
		if f.expireOnce {
			f.expireOnce = false
			io.WriteString(w, "<ResponseCode>401</ResponseCode>")
			return
		}
		switch action {
		case attachAction:
			if f.attachStatus != 0 {
				w.WriteHeader(f.attachStatus)
				return
			}
			io.WriteString(w, attachFixture)
		case wlanService + "#GetInfo":
			if f.radiosBroken {
				io.WriteString(w, "<Envelope><Body><ResponseCode>501</ResponseCode></Body></Envelope>")
				return
			}
			io.WriteString(w, `<Envelope><Body><GetInfoResponse><NewChannel> 6 </NewChannel><NewWirelessMode>300Mbps</NewWirelessMode><NewSSID>HomeNet</NewSSID></GetInfoResponse><ResponseCode>000</ResponseCode></Body></Envelope>`)
		case wlanService + "#Get5GInfo":
			if f.radiosBroken {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			io.WriteString(w, `<Envelope><Body><Get5GInfoResponse><NewChannel>44</NewChannel><NewWirelessMode> 866Mbps </NewWirelessMode><NewSSID>HomeNet</NewSSID></Get5GInfoResponse><ResponseCode>000</ResponseCode></Body></Envelope>`)
		case deviceService + "#GetAllSatellites":
			io.WriteString(w, f.satsBody)
		default:
			t.Errorf("unexpected SOAP action %q", action)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func TestRefreshHappyPathAndVMPush(t *testing.T) {
	f := &fakeOrbi{satsBody: okSats}
	orbiSrv := httptest.NewServer(f.handler(t))
	defer orbiSrv.Close()

	var importMu sync.Mutex
	var imported string
	vmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		importMu.Lock()
		imported = string(b)
		importMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer vmSrv.Close()

	p := New(orbiSrv.URL, "admin", `s3cr&t<`, nil)
	p.SetVMClient(vm.New(vmSrv.URL))
	p.refresh()
	st := p.Snapshot()

	if !st.Reachable || st.Busy || st.Model != "RBR50" || st.Firmware != "V2.7.5.4" || !st.APMode {
		t.Fatalf("state header = %+v", st)
	}
	if len(st.Devices) != 4 || st.Devices[0].ConnType != "5G" {
		t.Errorf("devices = %+v", st.Devices)
	}
	wantRadios := []RadioInfo{{Band: "2.4G", Channel: 6, Mode: "300Mbps", SSID: "HomeNet"}, {Band: "5G", Channel: 44, Mode: "866Mbps", SSID: "HomeNet"}}
	if len(st.Radios) != 2 || st.Radios[0] != wantRadios[0] || st.Radios[1] != wantRadios[1] {
		t.Errorf("radios = %+v", st.Radios)
	}
	wantSat := SatelliteInfo{Name: "Upstairs", Model: "RBS50", MAC: "10:20:30:40:50:60", IP: "192.168.1.2", Hop: 1,
		BackhaulConn: 1, BackhaulRSSI: -58, Firmware: "V2.7.3", Online: true}
	if len(st.Satellites) != 1 || st.Satellites[0] != wantSat {
		t.Errorf("satellites = %+v", st.Satellites)
	}
	if f.logins != 1 || !f.cookieChecked || len(f.gotPasswords) != 1 || f.gotPasswords[0] != "s3cr&amp;t&lt;" {
		t.Errorf("logins=%d cookie=%v passwords=%q", f.logins, f.cookieChecked, f.gotPasswords)
	}

	importMu.Lock()
	got := imported
	importMu.Unlock()
	lines := strings.Split(strings.TrimSpace(got), "\n")
	for i := range lines { // strip the timestamp column
		lines[i] = lines[i][:strings.LastIndex(lines[i], " ")]
	}
	sort.Strings(lines)
	want := []string{
		// Laptop connects via the satellite (named by its device-table
		// entry); Phone reports no ConnAPMAC.
		`orbi_ap_clients{ap="RBS50"} 1`,
		`orbi_ap_clients{ap="unknown"} 1`,
		`orbi_client_linkspeed{mac="AA:BB:CC:00:11:22",name="Laptop",band="5G"} 866`,
		`orbi_client_linkspeed{mac="AA:BB:CC:00:11:33",name="Phone",band="2.4G"} 0`,
		`orbi_client_signal{mac="AA:BB:CC:00:11:22",name="Laptop",band="5G"} 78`,
		`orbi_client_signal{mac="AA:BB:CC:00:11:33",name="Phone",band="2.4G"} 0`,
		`orbi_radio_channel{band="2.4G"} 6`,
		`orbi_radio_channel{band="5G"} 44`,
		`orbi_wifi_clients{band="2.4G"} 1`,
		`orbi_wifi_clients{band="5G"} 1`,
		// Desktop plus the satellite's own "-" entry.
		`orbi_wired_clients 2`,
	}
	sort.Strings(want)
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("VM import:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}

	// Second refresh reuses the session cookie.
	p.refresh()
	if f.logins != 1 {
		t.Errorf("cookie should be reused, logins=%d", f.logins)
	}
}

func TestRefreshReloginOnExpiredSession(t *testing.T) {
	f := &fakeOrbi{satsBody: okSats}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	p := New(srv.URL, "admin", "pw", nil)
	p.refresh()
	f.mu.Lock()
	f.expireOnce = true
	f.mu.Unlock()
	p.refresh()
	st := p.Snapshot()
	if st.Busy || len(st.Devices) != 4 {
		t.Errorf("expired session should be renewed transparently: %+v", st)
	}
	if f.logins != 2 {
		t.Errorf("logins = %d, want 2", f.logins)
	}
}

func TestRefreshFailureModes(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		p := New(srv.URL, "admin", "pw", nil)
		p.refresh()
		st := p.Snapshot()
		if st.Reachable || st.At.IsZero() || st.Devices == nil {
			t.Errorf("state = %+v", st)
		}
	})
	t.Run("login rejected marks busy", func(t *testing.T) {
		f := &fakeOrbi{loginFails: true}
		srv := httptest.NewServer(f.handler(t))
		defer srv.Close()
		p := New(srv.URL, "admin", "wrong", nil)
		p.refresh()
		st := p.Snapshot()
		if !st.Reachable || !st.Busy || st.Model != "RBR50" || len(st.Devices) != 0 {
			t.Errorf("state = %+v", st)
		}
	})
	t.Run("device list HTTP error marks busy", func(t *testing.T) {
		f := &fakeOrbi{attachStatus: http.StatusInternalServerError}
		srv := httptest.NewServer(f.handler(t))
		defer srv.Close()
		p := New(srv.URL, "admin", "pw", nil)
		p.refresh()
		if st := p.Snapshot(); !st.Busy {
			t.Errorf("state = %+v", st)
		}
	})
	t.Run("radio and satellite failures are best effort", func(t *testing.T) {
		f := &fakeOrbi{radiosBroken: true, satsBody: okSats}
		srv := httptest.NewServer(f.handler(t))
		defer srv.Close()
		var log eventLog
		p := New(srv.URL, "admin", "pw", log.hook)
		p.refresh()
		st := p.Snapshot()
		if st.Busy || len(st.Radios) != 0 || len(st.Satellites) != 1 {
			t.Fatalf("state = %+v", st)
		}
		// Satellite query now returns a non-zero code twice: remembered
		// list must be kept online (failed polls are not misses).
		f.mu.Lock()
		f.satsBody = `<Envelope><Body><ResponseCode>401001</ResponseCode></Body></Envelope>`
		f.mu.Unlock()
		p.refresh()
		p.refresh()
		st = p.Snapshot()
		if len(st.Satellites) != 1 || !st.Satellites[0].Online {
			t.Errorf("satellites after failed polls = %+v", st.Satellites)
		}
		// Successful empty answers twice: satellite goes offline with an event.
		f.mu.Lock()
		f.satsBody = `<Envelope><Body><GetAllSatellitesResponse/><ResponseCode>000</ResponseCode></Body></Envelope>`
		f.mu.Unlock()
		p.refresh()
		p.refresh()
		st = p.Snapshot()
		if len(st.Satellites) != 1 || st.Satellites[0].Online {
			t.Errorf("satellite should be offline: %+v", st.Satellites)
		}
		found := false
		for _, m := range log.msgs() {
			if m == "Upstairs went offline" {
				found = true
			}
		}
		if !found {
			t.Errorf("missing offline event in %q", log.msgs())
		}
	})
}

// The attached-device list in AP mode does not contain the mesh units, so a
// satellite AP MAC must resolve from the GetAllSatellites state; without that
// a RBS50→RBR50 roam reads as "roamed from RBR50 to RBR50".
func TestAPNameForResolvesSatelliteFromState(t *testing.T) {
	p := New("http://orbi", "", "", nil)
	p.commit(State{
		Model: "RBR50",
		Satellites: []SatelliteInfo{
			{MAC: "AA:BB:CC:00:00:05", Model: "RBS50"},
		},
	})
	if got := p.apNameFor(nil, "aa:bb:cc:00:00:05"); got != "RBS50" {
		t.Errorf("satellite MAC: apNameFor = %q, want RBS50", got)
	}
	if got := p.apNameFor(nil, "AA:BB:CC:00:00:01"); got != "RBR50" {
		t.Errorf("unknown MAC: apNameFor = %q, want router model fallback RBR50", got)
	}
}

// Event messages must prefer the panel's resolved client name (DHCP/static
// lease, vendor cache) over the Orbi's generic "Network (Generic)" label.
func TestClientNamePrefersResolvedName(t *testing.T) {
	p := New("http://orbi", "", "", nil)
	p.SetNameResolver(func(mac string) string {
		if strings.EqualFold(mac, "aa:bb:cc:00:00:06") {
			return "Nothing-2A"
		}
		return mac
	})
	d := Device{MAC: "AA:BB:CC:00:00:06", Name: "unknown", DevType: "Network (Generic)"}
	if got := p.clientName(d); got != "Nothing-2A" {
		t.Errorf("clientName = %q, want Nothing-2A", got)
	}

	// Unknown MAC (resolver echoes it back): fall through to the Orbi label.
	if got := p.clientName(Device{MAC: "AA:00:00:00:00:01", Name: "unknown", DevType: "Network (Generic)"}); got != "Network (Generic)" {
		t.Errorf("clientName(unknown) = %q, want Network (Generic)", got)
	}
}
