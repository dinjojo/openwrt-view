package orbi

import (
	"encoding/xml"
	"strings"
	"testing"
)

const attachFixture = `<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/">
<soap-env:Body>
<m:GetAttachDevice2Response xmlns:m="urn:NETGEAR-ROUTER:service:DeviceInfo:1">
<NewAttachDevice>
<Device>
  <IP> 192.168.1.20 </IP>
  <Name> Laptop </Name>
  <MAC>aa:bb:cc:00:11:22</MAC>
  <ConnectionType>5GHz</ConnectionType>
  <SSID> HomeNet </SSID>
  <Linkspeed>866</Linkspeed>
  <SignalStrength>78</SignalStrength>
  <DeviceModel> MacBook </DeviceModel>
  <DeviceTypeNameV2>Computer (Generic)</DeviceTypeNameV2>
  <ConnAPMAC> 10:20:30:40:50:60 </ConnAPMAC>
  <Upload>1.25</Upload>
  <Download>12.5 Mbps</Download>
</Device>
<Device>
  <IP>192.168.1.21</IP>
  <Name>Phone</Name>
  <MAC>AA:BB:CC:00:11:33</MAC>
  <ConnectionType>2.4GHz</ConnectionType>
  <SignalStrength>n/a</SignalStrength>
  <Linkspeed></Linkspeed>
</Device>
<Device>
  <IP>192.168.1.2</IP>
  <Name>RBS50</Name>
  <MAC>10:20:30:40:50:60</MAC>
  <ConnectionType>-</ConnectionType>
</Device>
<Device>
  <IP>192.168.1.30</IP>
  <Name>NoMac</Name>
  <MAC></MAC>
</Device>
<Device>
  <IP>192.168.1.40</IP>
  <Name>Desktop</Name>
  <MAC>aa:bb:cc:00:11:44</MAC>
  <ConnectionType>wired</ConnectionType>
  <SignalStrength>100</SignalStrength>
</Device>
</NewAttachDevice>
</m:GetAttachDevice2Response>
</soap-env:Body>
</soap-env:Envelope>`

func TestParseDevices(t *testing.T) {
	devs, err := parseDevices(attachFixture)
	if err != nil {
		t.Fatal(err)
	}
	want := []Device{
		{MAC: "AA:BB:CC:00:11:22", IP: "192.168.1.20", Name: "Laptop", ConnType: "5G", DevType: "Computer (Generic)",
			Model: "MacBook", ConnOrbi: "10:20:30:40:50:60", Uprate: 1.25, Downrate: 12.5, Signal: 78, Linkspeed: 866, SSID: "HomeNet"},
		{MAC: "AA:BB:CC:00:11:33", IP: "192.168.1.21", Name: "Phone", ConnType: "2.4G"},
		{MAC: "10:20:30:40:50:60", IP: "192.168.1.2", Name: "RBS50", ConnType: "-"},
		{MAC: "AA:BB:CC:00:11:44", IP: "192.168.1.40", Name: "Desktop", ConnType: "wired", Signal: 100},
	}
	if len(devs) != len(want) {
		t.Fatalf("got %d devices %+v, want %d (entry without MAC must be dropped)", len(devs), devs, len(want))
	}
	for i := range want {
		if devs[i] != want[i] {
			t.Errorf("device %d:\n got %+v\nwant %+v", i, devs[i], want[i])
		}
	}
}

func TestParseDevicesEdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
		wantN   int
	}{
		{"malformed XML", `<soap-env:Envelope><Body>`, true, 0},
		{"empty body", ``, true, 0},
		{"HTML login page", `<html><body>multi_login.html</body></html>`, false, 0},
		{"empty device list", `<Envelope><Body><GetAttachDevice2Response><NewAttachDevice></NewAttachDevice></GetAttachDevice2Response></Body></Envelope>`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			devs, err := parseDevices(tc.body)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && (devs == nil || len(devs) != tc.wantN) {
				t.Errorf("devs = %#v, want non-nil len %d", devs, tc.wantN)
			}
		})
	}
}

func TestNormalizeConn(t *testing.T) {
	cases := map[string]string{
		"5GHz":     "5G",
		" 5GHz ":   "5G",
		"2.4GHz":   "2.4G",
		"wired":    "wired",
		" wired\n": "wired",
		"-":        "-",
		"":         "",
		"6GHz":     "6GHz",
	}
	for in, want := range cases {
		if got := normalizeConn(in); got != want {
			t.Errorf("normalizeConn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAtoiDefault(t *testing.T) {
	cases := []struct {
		in   string
		def  int
		want int
	}{
		{"42", 0, 42},
		{" -60 ", 0, -60},
		{"", 7, 7},
		{"n/a", -1, -1},
		{"3.5", 9, 9},
	}
	for _, tc := range cases {
		if got := atoiDefault(tc.in, tc.def); got != tc.want {
			t.Errorf("atoiDefault(%q, %d) = %d, want %d", tc.in, tc.def, got, tc.want)
		}
	}
}

func TestParseRate(t *testing.T) {
	cases := map[string]float64{
		"866":       866,
		" 1.25 ":    1.25,
		"12.5 Mbps": 12.5,
		"0":         0,
		"":          0,
		"--":        0,
		"1e2":       100,
		"144.4Mbps": 144.4,
	}
	for in, want := range cases {
		if got := parseRate(in); got != want {
			t.Errorf("parseRate(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSanitizeLabel(t *testing.T) {
	cases := map[string]string{
		`plain`:          `plain`,
		`Bob's "iPhone"`: `Bob's \"iPhone\"`,
		`back\slash`:     `back\\slash`,
		"two\nlines":     "two lines",
		`\"`:             `\\\"`,
	}
	for in, want := range cases {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginXMLEscapesPassword(t *testing.T) {
	for _, pass := range []string{"simple", `p<a>ss&"word'`, "</Password><Injected>", ""} {
		var env struct {
			Body struct {
				Login struct {
					Username string `xml:"Username"`
					Password string `xml:"Password"`
				} `xml:"SOAPLogin"`
			} `xml:"Body"`
		}
		doc := loginXML(pass)
		if err := xml.Unmarshal([]byte(doc), &env); err != nil {
			t.Fatalf("pass %q produced invalid XML: %v\n%s", pass, err, doc)
		}
		if env.Body.Login.Password != pass || env.Body.Login.Username != "admin" {
			t.Errorf("pass %q round-tripped as user=%q pass=%q", pass, env.Body.Login.Username, env.Body.Login.Password)
		}
		if strings.Contains(doc, "<Injected>") {
			t.Errorf("pass %q injected markup", pass)
		}
	}
}

func TestSoapCallXML(t *testing.T) {
	doc := soapCallXML(wlanService, "Get5GInfo")
	var env struct {
		Header struct {
			SessionID string `xml:"SessionID"`
		} `xml:"Header"`
		Body struct {
			Call struct {
				XMLName xml.Name
			} `xml:",any"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal([]byte(doc), &env); err != nil {
		t.Fatal(err)
	}
	if env.Header.SessionID != sessionHeader || env.Body.Call.XMLName.Local != "Get5GInfo" || env.Body.Call.XMLName.Space != wlanService {
		t.Errorf("envelope = %+v", env)
	}
}

func TestDisplayNameBandIsWiFi(t *testing.T) {
	names := []struct {
		d    Device
		want string
	}{
		{Device{Name: " Laptop ", DevType: "Computer", MAC: "AA"}, "Laptop"},
		{Device{Name: "Unknown", DevType: "Phone", MAC: "AA"}, "Phone"},
		{Device{Name: "unknown", MAC: "AA"}, "AA"},
		{Device{MAC: "AA"}, "AA"},
		{Device{}, ""},
	}
	for _, tc := range names {
		if got := displayName(tc.d); got != tc.want {
			t.Errorf("displayName(%+v) = %q, want %q", tc.d, got, tc.want)
		}
	}
	bands := []struct {
		ct, band string
		wifi     bool
	}{
		{"2.4G", "2.4 GHz", true},
		{"5G", "5 GHz", true},
		{"wired", "wired", false},
		{"-", "-", false},
		{"", "", false},
	}
	for _, tc := range bands {
		if got := band(tc.ct); got != tc.band {
			t.Errorf("band(%q) = %q, want %q", tc.ct, got, tc.band)
		}
		if got := isWiFi(tc.ct); got != tc.wifi {
			t.Errorf("isWiFi(%q) = %v, want %v", tc.ct, got, tc.wifi)
		}
	}
}

func TestCut(t *testing.T) {
	cases := []struct {
		in, before, after string
		found             bool
	}{
		{"Model=RBR50", "Model", "RBR50", true},
		{"Firmware=V2.7=x", "Firmware", "V2.7=x", true},
		{"=v", "", "v", true},
		{"novalue", "novalue", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		b, a, f := cut(tc.in, "=")
		if b != tc.before || a != tc.after || f != tc.found {
			t.Errorf("cut(%q) = %q,%q,%v want %q,%q,%v", tc.in, b, a, f, tc.before, tc.after, tc.found)
		}
	}
}

func TestSatKeyAndName(t *testing.T) {
	cases := []struct {
		s         SatelliteInfo
		key, name string
	}{
		{SatelliteInfo{MAC: "AA", Name: "Living", Model: "RBS50"}, "AA", "Living"},
		{SatelliteInfo{MAC: "AA", Model: "RBS50"}, "AA", "RBS50"},
		{SatelliteInfo{MAC: "AA"}, "AA", "AA"},
		{SatelliteInfo{Name: "Attic"}, "name:Attic", "Attic"},
		{SatelliteInfo{}, "name:", ""},
	}
	for _, tc := range cases {
		if got := satKey(tc.s); got != tc.key {
			t.Errorf("satKey(%+v) = %q, want %q", tc.s, got, tc.key)
		}
		if got := satName(tc.s); got != tc.name {
			t.Errorf("satName(%+v) = %q, want %q", tc.s, got, tc.name)
		}
	}
}

func TestSatMemoryOrderingAndUntrackable(t *testing.T) {
	var m satMemory
	a := SatelliteInfo{Name: "A", MAC: "AA", Firmware: "1"}
	b := SatelliteInfo{Name: "B", MAC: "BB"}
	byName := SatelliteInfo{Name: "C"}
	anon := SatelliteInfo{Model: "RBS50"} // no MAC and no name

	got, evs := m.merge([]SatelliteInfo{b, a, anon, byName}, true)
	if len(evs) != 0 {
		t.Errorf("first sighting must not emit events: %v", evs)
	}
	if len(got) != 3 || got[0].Name != "B" || got[1].Name != "A" || got[2].Name != "C" {
		t.Fatalf("want first-seen order B,A,C without anon: %+v", got)
	}
	for _, s := range got {
		if !s.Online {
			t.Errorf("%s should be online", s.Name)
		}
	}

	// Updated info replaces the remembered entry; order stays stable.
	a2 := a
	a2.Firmware = "2"
	got, _ = m.merge([]SatelliteInfo{a2, b, byName}, true)
	if got[1].Firmware != "2" || got[0].Name != "B" {
		t.Errorf("update lost: %+v", got)
	}

	// Failed poll with no memory returns an empty (non-nil) list.
	var empty satMemory
	got, evs = empty.merge(nil, false)
	if got == nil || len(got) != 0 || len(evs) != 0 {
		t.Errorf("empty memory failed poll = %#v %v", got, evs)
	}
}
