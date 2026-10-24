// Package orbi polls a Netgear Orbi AP (here: an RBR50 running Voxel
// firmware in AP mode) for attached-device and reachability state.
//
// Device data comes from the Netgear SOAP API (/soap/server_sa/): a
// SOAPLogin with the plain admin password yields a JWT cookie that
// GetAttachDevice2 accepts. The SOAP session is independent of the web
// UI's single-admin-session lock, so polling never fights a browser.
// (Scraping /DEV_device_info.htm with basic auth was tried first: the
// Orbi's LoginMethod 2.0 only honours basic auth while *some* web
// session exists, and any other login kicks it out.)
//
// Reachability still comes from the unauthenticated /currentsetting.htm
// page, which works regardless of any session state.
package orbi

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dinjojo/openwrt-view/pkg/vm"
)

// Device is one entry of the Orbi's attached-device list.
type Device struct {
	MAC       string  `json:"mac"`
	IP        string  `json:"ip"`
	Name      string  `json:"name"`
	ConnType  string  `json:"contype"` // "wired", "2.4G", "5G" (or "-" for satellites)
	DevType   string  `json:"devtype"` // e.g. "Computer (Generic)"
	Model     string  `json:"model"`
	ConnOrbi  string  `json:"conn_orbi"` // MAC of the AP unit the client connects through
	Uprate    float64 `json:"uprate_mbps"`
	Downrate  float64 `json:"downrate_mbps"`
	Signal    int     `json:"signal"`         // 0-100 quality, wired clients report 100
	Linkspeed float64 `json:"linkspeed_mbps"` // Wi-Fi PHY rate in Mbit/s
	SSID      string  `json:"ssid"`           // SSID the client associated to
}

// RadioInfo is one band's radio state from the WLANConfiguration SOAP
// service (GetInfo / Get5GInfo), confirmed working on RBR50 Voxel.
type RadioInfo struct {
	Band    string `json:"band"`    // "2.4G" or "5G"
	Channel int    `json:"channel"` // current channel number
	Mode    string `json:"mode"`    // radio's link tier, e.g. "866Mbps"
	SSID    string `json:"ssid"`
}

// SatelliteInfo is one mesh unit from the GetAllSatellites SOAP call
// (confirmed working on RBR50 Voxel). BackhaulConn 0 with an IP usually
// means Ethernet backhaul; wireless backhaul reports RSSI.
type SatelliteInfo struct {
	Name         string `json:"name"`
	Model        string `json:"model"`
	MAC          string `json:"mac"`
	IP           string `json:"ip"`
	Hop          int    `json:"hop"`
	BackhaulConn int    `json:"backhaul_conn"` // 1 = wireless backhaul
	BackhaulRSSI int    `json:"backhaul_rssi"`
	Firmware     string `json:"firmware"`
	// Online is false for a satellite seen earlier (since process start)
	// that has been missing from two consecutive successful
	// GetAllSatellites polls. Offline entries keep their last known
	// name/model/IP/firmware/hop; BackhaulConn and BackhaulRSSI are zeroed
	// because a stale backhaul reading would be misleading.
	Online bool `json:"online"`
}

// State is the latest Orbi snapshot.
type State struct {
	At         time.Time       `json:"at"`
	Reachable  bool            `json:"reachable"`
	Busy       bool            `json:"busy"` // true when the device list could not be fetched
	Model      string          `json:"model"`
	Firmware   string          `json:"firmware"`
	APMode     bool            `json:"ap_mode"`
	Devices    []Device        `json:"devices"`
	Radios     []RadioInfo     `json:"radios"`     // empty when the radio query failed
	Satellites []SatelliteInfo `json:"satellites"` // every satellite seen since start; last known list when the query failed
}

// soapEnvelope is the GetAttachDevice2 response we parse.
type soapEnvelope struct {
	Body struct {
		Response struct {
			NewAttachDevice struct {
				Devices []soapDevice `xml:"Device"`
			} `xml:"NewAttachDevice"`
		} `xml:"GetAttachDevice2Response"`
	} `xml:"Body"`
}

// soapDevice mirrors one <Device> entry of the SOAP response.
type soapDevice struct {
	IP          string `xml:"IP"`
	Name        string `xml:"Name"`
	MAC         string `xml:"MAC"`
	ConnType    string `xml:"ConnectionType"`
	Signal      string `xml:"SignalStrength"`
	Linkspeed   string `xml:"Linkspeed"`
	SSID        string `xml:"SSID"`
	DeviceModel string `xml:"DeviceModel"`
	TypeName    string `xml:"DeviceTypeNameV2"`
	ConnAPMAC   string `xml:"ConnAPMAC"`
	Upload      string `xml:"Upload"`
	Download    string `xml:"Download"`
}

const (
	soapPath      = "/soap/server_sa/"
	loginAction   = "urn:NETGEAR-ROUTER:service:DeviceConfig:1#SOAPLogin"
	attachAction  = "urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAttachDevice2"
	wlanService   = "urn:NETGEAR-ROUTER:service:WLANConfiguration:1"
	deviceService = "urn:NETGEAR-ROUTER:service:DeviceInfo:1"
	sessionHeader = "A7D88AE69687E58D9A00" // fixed magic session id, as the Netgear app sends
)

// xmlEscaper escapes the five predefined XML entities for interpolation
// into the SOAP login envelope.
var xmlEscaper = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;",
)

func loginXML(pass string) string {
	// Password is interpolated into XML — escape it so special characters
	// (<, &, quotes) can't break the envelope.
	escaped := xmlEscaper.Replace(pass)
	return `<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Header><SessionID>` + sessionHeader + `</SessionID></SOAP-ENV:Header>
<SOAP-ENV:Body><M1:SOAPLogin xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceConfig:1">
<Username>admin</Username><Password>` + escaped + `</Password>
</M1:SOAPLogin></SOAP-ENV:Body></SOAP-ENV:Envelope>`
}

const attachXML = `<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Header><SessionID>` + sessionHeader + `</SessionID></SOAP-ENV:Header>
<SOAP-ENV:Body><M1:GetAttachDevice2 xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceInfo:1"></M1:GetAttachDevice2></SOAP-ENV:Body></SOAP-ENV:Envelope>`

// Poller refreshes the Orbi snapshot every minute.
type Poller struct {
	mu      sync.RWMutex
	url     string // e.g. http://192.168.1.100 (no trailing slash)
	pass    string
	cookie  string // jwt_local cookie from the last successful SOAP login
	vmc     *vm.Client
	client  *http.Client
	state   State
	seen    map[string]string // mac -> contype from the previous successful poll
	seenOK  bool              // false until the first device poll succeeded
	sats    satMemory         // satellites remembered across polls (poll goroutine only)
	onEvent func(kind, sev, msg string)
	nameFor func(mac string) string // friendly client names for events; may be nil
}

// New builds a poller. Empty url disables it (Snapshot reports Reachable
// false with a zero At — the health check then reports "not configured").
func New(url, user, pass string, onEvent func(kind, sev, msg string)) *Poller {
	return &Poller{
		url:  strings.TrimRight(url, "/"),
		pass: pass,
		// The Orbi's uhttpd mishandles reused connections (idle keep-alive
		// connections get stale auth); it answers Connection: close anyway.
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		},
		onEvent: onEvent,
	}
}

// SetEventHook registers the callback fired on Wi-Fi client join/leave.
func (p *Poller) SetEventHook(fn func(kind, sev, msg string)) { p.onEvent = fn }

// SetNameResolver installs a callback that resolves friendly client names
// (DHCP/static lease names, vendor cache) for event messages. The Orbi's
// own device list only reports raw MACs and generic types, so without it
// events read "Network (Generic)" for phones with randomised MACs.
func (p *Poller) SetNameResolver(fn func(mac string) string) { p.nameFor = fn }

// SetVMClient enables pushing Wi-Fi gauges into VictoriaMetrics.
func (p *Poller) SetVMClient(c *vm.Client) { p.vmc = c }

// Enabled reports whether the poller has a target to poll.
func (p *Poller) Enabled() bool { return p != nil && p.url != "" }

// Snapshot returns the latest known Orbi state.
func (p *Poller) Snapshot() State {
	if p == nil {
		return State{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// Run blocks, polling once a minute until ctx is done.
func (p *Poller) Run(ctx context.Context) {
	p.refresh() // first poll immediately
	t := time.NewTicker(60 * time.Second)
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

func (p *Poller) refresh() {
	st := State{At: time.Now(), Devices: []Device{}}

	// Reachability: no auth needed, works regardless of session state.
	raw, err := p.get(p.url+"/currentsetting.htm", nil)
	if err != nil {
		p.commit(st)
		return
	}
	st.Reachable = true
	// currentsetting.htm uses CR line endings; normalise both.
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r", "\n"), "\n") {
		k, v, ok := cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Model":
			st.Model = strings.TrimSpace(v)
		case "Firmware":
			st.Firmware = strings.TrimSpace(v)
		case "DeviceMode":
			st.APMode = strings.TrimSpace(v) == "1" // 1 = AP mode
		}
	}

	// Attached devices via SOAP. On failure keep the last device list and
	// flag it (Busy) instead of alerting — data is stale, not wrong.
	devs, err := p.soapDevices()
	if err != nil {
		st.Busy = true
		p.commit(st)
		return
	}
	st.Devices = devs
	st.Radios = p.soapRadios()
	sats, serr := p.soapSatellites()
	var satEvents []satEvent
	st.Satellites, satEvents = p.sats.merge(sats, serr == nil)
	p.commit(st)
	p.emitSatEvents(satEvents)
	p.diffEvents(devs)
	p.pushVM(devs, st.Radios)
}

// pushVM imports Wi-Fi gauges into VictoriaMetrics: client counts per
// band, per-AP client counts, radio channels, and per-client signal
// strength so client drill-downs can chart their own radio history.
// Called from the poll goroutine only.
func (p *Poller) pushVM(devs []Device, radios []RadioInfo) {
	if p.vmc == nil {
		return
	}
	var b24, b5, wired int
	apCount := map[string]int{} // AP-unit MAC -> clients served
	var b strings.Builder
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	for _, d := range devs {
		switch d.ConnType {
		case "2.4G":
			b24++
		case "5G":
			b5++
		default:
			wired++
			continue // wired clients have no radio story
		}
		apCount[d.ConnOrbi]++
		name := sanitizeLabel(d.Name)
		mac := sanitizeLabel(d.MAC)
		b.WriteString("orbi_client_signal{mac=\"" + mac + "\",name=\"" + name + "\",band=\"" + d.ConnType + "\"} " +
			strconv.Itoa(d.Signal) + " " + ts + "\n")
		b.WriteString("orbi_client_linkspeed{mac=\"" + mac + "\",name=\"" + name + "\",band=\"" + d.ConnType + "\"} " +
			strconv.FormatFloat(d.Linkspeed, 'f', -1, 64) + " " + ts + "\n")
	}
	b.WriteString("orbi_wifi_clients{band=\"2.4G\"} " + strconv.Itoa(b24) + " " + ts + "\n")
	b.WriteString("orbi_wifi_clients{band=\"5G\"} " + strconv.Itoa(b5) + " " + ts + "\n")
	b.WriteString("orbi_wired_clients " + strconv.Itoa(wired) + " " + ts + "\n")
	for apMac, n := range apCount {
		label := sanitizeLabel(p.apNameFor(devs, apMac))
		b.WriteString("orbi_ap_clients{ap=\"" + label + "\"} " + strconv.Itoa(n) + " " + ts + "\n")
	}
	for _, r := range radios {
		if r.Channel > 0 {
			b.WriteString("orbi_radio_channel{band=\"" + r.Band + "\"} " + strconv.Itoa(r.Channel) + " " + ts + "\n")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.vmc.Import(ctx, b.String()); err != nil {
		log.Printf("[orbi] VM import failed: %v", err)
	}
}

func sanitizeLabel(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "\"", "\\\"")
	v = strings.ReplaceAll(v, "\n", " ")
	return v
}

// soapLogin performs a SOAPLogin and stores the session cookie.
func (p *Poller) soapLogin() error {
	req, err := http.NewRequest("POST", p.url+soapPath, strings.NewReader(loginXML(p.pass)))
	if err != nil {
		return err
	}
	req.Header.Set("SOAPAction", loginAction)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "multipart/form-data")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := readAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "<ResponseCode>000") {
		return fmt.Errorf("orbi: SOAP login failed (%d)", resp.StatusCode)
	}
	ck := ""
	for _, c := range resp.Cookies() {
		if c.Name == "jwt_local" {
			ck = c.Name + "=" + c.Value
		}
	}
	if ck == "" {
		return fmt.Errorf("orbi: SOAP login returned no session cookie")
	}
	p.cookie = ck
	return nil
}

// soapPost runs one SOAP action against the Orbi, re-logging in once if
// the session cookie was rejected or expired. Returns the raw XML body.
func (p *Poller) soapPost(action, body string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if p.cookie == "" {
			if err := p.soapLogin(); err != nil {
				return "", err
			}
		}
		req, err := http.NewRequest("POST", p.url+soapPath, strings.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("SOAPAction", action)
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Content-Type", "multipart/form-data")
		req.Header.Set("Cookie", p.cookie)
		resp, err := p.client.Do(req)
		if err != nil {
			return "", err
		}
		raw, _ := readAll(resp.Body)
		resp.Body.Close()
		page := string(raw)
		// Session expired or invalid: the server answers 200 with
		// <ResponseCode>401</ResponseCode> (or an auth redirect page).
		if resp.StatusCode == http.StatusUnauthorized ||
			strings.Contains(page, "<ResponseCode>401") ||
			strings.Contains(page, "multi_login.html") {
			p.cookie = ""
			continue // re-login and retry once
		}
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("orbi: %s -> %d", action, resp.StatusCode)
		}
		return page, nil
	}
	return "", fmt.Errorf("orbi: %s unavailable after re-login", action)
}

// soapDevices fetches the attached-device list.
func (p *Poller) soapDevices() ([]Device, error) {
	body, err := p.soapPost(attachAction, attachXML)
	if err != nil {
		return nil, err
	}
	return parseDevices(body)
}

// soapCallXML wraps one action call under a service namespace.
func soapCallXML(ns, action string) string {
	return `<?xml version="1.0" encoding="utf-8" standalone="no"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Header><SessionID>` + sessionHeader + `</SessionID></SOAP-ENV:Header>
<SOAP-ENV:Body><M1:` + action + ` xmlns:M1="` + ns + `"></M1:` + action + `></SOAP-ENV:Body></SOAP-ENV:Envelope>`
}

// soapRadios reads both bands' radio state. Best-effort: on any failure
// the snapshot simply carries no radio info (the UI hides the channel).
func (p *Poller) soapRadios() []RadioInfo {
	var out []RadioInfo
	for _, spec := range []struct{ action, band string }{
		{"GetInfo", "2.4G"}, {"Get5GInfo", "5G"},
	} {
		raw, err := p.soapPost(wlanService+"#"+spec.action, soapCallXML(wlanService, spec.action))
		if err != nil {
			log.Printf("[orbi] radio %s query failed: %v", spec.band, err)
			continue
		}
		// Seek the action's response element inside the SOAP envelope
		// (the document root is the Envelope, so plain Unmarshal would
		// only ever see that element).
		var fields struct {
			Channel string `xml:"NewChannel"`
			Mode    string `xml:"NewWirelessMode"`
			SSID    string `xml:"NewSSID"`
		}
		found := false
		dec := xml.NewDecoder(strings.NewReader(raw))
		for {
			tok, terr := dec.Token()
			if terr != nil {
				break
			}
			if se, ok := tok.(xml.StartElement); ok && se.Name.Local == spec.action+"Response" {
				if derr := dec.DecodeElement(&fields, &se); derr == nil {
					found = true
				}
				break
			}
		}
		if !found || !strings.Contains(raw, "<ResponseCode>000") {
			continue
		}
		out = append(out, RadioInfo{
			Band:    spec.band,
			Channel: atoiDefault(fields.Channel, 0),
			Mode:    strings.TrimSpace(fields.Mode),
			SSID:    strings.TrimSpace(fields.SSID),
		})
	}
	return out
}

func (p *Poller) get(url string, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("orbi: %s -> %d", url, resp.StatusCode)
	}
	return readAll(resp.Body)
}

func readAll(body io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 32*1024)
	b := make([]byte, 16*1024)
	for {
		n, err := body.Read(b)
		buf = append(buf, b[:n]...)
		if err != nil {
			break // io.EOF ends the read
		}
	}
	return buf, nil
}

// parseDevices extracts the device entries from the SOAP XML.
func parseDevices(body string) ([]Device, error) {
	var env soapEnvelope
	if err := xml.Unmarshal([]byte(body), &env); err != nil {
		return nil, fmt.Errorf("orbi: parse device list: %w", err)
	}
	raw := env.Body.Response.NewAttachDevice.Devices
	devs := make([]Device, 0, len(raw))
	for _, d := range raw {
		if d.MAC == "" {
			continue
		}
		devs = append(devs, Device{
			MAC:       strings.ToUpper(d.MAC),
			IP:        strings.TrimSpace(d.IP),
			Name:      strings.TrimSpace(d.Name),
			ConnType:  normalizeConn(d.ConnType),
			DevType:   strings.TrimSpace(d.TypeName),
			Model:     strings.TrimSpace(d.DeviceModel),
			ConnOrbi:  strings.ToUpper(strings.TrimSpace(d.ConnAPMAC)),
			Uprate:    parseRate(d.Upload),
			Downrate:  parseRate(d.Download),
			Signal:    atoiDefault(d.Signal, 0),
			Linkspeed: parseRate(d.Linkspeed),
			SSID:      strings.TrimSpace(d.SSID),
		})
	}
	return devs, nil
}

// normalizeConn maps the SOAP band names ("5GHz", "2.4GHz") to the short
// forms the UI and health checks use ("5G", "2.4G").
func normalizeConn(ct string) string {
	switch strings.TrimSpace(ct) {
	case "5GHz":
		return "5G"
	case "2.4GHz":
		return "2.4G"
	default:
		return strings.TrimSpace(ct)
	}
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func parseRate(s string) float64 {
	var f float64
	_, _ = fmt.Sscanf(strings.TrimSpace(s), "%f", &f)
	return f
}

// diffEvents emits join/leave/move events for Wi-Fi clients (wired joins
// are ordinary DHCP/bridge events; Wi-Fi associations are the AP's story).
// Moves cover roaming: a client switching AP unit (RBR50 ↔ RBS50) or
// band (5 GHz ↔ 2.4 GHz) — the mesh working as designed, but worth a line.
func (p *Poller) diffEvents(devs []Device) {
	if p.onEvent == nil {
		return
	}
	p.mu.Lock()
	prev := p.seen
	now := make(map[string]string, len(devs))
	for _, d := range devs {
		now[d.MAC] = d.ConnType + "|" + d.ConnOrbi
	}
	first := !p.seenOK
	p.seen, p.seenOK = now, true
	p.mu.Unlock()

	if first {
		return // baseline: no event storm at startup
	}
	for _, d := range devs {
		if !isWiFi(d.ConnType) {
			continue
		}
		prevKey := prev[d.MAC]
		if prevKey == "" {
			p.onEvent("orbi", "info", "Wi-Fi client joined: "+p.clientName(d)+" ("+strings.ToLower(d.MAC)+") on "+band(d.ConnType))
			continue
		}
		prevCT, prevAP, _ := strings.Cut(prevKey, "|")
		if prevCT != d.ConnType {
			p.onEvent("orbi", "info", p.clientName(d)+" ("+strings.ToLower(d.MAC)+") moved from "+band(prevCT)+" to "+band(d.ConnType))
		}
		if prevAP != d.ConnOrbi {
			p.onEvent("orbi", "info", p.clientName(d)+" ("+strings.ToLower(d.MAC)+") roamed from "+p.apNameFor(devs, prevAP)+" to "+p.apNameFor(devs, d.ConnOrbi))
		}
	}
	for mac, key := range prev {
		ct, _, _ := strings.Cut(key, "|")
		if isWiFi(ct) && now[mac] == "" {
			p.onEvent("orbi", "info", "Wi-Fi client left: "+p.leftLabel(mac)+" (was on "+band(ct)+")")
		}
	}
}

// soapSatellites reads the mesh unit list (GetAllSatellites). Best-effort:
// on failure it returns an error and the caller keeps the remembered list.
func (p *Poller) soapSatellites() ([]SatelliteInfo, error) {
	raw, err := p.soapPost(deviceService+"#GetAllSatellites", soapCallXML(deviceService, "GetAllSatellites"))
	if err != nil {
		log.Printf("[orbi] satellite query failed: %v", err)
		return nil, err
	}
	if !strings.Contains(raw, "<ResponseCode>000") {
		return nil, fmt.Errorf("orbi: GetAllSatellites returned a non-zero response code")
	}
	// Seek each <satellite> element inside the envelope and decode it.
	var out []SatelliteInfo
	dec := xml.NewDecoder(strings.NewReader(raw))
	for {
		tok, terr := dec.Token()
		if terr != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "satellite" {
			continue
		}
		var fields struct {
			SignalStrength string `xml:"SignalStrength"`
			Hop            string `xml:"Hop"`
			BHConnStatus   string `xml:"BHConnStatus"`
			IP             string `xml:"IP"`
			DeviceName     string `xml:"DeviceName"`
			MAC            string `xml:"MAC"`
			ModelName      string `xml:"ModelName"`
			FWVersion      string `xml:"FWVersion"`
		}
		if derr := dec.DecodeElement(&fields, &se); derr != nil {
			continue
		}
		out = append(out, SatelliteInfo{
			Name:         strings.TrimSpace(fields.DeviceName),
			Model:        strings.TrimSpace(fields.ModelName),
			MAC:          strings.ToUpper(strings.TrimSpace(fields.MAC)),
			IP:           strings.TrimSpace(fields.IP),
			Hop:          atoiDefault(fields.Hop, 0),
			BackhaulConn: atoiDefault(fields.BHConnStatus, 0),
			// SignalStrength is the backhaul RSSI; -100 is the placeholder
			// the firmware reports when the backhaul is not wireless.
			BackhaulRSSI: atoiDefault(fields.SignalStrength, 0),
			Firmware:     strings.TrimSpace(fields.FWVersion),
			Online:       true,
		})
	}
	return out, nil
}

// satMissLimit is how many consecutive successful satellite polls a
// satellite must be absent from before it is reported offline — one
// empty or partial answer must not flap the UI or the event feed.
const satMissLimit = 2

// satMemory remembers every satellite seen since process start, keyed by
// MAC, so a powered-off unit stays visible as offline instead of vanishing.
type satMemory struct {
	order  []string                 // keys in first-seen order (stable UI ordering)
	byKey  map[string]SatelliteInfo // last known info
	missed map[string]int           // consecutive successful polls the satellite was absent from
}

type satEvent struct {
	name   string
	online bool
}

func satKey(s SatelliteInfo) string {
	if s.MAC != "" {
		return s.MAC
	}
	return "name:" + s.Name
}

func satName(s SatelliteInfo) string {
	switch {
	case s.Name != "":
		return s.Name
	case s.Model != "":
		return s.Model
	default:
		return s.MAC
	}
}

// merge folds one poll result into the memory and returns the full list
// to report plus any online/offline transitions. ok=false means the query
// failed: the remembered list is returned unchanged and no miss counters
// advance (a failed poll is not evidence the satellite is gone).
func (m *satMemory) merge(latest []SatelliteInfo, ok bool) ([]SatelliteInfo, []satEvent) {
	if m.byKey == nil {
		m.byKey = map[string]SatelliteInfo{}
		m.missed = map[string]int{}
	}
	var evs []satEvent
	if ok {
		present := make(map[string]bool, len(latest))
		for _, s := range latest {
			k := satKey(s)
			if k == "name:" {
				continue // neither MAC nor name: cannot be tracked
			}
			present[k] = true
			prev, known := m.byKey[k]
			if !known {
				m.order = append(m.order, k)
			} else if !prev.Online {
				evs = append(evs, satEvent{name: satName(s), online: true})
			}
			s.Online = true
			m.byKey[k] = s
			m.missed[k] = 0
		}
		for _, k := range m.order {
			if present[k] {
				continue
			}
			m.missed[k]++
			s := m.byKey[k]
			if s.Online && m.missed[k] >= satMissLimit {
				s.Online = false
				s.BackhaulConn, s.BackhaulRSSI = 0, 0
				m.byKey[k] = s
				evs = append(evs, satEvent{name: satName(s), online: false})
			}
		}
	}
	out := make([]SatelliteInfo, 0, len(m.order))
	for _, k := range m.order {
		out = append(out, m.byKey[k])
	}
	return out, evs
}

func (p *Poller) emitSatEvents(evs []satEvent) {
	if p.onEvent == nil {
		return
	}
	for _, e := range evs {
		if e.online {
			p.onEvent("satellite", "info", e.name+" is back online")
		} else {
			p.onEvent("satellite", "warn", e.name+" went offline")
		}
	}
}

// apNameFor resolves one AP-unit MAC to a friendly name. Satellites list
// themselves in the device table with ConnectionType "-"; the Orbi router
// itself never does, so it falls back to the unit's model name.
func (p *Poller) apNameFor(devs []Device, apMac string) string {
	if apMac == "" {
		return "unknown"
	}
	// In AP mode the attached-device list normally does not contain the mesh
	// units themselves, so resolve satellites from GetAllSatellites first;
	// without this every AP falls back to the router model ("RBR50") and a
	// RBS50→RBR50 roam reads as "roamed from RBR50 to RBR50".
	p.mu.RLock()
	for _, s := range p.state.Satellites {
		if s.Model != "" && strings.EqualFold(s.MAC, apMac) {
			p.mu.RUnlock()
			return s.Model
		}
	}
	p.mu.RUnlock()
	for _, d := range devs {
		if d.MAC == apMac && d.ConnType == "-" {
			return displayName(d)
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.state.Model != "" {
		return p.state.Model
	}
	return "router"
}

func (p *Poller) commit(st State) {
	p.mu.Lock()
	p.state = st
	p.mu.Unlock()
}

func isWiFi(ct string) bool { return ct == "2.4G" || ct == "5G" }

func band(ct string) string {
	if ct == "2.4G" {
		return "2.4 GHz"
	}
	if ct == "5G" {
		return "5 GHz"
	}
	return ct
}

// clientName picks the friendliest label for a client device in events: the
// panel's resolved name (DHCP/static lease, /etc/hosts, vendor cache) when
// the resolver is wired and knows the MAC, else the Orbi's own display name.
func (p *Poller) clientName(d Device) string {
	if p.nameFor != nil {
		n := strings.TrimSpace(p.nameFor(strings.ToLower(d.MAC)))
		if n != "" && !strings.EqualFold(n, d.MAC) && !strings.HasPrefix(strings.ToLower(n), "device-") {
			return n
		}
	}
	return displayName(d)
}

// leftLabel labels a Wi-Fi client that has already left the mesh. Only the
// MAC survives in the previous-state map, so resolve it through the panel's
// name sources and keep the MAC visible for matching; unknown MACs fall back
// to the lowercase MAC, consistent with the other event messages.
func (p *Poller) leftLabel(mac string) string {
	low := strings.ToLower(mac)
	if p.nameFor != nil {
		if n := strings.TrimSpace(p.nameFor(low)); n != "" && !strings.EqualFold(n, low) && !strings.HasPrefix(strings.ToLower(n), "device-") {
			return n + " (" + low + ")"
		}
	}
	return low
}

func displayName(d Device) string {
	n := strings.TrimSpace(d.Name)
	if n == "" || strings.EqualFold(n, "Unknown") {
		n = d.DevType
	}
	if n == "" {
		n = d.MAC
	}
	return n
}

func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
