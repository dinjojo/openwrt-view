package health

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// dnsAnswer is how the fake resolver answers A queries for one name.
type dnsAnswer struct {
	ip    string // "" with nx=false = NOERROR with no records
	nx    bool   // NXDOMAIN
	delay time.Duration
}

// fakeDNS runs a minimal UDP DNS server: it answers A queries from the
// table, AAAA queries with an empty NOERROR, and unknown names with
// NXDOMAIN. Returns its address.
func fakeDNS(t *testing.T, zone map[string]dnsAnswer) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			go func() {
				if resp := dnsReply(req, zone); resp != nil {
					_, _ = pc.WriteTo(resp, addr)
				}
			}()
		}
	}()
	return pc.LocalAddr().String()
}

func dnsReply(req []byte, zone map[string]dnsAnswer) []byte {
	if len(req) < 12 {
		return nil
	}
	// Parse the single question.
	i := 12
	var labels []string
	for i < len(req) && req[i] != 0 {
		l := int(req[i])
		if i+1+l > len(req) {
			return nil
		}
		labels = append(labels, string(req[i+1:i+1+l]))
		i += 1 + l
	}
	i++ // zero label
	if i+4 > len(req) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(req[i:])
	question := req[12 : i+4]
	name := strings.ToLower(strings.Join(labels, "."))

	ans, known := zone[name]
	time.Sleep(ans.delay)

	rcode := uint16(0)
	var answer []byte
	switch {
	case !known || ans.nx:
		rcode = 3
	case qtype == 1 && ans.ip != "":
		ip := net.ParseIP(ans.ip).To4()
		answer = []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
		answer = append(answer, ip...)
	}
	resp := make([]byte, 12, 12+len(question)+len(answer))
	copy(resp[0:2], req[0:2])                          // ID
	binary.BigEndian.PutUint16(resp[2:], 0x8180|rcode) // QR RD RA + rcode
	binary.BigEndian.PutUint16(resp[4:], 1)            // QDCOUNT
	if answer != nil {
		binary.BigEndian.PutUint16(resp[6:], 1) // ANCOUNT
	}
	resp = append(resp, question...)
	return append(resp, answer...)
}

func TestEvalDNS(t *testing.T) {
	const okName, canary = "wikipedia.org", "updates.amazon.com"
	cases := []struct {
		name string
		zone map[string]dnsAnswer // nil = no server listening
		w    want
	}{
		{"resolver down", nil,
			want{state: StateCrit, value: "failing", contains: []string{"DNS is down"}}},
		{"real names fail", map[string]dnsAnswer{okName: {nx: true}},
			want{state: StateCrit, value: "failing"}},
		{"healthy, canary NXDOMAIN", map[string]dnsAnswer{okName: {ip: "198.35.26.96"}, canary: {nx: true}},
			want{state: StateOK, contains: []string{"blocking rules are enforced"}}},
		{"healthy, canary sinkholed to 0.0.0.0", map[string]dnsAnswer{okName: {ip: "198.35.26.96"}, canary: {ip: "0.0.0.0"}},
			want{state: StateOK}},
		{"healthy, canary sinkholed to 127.0.0.1", map[string]dnsAnswer{okName: {ip: "198.35.26.96"}, canary: {ip: "127.0.0.1"}},
			want{state: StateOK}},
		{"healthy, canary empty answer", map[string]dnsAnswer{okName: {ip: "198.35.26.96"}, canary: {}},
			want{state: StateOK}},
		{"filtering off", map[string]dnsAnswer{okName: {ip: "198.35.26.96"}, canary: {ip: "52.94.236.248"}},
			want{state: StateWarn, contains: []string{"blocking rules are not taking effect"}}},
		{"slow resolver", map[string]dnsAnswer{okName: {ip: "198.35.26.96", delay: 300 * time.Millisecond}, canary: {nx: true}},
			want{state: StateWarn, contains: []string{"slow enough"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var addr string
			if c.zone == nil {
				addr = closedUDPAddr(t)
			} else {
				addr = fakeDNS(t, c.zone)
			}
			got := evalDNS(newDNSProber(addr))
			checkCommon(t, got, "DNS & ad-blocking", c.w)
			if got.State != StateCrit && !strings.HasSuffix(got.Value, " ms") {
				t.Errorf("Value = %q, want a latency", got.Value)
			}
		})
	}
}

func closedUDPAddr(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}
