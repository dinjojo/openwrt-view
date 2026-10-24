package orbissn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const iwconfig5G = `ath1      IEEE 802.11ac  ESSID:"TestSSID"  
          Mode:Master  Frequency:5.18 GHz  Access Point: AA:BB:CC:00:00:0A   
          Bit Rate:866.7 Mb/s   Tx-Power=23 dBm   
          RTS thr:off   Fragment thr:off
          Encryption key:****-****-****-****-****-****-****-****   Security mode:restricted
          Power Management:off
          Link Quality=94/94  Signal level=-97 dBm  Noise level=-95 dBm
          Rx invalid nwid:13141  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:0   Missed beacon:0
`

const iwconfig24G = "ath0      IEEE 802.11ng  ESSID:\"TestSSID\"  \r\n" +
	"          Mode:Master  Frequency:2.462 GHz  Access Point: AA:BB:CC:00:00:0B   \r\n" +
	"          Link Quality=80/94  Signal level=-96 dBm  Noise level=-92 dBm\r\n" +
	"          Rx invalid nwid:7  Rx invalid crypt:3  Rx invalid frag:1\r\n"

func TestParseIwconfig(t *testing.T) {
	cases := []struct {
		name  string
		iface string
		out   string
		ok    bool
		want  RadioEnv
	}{
		{"5G radio", "ath1", iwconfig5G, true, RadioEnv{Iface: "ath1", Band: "5G", FreqGHz: 5.18, NoiseDBm: -95, Quality: 94, QualityMax: 94, NwidRejects: 13141}},
		{"2.4G radio with CRLF", "ath0", iwconfig24G, true, RadioEnv{Iface: "ath0", Band: "2.4G", FreqGHz: 2.462, NoiseDBm: -92, Quality: 80, QualityMax: 94, NwidRejects: 7, CryptRejects: 3, FragRejects: 1}},
		{"no such device", "ath2", "ath2      No such device\n", false, RadioEnv{}},
		{"down VAP without frequency", "ath2", "ath2      IEEE 802.11ac  ESSID:\"\"\n          Mode:Master  Access Point: Not-Associated\n          Link Quality=0/94  Signal level=-95 dBm  Noise level=-95 dBm\n", false, RadioEnv{}},
		{"missing noise", "ath1", "ath1 Frequency:5.18 GHz\n Link Quality=94/94\n", false, RadioEnv{}},
		{"empty", "ath1", "", false, RadioEnv{}},
	}
	for _, c := range cases {
		got, ok := parseIwconfig(c.iface, c.out)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v, want %v (%+v)", c.name, ok, c.ok, got)
		}
		if ok && got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

// fakeShell answers commands from a map; missing commands fail.
type fakeShell map[string]string

func (f fakeShell) Run(_ context.Context, cmd string) (string, error) {
	if out, ok := f[cmd]; ok {
		return out, nil
	}
	return "", errors.New("exit status 1")
}
func (f fakeShell) Close() error { return nil }

func TestCollectRadioEnv(t *testing.T) {
	sh := fakeShell{
		"wlanconfig ath1 list sta": strings.SplitN(fixtureFull, "\n", 2)[0] + "\n",
		"iwconfig ath0":            iwconfig24G,
		"iwconfig ath1":            iwconfig5G,
		"iwconfig ath2":            "ath2      No such device\n",
	}
	res, err := collect(context.Background(), sh)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.radioEnv) != 2 || res.radioEnv[0].Iface != "ath0" || res.radioEnv[1].Iface != "ath1" {
		t.Fatalf("radioEnv = %+v, want ath0 and ath1 only", res.radioEnv)
	}
}
