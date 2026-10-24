package orbissn

import (
	"encoding/json"
	"testing"
)

const fixtureFull = `ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS ACAPS ERP    STATE MAXRATE(DOT11) HTCAPS   ASSOCTIME IEs   MODE                       PSMODE
98:3a:c3:12:34:56    1   36  780M   780M   36   31      47      0     0      65535 EPs  0     b      0     0              AWPSM    15:09:21  RSN WME IEEE80211_MODE_11AC_VHT80  0
f4:0f:24:ab:cd:ef    2   36  390M    6M    20   18      25      4     12     4021  EPs  0     b      0     0              AWPSM    00:03:07  RSN WME IEEE80211_MODE_11AC_VHT40  1
not-a-mac            3   36  1M      1M    1    1       1       0     0      0     EPs  0     b      0     0              AWPSM    00:00:01  RSN WME IEEE80211_MODE_11A         0
`

// Older firmware: no PSMODE column, "list stat" style header, garbage
// rate on one row, and a trailing shell prompt.
const fixtureNoPSMode = `wlanconfig: list stat
ADDR               AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE  TXSEQ  RXSEQ  CAPS ACAPS ERP    STATE MAXRATE(DOT11) HTCAPS   ASSOCTIME IEs   MODE
2c:f0:5d:00:11:22    1   11  144M   72M    40   33      44      0     0      65535 EPs  0     b      0     0              WPSM     1:02:03   WME   IEEE80211_MODE_11NG_HT20
aa:bb:cc:dd:ee:01    2   11  ?      ?      x    33      44      0     0      65535 EPs  0     b      0     0              WPSM     0:00:10   WME   IEEE80211_MODE_11NG_HT20
root@RBR50:/#
`

func ip(v int) *int { return &v }

func TestParseStations(t *testing.T) {
	cases := []struct {
		name string
		out  string
		band string
		want map[string]Station
	}{
		{"full header", fixtureFull, "5G", map[string]Station{
			"98:3A:C3:12:34:56": {DBm: ip(-59), MinDBm: ip(-64), MaxDBm: ip(-48), TxRate: ip(780), RxRate: ip(780),
				Mode: "11AC_VHT80", Assoc: "15:09:21", Band: "5G"},
			"F4:0F:24:AB:CD:EF": {DBm: ip(-75), MinDBm: ip(-77), MaxDBm: ip(-70), TxRate: ip(390), RxRate: ip(6),
				Mode: "11AC_VHT40", Assoc: "00:03:07", Band: "5G"},
		}},
		{"no PSMODE column", fixtureNoPSMode, "2.4G", map[string]Station{
			"2C:F0:5D:00:11:22": {DBm: ip(-55), MinDBm: ip(-62), MaxDBm: ip(-51), TxRate: ip(144), RxRate: ip(72),
				Mode: "11NG_HT20", Assoc: "1:02:03", Band: "2.4G"},
			"AA:BB:CC:DD:EE:01": {MinDBm: ip(-62), MaxDBm: ip(-51), Mode: "11NG_HT20", Assoc: "0:00:10", Band: "2.4G"},
		}},
		{"empty output", "", "5G", map[string]Station{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStations(tc.out, tc.band)
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(tc.want)
			if string(gj) != string(wj) {
				t.Errorf("got  %s\nwant %s", gj, wj)
			}
		})
	}
}
