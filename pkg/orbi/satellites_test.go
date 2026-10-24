package orbi

import "testing"

func TestSatMemoryOfflineAfterTwoMisses(t *testing.T) {
	sat := SatelliteInfo{Name: "RBS50", Model: "RBS50", MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.1.2",
		BackhaulConn: 1, BackhaulRSSI: -60, Online: true}
	var m satMemory

	steps := []struct {
		name       string
		latest     []SatelliteInfo
		ok         bool
		wantOnline bool
		wantEvents []satEvent
	}{
		{"first sighting", []SatelliteInfo{sat}, true, true, nil},
		{"one miss keeps it online", nil, true, true, nil},
		{"failed poll does not count", nil, false, true, nil},
		{"second miss marks offline", nil, true, false, []satEvent{{"RBS50", false}}},
		{"third miss stays quiet", nil, true, false, nil},
		{"returns", []SatelliteInfo{sat}, true, true, []satEvent{{"RBS50", true}}},
	}
	for _, s := range steps {
		got, evs := m.merge(s.latest, s.ok)
		if len(got) != 1 {
			t.Fatalf("%s: want 1 remembered satellite, got %d", s.name, len(got))
		}
		if got[0].Online != s.wantOnline {
			t.Errorf("%s: online=%v, want %v", s.name, got[0].Online, s.wantOnline)
		}
		if got[0].Name != "RBS50" || got[0].IP != "192.168.1.2" {
			t.Errorf("%s: lost identity fields: %+v", s.name, got[0])
		}
		if !got[0].Online && (got[0].BackhaulRSSI != 0 || got[0].BackhaulConn != 0) {
			t.Errorf("%s: offline satellite should have zeroed backhaul fields: %+v", s.name, got[0])
		}
		if len(evs) != len(s.wantEvents) {
			t.Fatalf("%s: events=%v, want %v", s.name, evs, s.wantEvents)
		}
		for i := range evs {
			if evs[i] != s.wantEvents[i] {
				t.Errorf("%s: event %d = %v, want %v", s.name, i, evs[i], s.wantEvents[i])
			}
		}
	}
}
