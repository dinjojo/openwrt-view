//go:build linux

package wanbpf

import "testing"

func TestDestPrefixString(t *testing.T) {
	// IPv4: 3.175.86.4 → saddr's bytes loaded little-endian, so octets
	// 1-3 sit in u64 bytes 0-2 after the host octet is masked off.
	k4 := destKey{Fam: 4, Prefix: 0x56AF03}
	if got := destPrefixString(k4); got != "3.175.86.0/24" {
		t.Errorf("v4 prefix = %q, want 3.175.86.0/24", got)
	}

	// IPv6: memcpy'd first 6 address bytes → u64 byte i = address byte i.
	// 2406:da12:0001:... → bytes 24 06 da 12 00 01.
	k6 := destKey{Fam: 6, Prefix: 0x01_00_12_da_06_24}
	if got := destPrefixString(k6); got != "2406:da12:0001::/48" {
		t.Errorf("v6 prefix = %q, want 2406:da12:0001::/48", got)
	}
}

func TestFoldDestRTTs(t *testing.T) {
	mac := uint64(0xb885_84b7_b98f) // packed big-endian low 48 bits
	mk := func(prefix uint64, fam uint32, count, sum, max uint64) destEntry {
		return destEntry{k: destKey{Mac: mac, Prefix: prefix, Fam: fam}, v: destRTT{Count: count, SumNs: sum, MaxNs: max}}
	}
	prev := map[destKey]destRTT{}
	entries := []destEntry{
		mk(0x56AF03, 4, 10, 10_000, 2_000), // busiest this window
		mk(0x080808, 4, 5, 500_000, 200_000),
		mk(0x01_00_12_da_06_24, 6, 3, 300, 150),
		mk(0x00_66_dc, 4, 4, 400, 100), // no new samples since prev
		mk(0x000000, 4, 0, 0, 0),       // empty entry dropped
	}
	prev[destKey{Mac: mac, Prefix: 0x00_66_dc, Fam: 4}] = destRTT{Count: 4, SumNs: 400}

	got := foldDestRTTs(entries, 2, prev)
	ds := got[macString(mac)]
	if len(ds) != 2 {
		t.Fatalf("kept %d dests, want 2", len(ds))
	}
	if ds[0].Prefix != "3.175.86.0/24" || ds[0].Count != 10 || ds[0].AvgNs != 1_000 || ds[0].MaxNs != 2_000 {
		t.Errorf("ds[0] = %+v", ds[0])
	}
	if ds[1].Count != 5 {
		t.Errorf("ds[1].Count = %d, want 5", ds[1].Count)
	}

	// Windowed diff: same counters again with no new samples → nothing.
	got = foldDestRTTs(entries, 2, prev)
	if len(got[macString(mac)]) != 0 {
		t.Errorf("second fold kept %d dests, want 0 (no new samples)", len(got[macString(mac)]))
	}
}
