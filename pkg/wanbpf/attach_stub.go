//go:build !linux

package wanbpf

import "fmt"

// Attach is unavailable off Linux: XDP and TC hooks do not exist there.
// The application logs this and continues without the WAN collectors.
func Attach(wan, ifb, lan string) (*Collector, error) {
	return nil, fmt.Errorf("wanbpf: eBPF collectors are Linux-only (requested %q/%q/%q)", wan, ifb, lan)
}
