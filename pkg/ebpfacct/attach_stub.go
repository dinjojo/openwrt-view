//go:build !linux

package ebpfacct

import "fmt"

// Attach is unavailable off Linux: TC hooks do not exist there. The
// application logs this and continues with the fallback accounting source.
func Attach(iface string) (*Collector, error) {
	return nil, fmt.Errorf("ebpfacct: eBPF accounting is Linux-only (requested iface %q)", iface)
}
