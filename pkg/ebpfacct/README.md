# pkg/ebpfacct — eBPF per-device traffic accounting

Kernel-side per-MAC byte counters attached to the LAN bridge's TC hooks.
The kernel counts bytes inline on the packet path: nothing to stall, no
daemon-side ledger to double-count on restart. Clients store reads the
map once per poll and carries totals across counter resets.

## Files

- `ebpf/counters.c` — the eBPF program (ingress counts bytes FROM the
  client per source MAC = upload; egress counts bytes TO the client per
  destination MAC = download; shared LRU hash map).
- `counters.bpf.o` — compiled bytecode, embedded in the binary via
  go:embed. Committed because the build host may lack clang.
- `ebpfacct.go` — loader (cilium/ebpf), TCX attach, map reader.

## Rebuilding the bytecode

Needs clang with BPF backend (clang ≥ 12) and libbpf headers:

    clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
      -c ebpf/counters.c -o counters.bpf.o

No BTF is required on the target kernel: the program only touches packet
data (the Ethernet header) and UAPI types, never kernel internals.

## Kernel requirements

- Linux 6.6+ for TCX attachment (tested on 6.12.87, OpenWrt)
- CONFIG_NET_CLS_ACT (clsact qdisc), bpffs mounted — both default on
  recent OpenWrt for rockchip/arm64 targets
- BTF is NOT required
