// WAN-side eBPF collectors for openwrt-view. Seven programs, one object:
//
//   xdp_wan_gate    (XDP, WAN ingress)  packet/byte totals, spoof-source
//                   observation, and a per-source SYN rate limit (port-scan
//                   dampening) — runs before the kernel builds an skb.
//   stamp_dl        (tc, WAN ingress)   timestamp inbound download flows
//                   into an LRU keyed by the remote endpoint; the arrival
//                   half of the download queue-delay measurement.
//   collect_dl      (tc, LAN egress)    the same flow departs to the client
//                   here, AFTER the CAKE ingress qdisc has dequeued it on
//                   the IFB mirror; the difference of the two stamps is
//                   the real queue wait. (Redirected skbs skip tc on the
//                   IFB itself, so the departure must be observed on the
//                   LAN bridge.)
//   stamp_ts        (tc, LAN ingress)   remember each client's latest TCP
//                   TSval per server endpoint, with the client's MAC.
//   collect_rtt     (tc, WAN ingress)   the server's ACK echoes that TSval
//                   back; matching echo → per-client round-trip sample,
//                   no probes.
//   local_from_lan  (tc, LAN ingress)   bytes from clients into router
//                   services, keyed by the destination port.
//   local_to_lan    (tc, LAN egress)    bytes from router services back to
//                   clients, keyed by the source port.
//
// Every tc program returns TCX_NEXT (-1) so multiple collectors chain
// on the same hook and the classic clsact filters (the SQM redirect)
// still run after us. TC_ACT_PIPE (3) ends the TCX chain.
//
// The router's WAN is PPPoE: frames on the WAN device are
// Ethernet / PPPoE / PPP / IP, so the parsers handle that chain. On the
// LAN bridge frames are plain Ethernet. Flow keys use the IP-layer
// tuple only (no length): the same packet appears once in PPPoE frames
// and once decapsulated, and CAKE's split-GSO means arrival and
// departure skbs differ in size. No kernel-internal types are touched,
// so no BTF is required on the target kernel.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// TCX chain-continue. TC_ACT_PIPE (3) ends the chain on kernel 6.8+;
// only TCX_NEXT (-1) runs the next program and then the clsact filters.
#define TCX_NEXT -1
#include <bpf/bpf_endian.h>

#define PPP_IP    0x0021
#define PPP_IPV6  0x0057
#define SYN_LIMIT 64       // SYNs per source per window before drops begin
#define SYN_WINDOW_NS (10ULL * 1000 * 1000 * 1000)
#define STALE_NS  (30ULL * 1000 * 1000 * 1000) // arrival stamps older than this are key reuse, not delay

// ── WAN gate (XDP) ──────────────────────────────────────────────────────

struct wan_stats {
    __u64 pkts;
    __u64 bytes;
    __u64 syn_pass;
    __u64 scan_drop;
    __u64 spoof_seen;   // bogon-source packets, counted (not dropped)
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wan_stats);
} xdp_stats SEC(".maps");

struct syn_state {
    __u64 win_start;    // ktime of the current window's first SYN
    __u32 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);              // source IPv4
    __type(value, struct syn_state);
} syn_windows SEC(".maps");

// Parse Ethernet [+ VLAN] [+ PPPoE/PPP] for XDP and hand back the L4
// protocol byte and the source IPv4. Returns 0 when the frame carries
// an IP payload.
static __inline int xdp_parse_l3(struct xdp_md *ctx, __u8 *l4proto,
                                 __u32 *src4, void **tcp_hdr) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return -1;
    __u16 etype = eth->h_proto;
    void *p = (void *)(eth + 1);
    if (etype == bpf_htons(ETH_P_8021Q)) {
        if (p + 4 > end)
            return -1;
        etype = *(__u16 *)(p + 2);
        p += 4;
    }
    if (etype == bpf_htons(ETH_P_PPP_SES)) {
        // PPPoE session header (6 bytes) then PPP protocol (2 bytes).
        if (p + 8 > end)
            return -1;
        if (((__u8 *)p)[1] != 0x00)   // code != Session-data
            return -1;
        __u16 ppp;
        __builtin_memcpy(&ppp, p + 6, 2);
        if (ppp == bpf_htons(PPP_IP))
            etype = bpf_htons(ETH_P_IP);
        else if (ppp == bpf_htons(PPP_IPV6))
            etype = bpf_htons(ETH_P_IPV6);
        else
            return -1;
        p += 8;
    }
    if (etype == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = p;
        if ((void *)(ip + 1) > end)
            return -1;
        if (ip->version != 4)
            return -1;
        __u32 ihl = (__u32)ip->ihl * 4;
        if (ihl < 20 || p + ihl > end)
            return -1;
        *l4proto = ip->protocol;
        *src4 = ip->saddr;
        void *l4 = p + ihl;
        if (ip->protocol == IPPROTO_TCP) {
            if (l4 + 20 > end)
                return -1;
            *tcp_hdr = l4;
        }
        return 0;
    }
    if (etype == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = p;
        if ((void *)(ip6 + 1) > end)
            return -1;
        if (ip6->version != 6)
            return -1;
        *l4proto = ip6->nexthdr;
        if (ip6->nexthdr == IPPROTO_TCP) {
            void *l4 = (void *)(ip6 + 1);
            if (l4 + 20 > end)
                return -1;
            *tcp_hdr = l4;
        }
        return 0;   // v6 sources are not spoof-candidates here
    }
    return -1;
}

SEC("xdp")
int xdp_wan_gate(struct xdp_md *ctx) {
    __u32 zero = 0;
    struct wan_stats *st = bpf_map_lookup_elem(&xdp_stats, &zero);
    if (!st)
        return XDP_PASS;
    __u64 len = (__u64)(ctx->data_end - ctx->data);

    __u8 l4proto = 0;
    __u32 src4 = 0;
    void *tcp = 0;
    if (xdp_parse_l3(ctx, &l4proto, &src4, &tcp) != 0)
        return XDP_PASS;

    st->pkts++;
    st->bytes += len;

    // Spoofed-source observation (count only): bogon sources on the WAN
    // are almost always junk, but dropping needs the peer allowlist, so
    // v1 only watches.
    __u32 a = src4 & 0xff;
    __u32 b = (src4 >> 8) & 0xff;
    if (a == 10 || a == 127 || a == 0 ||
        (a == 172 && (b & 0xf0) == 16) ||
        (a == 192 && b == 168) ||
        (a == 169 && b == 254) || a >= 224)
        st->spoof_seen++;

    // Port-scan dampening: sources opening SYN after SYN in a short
    // window have their further SYNs dropped (non-SYN and established
    // traffic always passes).
    if (l4proto == IPPROTO_TCP && tcp) {
        __u8 *f = (__u8 *)tcp + 13;
        if ((*f & 0x12) == 0x02) {   // SYN without ACK
            __u64 now = bpf_ktime_get_ns();
            struct syn_state *s = bpf_map_lookup_elem(&syn_windows, &src4);
            if (!s || now - s->win_start > SYN_WINDOW_NS) {
                struct syn_state fresh = { .win_start = now, .count = 1 };
                bpf_map_update_elem(&syn_windows, &src4, &fresh, BPF_ANY);
                st->syn_pass++;
                return XDP_PASS;
            }
            s->count++;
            if (s->count > SYN_LIMIT) {
                st->scan_drop++;
                return XDP_DROP;
            }
            st->syn_pass++;
        }
    }
    return XDP_PASS;
}

// ── Download queue delay (WAN ingress arrival + LAN egress departure) ──

struct flow_key {
    __u32 saddr;   // remote (server) address
    __u16 sport;   // remote port, 0 for non-TCP/UDP
    __u16 proto;
    __u32 pad;
};

struct flow_key6 {
    __u8 saddr[16];
    __u16 sport;
    __u16 proto;
    __u16 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, __u64);            // latest arrival ktime
} dl_arrive4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key6);
    __type(value, __u64);
} dl_arrive6 SEC(".maps");

struct q_delay {
    __u64 hist[32];   // bucket i ≈ 2^i microseconds (log2 of delay in µs)
    __u64 count;
    __u64 sum_ns;
    __u64 max_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct q_delay);
} q_delay SEC(".maps");

// Parse tc L2 (Ethernet [+ VLAN] [+ PPPoE]) into the flow keys. The
// key is the REMOTE endpoint only (source address and, for TCP/UDP,
// source port). NAT rewrites the local side between the WAN and LAN
// legs, but the server's address and port survive untouched, so the
// arrival stamp (WAN ingress) and the departure (LAN egress) share the
// same key. dst_is_remote selects which side of the packet names the
// remote endpoint: 0 for WAN-facing legs (server → client, remote is
// the source) and 1 for the client's outbound leg (remote is the
// destination). l4out receives the L4 header pointer when ports were
// parsed. Returns the L3 protocol family (4, 6, or 0) on success.
static __inline int tc_parse_l3(struct __sk_buff *skb, struct flow_key *k4,
                                struct flow_key6 *k6, __u8 *has_ports,
                                int dst_is_remote, void **l4out) {
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return 0;
    __u16 etype = eth->h_proto;
    void *p = (void *)(eth + 1);
    if (etype == bpf_htons(ETH_P_8021Q)) {
        if (p + 4 > end)
            return 0;
        etype = *(__u16 *)(p + 2);
        p += 4;
    }
    if (etype == bpf_htons(ETH_P_PPP_SES)) {
        if (p + 8 > end)
            return 0;
        if (((__u8 *)p)[1] != 0x00)
            return 0;
        __u16 ppp;
        __builtin_memcpy(&ppp, p + 6, 2);
        if (ppp == bpf_htons(PPP_IP))
            etype = bpf_htons(ETH_P_IP);
        else if (ppp == bpf_htons(PPP_IPV6))
            etype = bpf_htons(ETH_P_IPV6);
        else
            return 0;
        p += 8;
    }
    if (etype == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = p;
        if ((void *)(ip + 1) > end)
            return 0;
        __u32 ihl = (__u32)ip->ihl * 4;
        if (ihl < 20 || p + ihl > end)
            return 0;
        if (ip->frag_off & bpf_htons(0x1fff))
            return 0;   // non-first fragment: no L4 header to parse
        k4->proto = ip->protocol;
        k4->saddr = dst_is_remote ? ip->daddr : ip->saddr;
        void *l4 = p + ihl;
        if (ip->protocol == IPPROTO_TCP && l4 + 20 <= end) {
            struct tcphdr *t = l4;
            __u16 src = t->source, dst = t->dest;   // fixed-offset reads
            if (l4out)
                *l4out = l4;   // bounds-checked: a TCP header fits
            k4->sport = dst_is_remote ? dst : src;
            *has_ports = 1;
        } else if (ip->protocol == IPPROTO_UDP && l4 + 8 <= end) {
            __u16 *u = l4;
            __u16 src = u[0], dst = u[1];
            k4->sport = dst_is_remote ? dst : src;
            *has_ports = 1;
        }
        return 4;
    }
    if (etype == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = p;
        if ((void *)(ip6 + 1) > end)
            return 0;
        void *l4 = (void *)(ip6 + 1);
        __u8 nh = ip6->nexthdr;
        if (nh == IPPROTO_TCP) {
            struct tcphdr *t = l4;
            if ((void *)(t + 1) > end)
                return 0;   // truncated: a zero-saddr key would pollute dl_arrive6
            __u16 src = t->source, dst = t->dest;   // fixed-offset reads
            if (l4out)
                *l4out = l4;   // bounds-checked: a TCP header fits
            k6->sport = dst_is_remote ? dst : src;
            *has_ports = 1;
        } else if (nh == IPPROTO_UDP) {
            if (l4 + 8 > end)
                return 0;   // truncated: a zero-saddr key would pollute dl_arrive6
            __u16 *u = l4;
            __u16 src = u[0], dst = u[1];
            k6->sport = dst_is_remote ? dst : src;
            *has_ports = 1;
        }
        __builtin_memcpy(k6->saddr, dst_is_remote ? ip6->daddr.s6_addr : ip6->saddr.s6_addr, 16);
        k6->proto = nh;
        return 6;
    }
    return 0;
}

SEC("tc/ingress")
int stamp_dl(struct __sk_buff *skb) {
    struct flow_key k4 = {};
    struct flow_key6 k6 = {};
    __u8 has_ports = 0;
    __u8 fam = (__u8)tc_parse_l3(skb, &k4, &k6, &has_ports, 0, NULL);
    __u64 now = bpf_ktime_get_ns();
    if (fam == 4)
        bpf_map_update_elem(&dl_arrive4, &k4, &now, BPF_ANY);
    else if (fam == 6)
        bpf_map_update_elem(&dl_arrive6, &k6, &now, BPF_ANY);
    return TCX_NEXT;
}

SEC("tc/ingress")
int collect_dl(struct __sk_buff *skb) {
    struct flow_key k4 = {};
    struct flow_key6 k6 = {};
    __u8 has_ports = 0;
    __u8 fam = (__u8)tc_parse_l3(skb, &k4, &k6, &has_ports, 0, NULL);
    __u64 now = bpf_ktime_get_ns();
    __u64 *t0 = fam == 4 ? bpf_map_lookup_elem(&dl_arrive4, &k4)
              : fam == 6 ? bpf_map_lookup_elem(&dl_arrive6, &k6) : 0;
    if (!t0)
        return TCX_NEXT;
    __u64 delta = now - *t0;
    // The arrival stamp is only meaningful for a few seconds; anything
    // larger is a stale entry (flow seen once), not a queue delay.
    if (delta > STALE_NS)
        return TCX_NEXT;
    __u32 zero = 0;
    struct q_delay *q = bpf_map_lookup_elem(&q_delay, &zero);
    if (!q)
        return TCX_NEXT;
    __u64 us = delta >> 10;
    __u32 idx = 0;
    for (__u32 v = (__u32)us; v > 1 && idx < 31; v >>= 1)
        idx++;
    q->hist[idx]++;
    q->count++;
    q->sum_ns += delta;
    if (delta > q->max_ns)
        q->max_ns = delta;
    return TCX_NEXT;
}

// ── Passive per-device RTT from TCP timestamps ──────────────────────────
//
// Every modern TCP stack stamps its segments with a TSval and the peer
// echoes that value back in TSecver. Both sides are visible to tc
// hooks on this router, so the kernel itself can time the round trip
// of each client's connections with no probes:
//
//   stamp_ts    (tc, LAN ingress)  the client's segment carries TSval;
//                                  remember (server endpoint → TSval,
//                                  wall time, client MAC)
//   collect_rtt (tc, WAN ingress)  the server's ACK echoes TSecver;
//                                  when it matches the remembered
//                                  TSval, RTT = now − that wall time
//
// Both hooks run before netfilter, so the server endpoint looks the
// same on both legs (NAT rewrites only the local side) — the same
// property the queue-delay keys rely on. The RTT lands in a per-client
// MAC histogram. Delayed ACKs make the peer echo an older TSval; those
// echoes simply fail the match and are skipped, so the samples skew
// toward interactive request/response traffic — the traffic where RTT
// is actually felt.

// mac_key packs a MAC big-endian in the low 48 bits so keys print
// naturally (same encoding as the ebpfacct counters).
static __inline __u64 mac_key(const unsigned char *mac) {
    return ((__u64)mac[0] << 40) | ((__u64)mac[1] << 32) | ((__u64)mac[2] << 24) |
           ((__u64)mac[3] << 16) | ((__u64)mac[4] << 8) | (__u64)mac[5];
}

struct ts_track {
    __u32 tsval;   // client's latest TSval on this flow
    __u32 pad;
    __u64 ktime;   // when that TSval left the LAN
    __u64 mac;     // owning client, mac_key encoding
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);    // remote (server) endpoint
    __type(value, struct ts_track);
} ts_track4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key6);
    __type(value, struct ts_track);
} ts_track6 SEC(".maps");

// Per-client RTT accumulators, same shape as the queue-delay record.
// LRU so one spoofed/varying client set cannot exhaust the table and
// freeze out real clients; userspace resyncs when counters reset.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);              // client MAC, mac_key encoding
    __type(value, struct q_delay);
} srtt_hist SEC(".maps");

// tcp_tsopt scans the TCP options for the timestamp option (kind 8).
// Returns 1 with tsval/tsecver filled, 0 if absent or unparseable. The
// caller has proven a full 20-byte TCP header fits. The scan is a
// fully unrolled byte state machine: after unrolling, every packet
// read is at a compile-time constant offset with its own end-relative
// bounds check, which is the only shape the verifier accepts without
// fighting the compiler's loop transforms. Options are at most 40
// bytes, so 40 steps cover them.
static __inline int tcp_tsopt(const struct tcphdr *t, void *end,
                              __u32 *tsval_out, __u32 *tsecver_out) {
    __u32 doff = ((const __u8 *)t)[12] >> 4;   // header length in words
    __u32 opts_end = doff << 2;
    if (opts_end < 20 || opts_end > 60)
        return 0;
    __u32 tsval = 0, tsecver = 0;
    __u32 st = 0;    // 0 expect kind, 1 expect len, 2..9 inside TS, 10 skip
    __u32 kind = 0, rem = 0;
    #pragma unroll
    for (int i = 20; i < 60; i++) {
        if (i >= opts_end)
            break;                       // past declared options: payload
        if ((const void *)t + i + 1 > end)
            break;
        const __u8 b = ((const __u8 *)t)[i];
        if (st == 0) {
            if (b == 0)
                break;                       // end of options
            if (b == 1)
                continue;                    // NOP
            kind = b;
            st = 1;
        } else if (st == 1) {
            if (b < 2)
                break;                       // malformed
            if (kind == 8 && b != 10)
                break;                       // TS option with wrong length
            if (kind == 8) {
                st = 2;                      // 8 TS data bytes follow
            } else {
                rem = b - 2;                 // bytes of a non-TS option
                st = rem ? 10 : 0;
            }
        } else if (st >= 2 && st <= 9) {
            if (st < 6)
                tsval |= (__u32)b << (8 * (5 - st));
            else
                tsecver |= (__u32)b << (8 * (9 - st));
            st++;
            if (st == 10) {
                *tsval_out = tsval;
                *tsecver_out = tsecver;
                return 1;
            }
        } else {                             // skipping a foreign option
            rem--;
            if (!rem)
                st = 0;
        }
    }
    return 0;
}

SEC("tc/ingress")
int stamp_ts(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return TCX_NEXT;
    struct flow_key k4 = {};
    struct flow_key6 k6 = {};
    __u8 has_ports = 0;
    void *l4 = NULL;
    __u8 fam = (__u8)tc_parse_l3(skb, &k4, &k6, &has_ports, 1, &l4);
    if (!fam || !has_ports || !l4 || (fam == 4 && k4.proto != IPPROTO_TCP) ||
        (fam == 6 && k6.proto != IPPROTO_TCP))
        return TCX_NEXT;
    if (l4 + 20 > (void *)(long)skb->data_end)
        return TCX_NEXT;   // re-prove the header fits at the point of use
    __u32 tsval = 0, tsecver = 0;
    if (!tcp_tsopt(l4, (void *)(long)skb->data_end, &tsval, &tsecver) || !tsval)
        return TCX_NEXT;
    struct ts_track tr = {
        .tsval = tsval,
        .ktime = bpf_ktime_get_ns(),
        .mac = mac_key(eth->h_source),
    };
    if (fam == 4)
        bpf_map_update_elem(&ts_track4, &k4, &tr, BPF_ANY);
    else
        bpf_map_update_elem(&ts_track6, &k6, &tr, BPF_ANY);
    return TCX_NEXT;
}

SEC("tc/ingress")
int collect_rtt(struct __sk_buff *skb) {
    struct flow_key k4 = {};
    struct flow_key6 k6 = {};
    __u8 has_ports = 0;
    void *l4 = NULL;
    __u8 fam = (__u8)tc_parse_l3(skb, &k4, &k6, &has_ports, 0, &l4);
    if (!fam || !has_ports || !l4 || (fam == 4 && k4.proto != IPPROTO_TCP) ||
        (fam == 6 && k6.proto != IPPROTO_TCP))
        return TCX_NEXT;
    if (l4 + 20 > (void *)(long)skb->data_end)
        return TCX_NEXT;   // re-prove the header fits at the point of use
    __u32 tsval = 0, tsecver = 0;
    if (!tcp_tsopt(l4, (void *)(long)skb->data_end, &tsval, &tsecver) || !tsecver)
        return TCX_NEXT;
    struct ts_track *tr = fam == 4
                        ? bpf_map_lookup_elem(&ts_track4, &k4)
                        : bpf_map_lookup_elem(&ts_track6, &k6);
    if (!tr || tr->tsval != tsecver)
        return TCX_NEXT;                    // delayed ACK echoed an older TSval
    __u64 delta = bpf_ktime_get_ns() - tr->ktime;
    if (delta == 0 || delta > STALE_NS)
        return TCX_NEXT;
    struct q_delay *q = bpf_map_lookup_elem(&srtt_hist, &tr->mac);
    if (!q) {
        struct q_delay zero = {};
        if (bpf_map_update_elem(&srtt_hist, &tr->mac, &zero, BPF_NOEXIST) != 0)
            return TCX_NEXT;
        q = bpf_map_lookup_elem(&srtt_hist, &tr->mac);
        if (!q)
            return TCX_NEXT;
    }
    __u64 us = delta >> 10;
    __u32 idx = 0;
    for (__u32 v = (__u32)us; v > 1 && idx < 31; v >>= 1)
        idx++;
    q->hist[idx]++;
    q->count++;
    q->sum_ns += delta;
    if (delta > q->max_ns)
        q->max_ns = delta;
    return TCX_NEXT;
}

// ── Router-local service accounting (tc on LAN) ────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);              // router IPv4 on the LAN side
    __type(value, __u8);
} local_addrs4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u8[16]);           // router IPv6 (link-local incl.)
    __type(value, __u8);
} local_addrs6 SEC(".maps");

struct port_bytes {
    __u64 rx;    // from clients into the service (LAN ingress, dst port)
    __u64 tx;    // from the service to clients (LAN egress, src port)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128);
    __type(key, __u16);              // service port
    __type(value, struct port_bytes);
} local_bytes SEC(".maps");

// Shared body: returns the service port when the packet talks to a router
// address (ingress: destination port; egress: source port).
static __inline __u16 service_port(struct __sk_buff *skb, int egress) {
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return 0;
    __u16 etype = eth->h_proto;
    void *p = (void *)(eth + 1);
    if (etype == bpf_htons(ETH_P_8021Q)) {
        if (p + 4 > end)
            return 0;
        etype = *(__u16 *)(p + 2);
        p += 4;
    }
    if (etype == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = p;
        if ((void *)(ip + 1) > end)
            return 0;
        __u32 ihl = (__u32)ip->ihl * 4;
        if (ihl < 20 || p + ihl > end)
            return 0;
        __u32 mine = egress ? ip->saddr : ip->daddr;
        if (!bpf_map_lookup_elem(&local_addrs4, &mine))
            return 0;
        __u16 port = 0;
        void *l4 = p + ihl;
        if (ip->protocol == IPPROTO_TCP && l4 + 20 <= end) {
            struct tcphdr *t = l4;
            port = egress ? t->source : t->dest;
        } else if (ip->protocol == IPPROTO_UDP && l4 + 8 <= end) {
            __u16 *u = l4;
            port = egress ? u[0] : u[1];
        } else {
            return 0;
        }
        struct port_bytes *c = bpf_map_lookup_elem(&local_bytes, &port);
        if (!c) {
            struct port_bytes zero = {};
            bpf_map_update_elem(&local_bytes, &port, &zero, BPF_NOEXIST);
            c = bpf_map_lookup_elem(&local_bytes, &port);
        }
        if (c) {
            if (egress)
                __sync_fetch_and_add(&c->tx, skb->len);
            else
                __sync_fetch_and_add(&c->rx, skb->len);
        }
        return port;
    }
    if (etype == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = p;
        if ((void *)(ip6 + 1) > end)
            return 0;
        void *mine = egress ? (void *)ip6->saddr.s6_addr : (void *)ip6->daddr.s6_addr;
        if (!bpf_map_lookup_elem(&local_addrs6, mine))
            return 0;
        __u16 port = 0;
        void *l4 = (void *)(ip6 + 1);
        if (ip6->nexthdr == IPPROTO_TCP && l4 + 20 <= end) {
            struct tcphdr *t = l4;
            port = egress ? t->source : t->dest;
        } else if (ip6->nexthdr == IPPROTO_UDP && l4 + 8 <= end) {
            __u16 *u = l4;
            port = egress ? u[0] : u[1];
        } else {
            return 0;
        }
        struct port_bytes *c = bpf_map_lookup_elem(&local_bytes, &port);
        if (!c) {
            struct port_bytes zero = {};
            bpf_map_update_elem(&local_bytes, &port, &zero, BPF_NOEXIST);
            c = bpf_map_lookup_elem(&local_bytes, &port);
        }
        if (c) {
            if (egress)
                __sync_fetch_and_add(&c->tx, skb->len);
            else
                __sync_fetch_and_add(&c->rx, skb->len);
        }
        return port;
    }
    return 0;
}

SEC("tc/ingress")
int local_from_lan(struct __sk_buff *skb) {
    service_port(skb, 0);
    return TCX_NEXT;
}

SEC("tc/egress")
int local_to_lan(struct __sk_buff *skb) {
    service_port(skb, 1);
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "MIT";
