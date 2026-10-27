// Per-device traffic counter for TC: one eBPF program per direction,
// sharing one LRU hash map keyed by the client MAC. Ingress counts bytes
// FROM the client (source MAC, `up` = the client's upload); egress counts
// bytes TO the client (destination MAC, `down` = the client's download).
// The Go loader maps these device-centrically (Rx = down, Tx = up). No
// kernel-internal types are touched, so no BTF is required on the target
// kernel.
//
// A second LRU map keys the same bytes by client MAC + destination
// /24 (/48 for IPv6), internet destinations only — router- and LAN-bound
// traffic is filtered out — so userspace can rank which services each
// device actually talks to. One extra map update per packet; the hot
// path is a lookup and an atomic add.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

// TCX chain-continue. TC_ACT_PIPE (3) ends the chain on kernel 6.8+;
// only TCX_NEXT (-1) runs the next program and then the clsact filters.
#define TCX_NEXT -1
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/pkt_cls.h>

struct dev_counters {
    __u64 up;    // bytes FROM the client (ingress, source MAC)
    __u64 down;  // bytes TO the client (egress, destination MAC)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, __u64);   // MAC in the low 48 bits
    __type(value, struct dev_counters);
} device_bytes SEC(".maps");

// Per-device-per-destination byte counters, internet destinations only.
// Key mirrors wan.c's dest_key: the MAC big-endian in the low 48 bits;
// the prefix for v4 is the address's first three octets in the low three
// bytes (the address is read little-endian), for v6 the first six bytes
// of the address. 2048 entries ≈ 80 KB; LRU evicts cold prefixes.
struct dest_key {
    __u64 mac;
    __u64 prefix;
    __u32 fam;    // 4 or 6
    __u32 pad;
};

struct dest_bytes_val {
    __u64 up;    // client -> remote
    __u64 down;  // remote -> client
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct dest_key);
    __type(value, struct dest_bytes_val);
} dest_bytes SEC(".maps");

static __u64 mac_key(const unsigned char *mac) {
    // big-endian MAC in the low 48 bits so keys print naturally
    return ((__u64)mac[0] << 40) | ((__u64)mac[1] << 32) | ((__u64)mac[2] << 24) |
           ((__u64)mac[3] << 16) | ((__u64)mac[4] << 8) | (__u64)mac[5];
}

static struct dev_counters *counter_for(__u64 key) {
    struct dev_counters *c = bpf_map_lookup_elem(&device_bytes, &key);
    if (c)
        return c;
    struct dev_counters zero = {};
    if (bpf_map_update_elem(&device_bytes, &key, &zero, BPF_NOEXIST) == 0)
        return bpf_map_lookup_elem(&device_bytes, &key);
    return bpf_map_lookup_elem(&device_bytes, &key); // lost the race: retry
}

static struct dest_bytes_val *dest_for(__u64 mac, __u64 prefix, __u32 fam) {
    struct dest_key k = {.mac = mac, .prefix = prefix, .fam = fam};
    struct dest_bytes_val *d = bpf_map_lookup_elem(&dest_bytes, &k);
    if (d)
        return d;
    struct dest_bytes_val zero = {};
    if (bpf_map_update_elem(&dest_bytes, &k, &zero, BPF_NOEXIST) == 0)
        return bpf_map_lookup_elem(&dest_bytes, &k);
    return bpf_map_lookup_elem(&dest_bytes, &k); // lost the race: retry
}

// v4_remote is true when the address is an internet destination, i.e.
// anything that is not private, loopback, link-local, multicast or
// otherwise reserved. Same bogon list the WAN gate uses for sources.
static int v4_remote(__u32 a) {
    __u8 b0 = a & 0xff, b1 = (a >> 8) & 0xff;
    if (b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224)
        return 0;
    if (b0 == 169 && b1 == 254)
        return 0;
    if (b0 == 172 && (b1 & 0xf0) == 16)
        return 0;
    if (b0 == 192 && b1 == 168)
        return 0;
    return 1;
}

// v6_remote filters link-local (fe80::/10), unique-local (fc00::/7),
// multicast (ff00::/8) and the unspecified/loopback ::/1 stem.
static int v6_remote(const unsigned char *a) {
    if (a[0] == 0 || a[0] == 0xff)
        return 0;
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80)
        return 0;
    if (a[0] == 0xfc || a[0] == 0xfd)
        return 0;
    return 1;
}

// record_dest accounts one packet's bytes against client + destination.
// The remote address is read from the packet's far end: the destination
// on ingress (client speaking), the source on egress (client listening).
// Layout after the Ethernet header is checked once here so both
// programs share it: one optional 802.1Q tag, then IPv4 or IPv6.
static __inline void record_dest(void *data, void *end, struct ethhdr *eth,
                                 int egress, __u64 len) {
    __u16 etype = eth->h_proto;
    void *p = data + sizeof(*eth);
    if (p + 4 > end)
        return;
    if (etype == bpf_htons(0x8100)) {
        __builtin_memcpy(&etype, p + 2, 2);
        p += 4;
    }
    __u64 mac;
    const unsigned char *remote;
    if (egress) {
        if (eth->h_dest[0] & 0x01)
            return;   // multicast/broadcast: not a device
        mac = mac_key(eth->h_dest);
    } else {
        mac = mac_key(eth->h_source);
    }

    struct dest_key k = {.mac = mac};
    if (etype == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = p;
        if ((void *)(ip + 1) > end || ip->version != 4)
            return;
        remote = (void *)&ip->daddr;   // client speaking: the far end is the destination
        if (egress)
            remote = (void *)&ip->saddr;   // client listening: far end is the source
        __u32 addr;
        __builtin_memcpy(&addr, remote, 4);
        if (!v4_remote(addr))
            return;
        k.prefix = (__u64)(addr & 0x00FFFFFFu);   // host octet masked off
        k.fam = 4;
    } else if (etype == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = p;
        if ((void *)(ip6 + 1) > end || ip6->version != 6)
            return;
        remote = ip6->daddr.s6_addr;
        if (egress)
            remote = ip6->saddr.s6_addr;
        if (!v6_remote(remote))
            return;
        __builtin_memcpy(&k.prefix, remote, 6);   // top 48 bits
        k.fam = 6;
    } else {
        return;
    }

    struct dest_bytes_val *d = dest_for(mac, k.prefix, k.fam);
    if (d) {
        if (egress)
            __sync_fetch_and_add(&d->down, len);
        else
            __sync_fetch_and_add(&d->up, len);
    }
}

SEC("tc/ingress")
int count_from_client(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return TCX_NEXT;
    struct dev_counters *c = counter_for(mac_key(eth->h_source));
    if (c)
        __sync_fetch_and_add(&c->up, skb->len);
    record_dest(data, end, eth, 0, skb->len);
    return TCX_NEXT;
}

SEC("tc/egress")
int count_to_client(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return TCX_NEXT;
    struct dev_counters *c = counter_for(mac_key(eth->h_dest));
    if (c)
        __sync_fetch_and_add(&c->down, skb->len);
    record_dest(data, end, eth, 1, skb->len);
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "MIT";
