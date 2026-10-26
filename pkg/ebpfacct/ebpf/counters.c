// Per-device traffic counter for TC: one eBPF program per direction,
// sharing one LRU hash map keyed by the client MAC. Ingress counts bytes
// FROM the client (source MAC, `up` = the client's upload); egress counts
// bytes TO the client (destination MAC, `down` = the client's download).
// The Go loader maps these device-centrically (Rx = down, Tx = up). No
// kernel-internal types are touched, so no BTF is required on the target
// kernel.
#include <linux/bpf.h>
#include <linux/if_ether.h>
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
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "MIT";
