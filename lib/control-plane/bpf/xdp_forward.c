#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define COUNTER_TOTAL           0
#define COUNTER_TCP             1
#define COUNTER_UDP             2
#define COUNTER_NON_TCP_UDP     3
#define COUNTER_TOO_SHORT       4
#define COUNTER_NON_IPV4        5
#define TOTAL_ENTRIES           6

/* Macros not defined in vmlinux.h */
#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TOTAL_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} packet_counters SEC(".maps");

static __always_inline void inc_counter(__u32 idx) {
    __u64 *count = bpf_map_lookup_elem(&packet_counters, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(COUNTER_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_counter(COUNTER_TOO_SHORT);
        return XDP_PASS;
    }

    // Only support IPv4 packets, we can ignore the rest
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_counter(COUNTER_NON_IPV4);
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_counter(COUNTER_TOO_SHORT);
        return XDP_PASS;
    }

    // IPv4 header length is variable with a minimum valid value of 5 (20 bytes since ihl is in 32-bit words)
    if (ip->ihl < 5) {
        inc_counter(COUNTER_TOO_SHORT);
        return XDP_PASS;
    }
    __u32 ip_hdr_len = ip->ihl * 4;

    void *transport_layer = (void *)ip + ip_hdr_len;
    if (transport_layer > data_end) {
        inc_counter(COUNTER_TOO_SHORT);
        return XDP_PASS;
    }

    // ip->protocol is 1 byte so we dont have to convert endianness
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = transport_layer;
        if ((void *)(tcp + 1) > data_end) {
            inc_counter(COUNTER_TOO_SHORT);
            return XDP_PASS;
        }
        inc_counter(COUNTER_TCP);
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = transport_layer;
        if ((void *)(udp + 1) > data_end) {
            inc_counter(COUNTER_TOO_SHORT);
            return XDP_PASS;
        }
        inc_counter(COUNTER_UDP);
        break;
    }
    default:
        inc_counter(COUNTER_NON_TCP_UDP);
        break;
    }

    return XDP_PASS;

}