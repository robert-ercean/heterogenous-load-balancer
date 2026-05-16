#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0

#define COUNTER_TOTAL           0
#define COUNTER_TCP             1
#define COUNTER_UDP             2
#define COUNTER_NON_TCP_UDP     3
#define COUNTER_TOO_SHORT       4
#define COUNTER_NON_IP          5
#define TOTAL_ENTRIES           6


/* Macros not defined in vmlinux.h */
#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TOTAL_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} tc_packet_counters SEC(".maps");

static __always_inline void inc_counter(__u32 idx) {
    __u64 *count = bpf_map_lookup_elem(&tc_packet_counters, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

SEC("tc")
int tc_return(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    inc_counter(COUNTER_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_counter(COUNTER_TOO_SHORT);
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_counter(COUNTER_NON_IP);
        return TC_ACT_OK;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_counter(COUNTER_TOO_SHORT);
        return TC_ACT_OK;
    }

    // IPv4 header length is variable with a minimum valid value of 5 (20 bytes since ihl is in 32-bit words)  
    if (ip->ihl < 5) {
        inc_counter(COUNTER_TOO_SHORT);
        return TC_ACT_OK;
    }
    __u32 ip_hdr_len = ip->ihl * 4;

    void *transport_layer = (void *)ip + ip_hdr_len;
    if (transport_layer > data_end) {
        inc_counter(COUNTER_TOO_SHORT);
        return TC_ACT_OK;
    }

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = transport_layer;
        if ((void *)(tcp + 1) > data_end) {
            inc_counter(COUNTER_TOO_SHORT);
            return TC_ACT_OK;
        }
        inc_counter(COUNTER_TCP);
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = transport_layer;
        if ((void *)(udp + 1) > data_end) {
            inc_counter(COUNTER_TOO_SHORT);
            return TC_ACT_OK;
        }
        inc_counter(COUNTER_UDP);
        break;
            }
    default     :
        inc_counter(COUNTER_NON_TCP_UDP);
        break       ;
            }       

    return TC_ACT_OK;
}