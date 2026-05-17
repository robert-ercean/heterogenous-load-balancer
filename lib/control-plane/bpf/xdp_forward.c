// SPDX-License-Identifier: GPL-2.0

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Not defined in vmlinux.h, so we define it here for convenience
#define ETH_P_IP    0x0800

#define CNT_TOTAL     0
#define CNT_TCP       1
#define CNT_UDP       2
#define CNT_OTHER     3
#define CNT_TOO_SHORT 4
#define CNT_NON_IP    5
#define CNT_MAX       6

struct backend_entry {
    __u32 ip;           // network byte order, matches ip->daddr
    __u16 port;         // network byte order, matches tcp/udp dest port
    __u16 _pad;         // explicit padding so the struct size is predictable
    __u32 load_score;   // 0-255, lower = less loaded (host order)
    __u32 _pad2;        // align to 16 bytes total
};

// Counter packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} xdp_packet_counters SEC(".maps");

// Single-entry array map storing the VIP as a u32.
// The Go control plane populates this at startup.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} vip_map SEC(".maps");


// TCP backend pool — up to 64 slots, indexed 0..N-1
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct backend_entry);
} tcp_pool SEC(".maps");

// UDP backend pool — same shape
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct backend_entry);
} udp_pool SEC(".maps");

// pool_meta: tracks how many active slots each pool has.
// key 0 = TCP pool active count
// key 1 = UDP pool active count
// XDP needs this to know which slots are populated vs. zero-filled.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} pool_meta SEC(".maps");


/* --------------------------------------------------------------- */

static __always_inline void inc_counter(__u32 idx) {
    __u64 *count = bpf_map_lookup_elem(&xdp_packet_counters, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}


SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(CNT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_counter(CNT_TOO_SHORT);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_counter(CNT_NON_IP);
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_counter(CNT_TOO_SHORT);
        return XDP_PASS;
    }

    // ─── NEW: read VIP and log comparison ─────────────────
    __u32 key = 0;
    __u32 *vip_ptr = bpf_map_lookup_elem(&vip_map, &key);
    if (vip_ptr) {
        // Log the daddr we see vs the VIP we have configured.
        // Both are in network byte order (raw __be32 representations).
        bpf_printk("XDP packet: daddr=0x%x  vip_in_map=0x%x",
                   ip->daddr, *vip_ptr);
    } else {
        bpf_printk("XDP packet: vip_map empty");
    }

    // Existing protocol counting logic
    if (ip->protocol == IPPROTO_TCP) {
        inc_counter(CNT_TCP);
    } else if (ip->protocol == IPPROTO_UDP) {
        inc_counter(CNT_UDP);
    } else {
        inc_counter(CNT_OTHER);
    }

    // log pool sizes
    __u32 tcp_idx = 0, udp_idx = 1;
    __u32 *tcp_active = bpf_map_lookup_elem(&pool_meta, &tcp_idx);
    __u32 *udp_active = bpf_map_lookup_elem(&pool_meta, &udp_idx);

    __u32 tcp_count = tcp_active ? *tcp_active : 0;
    __u32 udp_count = udp_active ? *udp_active : 0;

    bpf_printk("XDP pool sizes: tcp=%u udp=%u", tcp_count, udp_count);

    #pragma unroll
    for (__u32 i = 0; i < 2; i++) {
        if (i >= tcp_count) break;
        __u32 slot = i;
        struct backend_entry *entry = bpf_map_lookup_elem(&tcp_pool, &slot);
        if (entry) {
            __u32 host_ip = bpf_ntohl(entry->ip);
            bpf_printk("ip=%u.%u.%u.%u, port=%u, load=%u",
                (host_ip >> 24) & 0xff,
                (host_ip >> 16) & 0xff,
                (host_ip >> 8) & 0xff,
                host_ip & 0xff,
                bpf_ntohs(entry->port),
                entry->load_score
            );

        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";