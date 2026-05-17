// SPDX-License-Identifier: GPL-2.0

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define TC_ACT_OK   0

// Counter indices
#define TCNT_TOTAL          0
#define TCNT_NON_IP         1
#define TCNT_TO_LB          2
#define TCNT_TCP_REWRITTEN  3
#define TCNT_NO_BACKEND     4
#define TCNT_OTHER_PROTO    5
#define TCNT_TOO_SHORT      6
#define TCNT_MAX            7

struct backend_entry {
    __u32 ip;
    __u16 port;
    __u16 _pad;
    __u32 load_score;
    __u32 _pad2;
};

// Maps shared with XDP via the loader's MapReplacements mechanism
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} pool_meta SEC(".maps");

// Separate maps that TC populates from the loader (not shared with XDP)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} lb_bridge_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} vip_tcp_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TCNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} tc_counters SEC(".maps");

static __always_inline void inc_counter(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&tc_counters, &idx);
    if (c) __sync_fetch_and_add(c, 1);
}

SEC("tc")
int tc_return(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    inc_counter(TCNT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_counter(TCNT_NON_IP);
        return TC_ACT_OK;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return TC_ACT_OK;
    }

    if (ip->ihl < 5) {
        inc_counter(TCNT_TOO_SHORT);
        return TC_ACT_OK;
    }

    // If destination is the LB's bridge IP, this is control plane
    // traffic (heartbeats, health responses). Pass through unchanged.
    __u32 key = 0;
    __u32 *bridge_ip = bpf_map_lookup_elem(&lb_bridge_ip, &key);
    if (bridge_ip && ip->daddr == *bridge_ip) {
        inc_counter(TCNT_TO_LB);
        return TC_ACT_OK;   
    }

    // Only handle TCP for now
    if (ip->protocol != IPPROTO_TCP) {
        inc_counter(TCNT_OTHER_PROTO);
        return TC_ACT_OK;
    }

    __u32 ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return TC_ACT_OK;
    }

    // Check if the source IP matches our backend (only one for now, slot 0).
    __u32 tcp_idx = 0;
    __u32 *tcp_active = bpf_map_lookup_elem(&pool_meta, &tcp_idx);
    if (!tcp_active || *tcp_active == 0) {
        inc_counter(TCNT_NO_BACKEND);
        bpf_printk("TC: no active backends in TCP pool, skipping rewrite");
        return TC_ACT_OK;
    }

    __u32 slot = 0;
    struct backend_entry *backend = bpf_map_lookup_elem(&tcp_pool, &slot);
    if (!backend || backend->ip != ip->saddr) {
        inc_counter(TCNT_NO_BACKEND);
        bpf_printk("TC: backend IP mismatch, skipping rewrite");
        return TC_ACT_OK;
    }

    // Read VIP and the VIP TCP port we should rewrite source to
    __u32 *vip_ptr = bpf_map_lookup_elem(&vip_map, &key);
    __u32 *vip_port_ptr = bpf_map_lookup_elem(&vip_tcp_port, &key);
    if (!vip_ptr || !vip_port_ptr) {
        bpf_printk("TC: missing VIP or VIP TCP port, skipping rewrite");
        return TC_ACT_OK;
    }

    __u32 new_saddr = *vip_ptr;
    __be16 new_sport = bpf_htons((__u16)*vip_port_ptr);

    __be32 old_saddr = ip->saddr;
    __be16 old_sport = tcp->source;

    __u8 proto = ip->protocol;
    __u16 total_len = bpf_ntohs(ip->tot_len);
    __be32 dst_addr = ip->daddr;

    // Rewrite
    // Calculate the exact byte offsets from the start of the packet
    __u32 ip_csum_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
    __u32 tcp_csum_offset = sizeof(struct ethhdr) + ip_hdr_len + offsetof(struct tcphdr, check);

    ip->saddr = new_saddr;
    tcp->source = new_sport;

    //  Update TCP Checksum (Must use BPF_F_PSEUDO_HDR flag when IP changes)
    // We pass sizeof() so the kernel knows whether we are updating a 32-bit IP or 16-bit port
    bpf_l4_csum_replace(skb, tcp_csum_offset, old_saddr, new_saddr, BPF_F_PSEUDO_HDR | sizeof(new_saddr));
    bpf_l4_csum_replace(skb, tcp_csum_offset, old_sport, new_sport, sizeof(new_sport));

    //  Update IP Checksum
    bpf_l3_csum_replace(skb, ip_csum_offset, old_saddr, new_saddr, sizeof(new_saddr));

    inc_counter(TCNT_TCP_REWRITTEN);

    #define ENP7S0_IFINDEX 2
    
    // Resolve the egress MAC for the destination. Without this, the bridge
    // would forward the frame with the bridge MAC, which the client wouldn't accept.
    // bpf_fib_lookup gives us src and dst MAC for the egress path.
    struct bpf_fib_lookup fib = {};
    fib.family = 2; // AF_INET
    fib.l4_protocol = proto;
    fib.tot_len = total_len;
    fib.ipv4_src = new_saddr;
    fib.ipv4_dst = dst_addr;
    fib.ifindex = ENP7S0_IFINDEX;

    int fib_ret = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
    if (fib_ret != BPF_FIB_LKUP_RET_SUCCESS) {
        bpf_printk("TC fib_lookup failed: ret=%d", fib_ret);
        return TC_ACT_OK;  // fall back to letting the kernel try
    }

    // Rewrite Ethernet MACs for egress.
    // skb->data points to the L2 header; we can write through it.
    void *eth_data = (void *)(long)skb->data;
    void *eth_end = (void *)(long)skb->data_end;
    struct ethhdr *eth_out = eth_data;
    if ((void *)(eth_out + 1) > eth_end) {
        return TC_ACT_OK;
    }
    __builtin_memcpy(eth_out->h_source, fib.smac, 6);
    __builtin_memcpy(eth_out->h_dest, fib.dmac, 6);

    bpf_printk("TC: redirecting to enp7s0 (ifindex=%d), dst_mac %x:%x:%x:%x:%x:%x",
               ENP7S0_IFINDEX,
               fib.dmac[0], fib.dmac[1], fib.dmac[2],
               fib.dmac[3], fib.dmac[4], fib.dmac[5]);

    return bpf_redirect(ENP7S0_IFINDEX, 0);
}

char _license[] SEC("license") = "GPL";