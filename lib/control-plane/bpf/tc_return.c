// SPDX-License-Identifier: GPL-2.0

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define TC_ACT_OK   0

// -------- Counters -----------------------------------──
#define TCNT_TOTAL              0
#define TCNT_NON_IP             1
#define TCNT_TO_LB              2
#define TCNT_TCP_REWRITTEN      3
#define TCNT_CT_MISS            4
#define TCNT_OTHER_PROTO        5
#define TCNT_TOO_SHORT          6
#define TCNT_FIB_FAILED         7
#define TCNT_MAX                8

#define ENP7S0_IFINDEX 2
__u8 enp7s0_mac[6] = {0x8c, 0x8c, 0xaa, 0xff, 0xdb, 0x3d};

__u8 default_gateway_mac[6] = {0x14, 0x22, 0x33, 0xe7, 0xef, 0x20};

struct backend_entry {
    __u32 ip;           // network byte order
    __u16 port;         // network byte order
    __u16 pad1;
    __u32 load_score;
    __u8  mac[6];
    __u16 pad2;
};

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  _pad[3];
};

struct ct_value {
    __u32 backend_slot;
};

// -------- Maps (shared with XDP) ---------------------------

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, struct backend_entry);
} tcp_pool SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, struct backend_entry);
} udp_pool SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} pool_meta SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct ct_value);
} tcp_conntrack_reverse SEC(".maps");

// -------- Maps (TC-only) -----------------------------------──

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

    // Look up reverse conntrack
    struct flow_key rev_key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
        .proto    = IPPROTO_TCP,
    };

    struct ct_value *ct = bpf_map_lookup_elem(&tcp_conntrack_reverse, &rev_key);
    if (!ct) {
        // No conntrack - this packet isn't part of a flow we manage.
        bpf_printk("TC: conntrack miss for flow %x:%d -> %x:%d\n",
                   rev_key.src_ip, bpf_ntohs(rev_key.src_port),
                   rev_key.dst_ip, bpf_ntohs(rev_key.dst_port));
        inc_counter(TCNT_CT_MISS);
        return TC_ACT_OK;
    }

    // Found in conntrack - rewrite source to VIP
    __u32 *vip_ptr = bpf_map_lookup_elem(&vip_map, &key);
    __u32 *vip_port_ptr = bpf_map_lookup_elem(&vip_tcp_port, &key);
    if (!vip_ptr || !vip_port_ptr) {
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

    // Update TCP Checksum 
    // Have to use BPF_F_PSEUDO_HDR flag when IP changes to avoid corruption during hardware checksum offload
    bpf_l4_csum_replace(skb, tcp_csum_offset, old_saddr, new_saddr, BPF_F_PSEUDO_HDR | sizeof(new_saddr));
    bpf_l4_csum_replace(skb, tcp_csum_offset, old_sport, new_sport, sizeof(new_sport));

    //  Update IP Checksum
    bpf_l3_csum_replace(skb, ip_csum_offset, old_saddr, new_saddr, sizeof(new_saddr));

    inc_counter(TCNT_TCP_REWRITTEN);

    
    // Rewrite Ethernet MACs for egress.
    // skb->data points to the L2 header; we can write through it.
    void *eth_data = (void *)(long)skb->data;
    void *eth_end = (void *)(long)skb->data_end;
    struct ethhdr *eth_out = eth_data;
    if ((void *)(eth_out + 1) > eth_end) {
        return TC_ACT_OK;
    }
    __builtin_memcpy(eth_out->h_source, enp7s0_mac, 6);
    __builtin_memcpy(eth_out->h_dest, default_gateway_mac, 6);

    bpf_printk("TC: redirecting to enp7s0 (ifindex=%d), dst_mac(default gateway's) %x:%x:%x:%x:%x:%x",
               ENP7S0_IFINDEX,
               default_gateway_mac[0], default_gateway_mac[1], default_gateway_mac[2],
               default_gateway_mac[3], default_gateway_mac[4], default_gateway_mac[5]);

    return bpf_redirect(ENP7S0_IFINDEX, 0);
}

char _license[] SEC("license") = "GPL";