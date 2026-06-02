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

#define ENP39S0_IFINDEX 2
// 0a:db:92:db:00:01
__u8 enp39s0_mac[6] = {0x0a, 0xdb, 0x92, 0xdb, 0x00, 0x01};

//  0a:e9:f4:61:78:4d
__u8 client_mac[6] = {0x0a, 0xe9, 0xf4, 0x61, 0x78, 0x4d};

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
    __uint(max_entries, 1 << 17);
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

/*
 * Incremental checksum update for 16-bit field replacement.
 *
 * Equivalent in spirit to:
 *   bpf_l4_csum_replace(... old16, new16 ...)
 *
 * Works for TCP checksum source-port update.
 */
static __always_inline __u16 csum_replace16(__u16 csum, __u16 old, __u16 new)
{
    __u32 sum;

    sum = (~csum) & 0xffff;
    sum += (~old) & 0xffff;
    sum += new;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

/*
 * Incremental checksum update for 32-bit field replacement.
 *
 * Equivalent in spirit to:
 *   bpf_l3_csum_replace(... old32, new32 ...)
 * and:
 *   bpf_l4_csum_replace(... old32, new32, BPF_F_PSEUDO_HDR ...)
 *
 * Used for IPv4 source-address update and TCP pseudo-header update.
 */
static __always_inline __u16 csum_replace32(__u16 csum, __be32 old, __be32 new)
{
    __u32 sum;
    __u16 old_hi = (__u16)(old >> 16);
    __u16 old_lo = (__u16)(old & 0xffff);
    __u16 new_hi = (__u16)(new >> 16);
    __u16 new_lo = (__u16)(new & 0xffff);

    sum = (~csum) & 0xffff;
    sum += (~old_hi) & 0xffff;
    sum += new_hi;
    sum += (~old_lo) & 0xffff;
    sum += new_lo;

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

SEC("xdp")
int xdp_return(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_counter(TCNT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        inc_counter(TCNT_NON_IP);
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return XDP_PASS;
    }

    if (ip->ihl < 5) {
        inc_counter(TCNT_TOO_SHORT);
        return XDP_PASS;
    }

    __u32 ip_hdr_len = ip->ihl * 4;

    if ((void *)ip + ip_hdr_len > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return XDP_PASS;
    }

    // If destination is the LB's bridge IP, this is control plane
    // traffic: heartbeats, health responses, etc.
    // Pass through unchanged.
    __u32 key = 0;
    __u32 *bridge_ip = bpf_map_lookup_elem(&lb_bridge_ip, &key);
    if (bridge_ip && ip->daddr == *bridge_ip) {
        inc_counter(TCNT_TO_LB);
        return XDP_PASS;
    }

    // Only handle TCP for now.
    if (ip->protocol != IPPROTO_TCP) {
        inc_counter(TCNT_OTHER_PROTO);
        return XDP_PASS;
    }

    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) {
        inc_counter(TCNT_TOO_SHORT);
        return XDP_PASS;
    }

    // Look up reverse conntrack.
    struct flow_key rev_key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
        .proto    = IPPROTO_TCP,
    };

    struct ct_value *ct = bpf_map_lookup_elem(&tcp_conntrack_reverse, &rev_key);
    if (!ct) {
        __u8 *src_ip_bytes = (__u8 *)&rev_key.src_ip;
        __u8 *dst_ip_bytes = (__u8 *)&rev_key.dst_ip;

        bpf_printk("[XDP_RETURN]: conntrack miss for flow %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                   src_ip_bytes[0], src_ip_bytes[1],
                   src_ip_bytes[2], src_ip_bytes[3],
                   bpf_ntohs(rev_key.src_port),
                   dst_ip_bytes[0], dst_ip_bytes[1],
                   dst_ip_bytes[2], dst_ip_bytes[3],
                   bpf_ntohs(rev_key.dst_port));

        inc_counter(TCNT_CT_MISS);
        return XDP_PASS;
    }

    // Found in conntrack - rewrite source to VIP.
    __u32 *vip_ptr = bpf_map_lookup_elem(&vip_map, &key);
    __u32 *vip_port_ptr = bpf_map_lookup_elem(&vip_tcp_port, &key);
    if (!vip_ptr || !vip_port_ptr) {
        bpf_printk("[XDP_RETURN]: VIP or VIP port not found\n");
        return XDP_PASS;
    }

    __be32 old_saddr = ip->saddr;
    __be16 old_sport = tcp->source;

    __be32 new_saddr = *vip_ptr;
    __be16 new_sport = bpf_htons((__u16)*vip_port_ptr);

    /*
     * XDP cannot use bpf_l3_csum_replace() or bpf_l4_csum_replace()
     * because those are SKB/TC helpers.
     *
     * So we update the checksums manually before or after direct writes.
     */

    // Update IP header checksum for source-address change.
    ip->check = csum_replace32(ip->check, old_saddr, new_saddr);

    // Update TCP checksum for IPv4 pseudo-header source-address change.
    tcp->check = csum_replace32(tcp->check, old_saddr, new_saddr);

    // Update TCP checksum for TCP source-port change.
    tcp->check = csum_replace16(tcp->check, old_sport, new_sport);

    // Rewrite packet fields.
    ip->saddr = new_saddr;
    tcp->source = new_sport;

    inc_counter(TCNT_TCP_REWRITTEN);

    // Rewrite Ethernet MACs for egress.
    __builtin_memcpy(eth->h_source, enp39s0_mac, 6);
    __builtin_memcpy(eth->h_dest, client_mac, 6);

    bpf_printk("[XDP_RETURN]: redirecting to enp39s0 ifindex=%d, dst_mac(client) %x:%x:%x:%x:%x:%x\n",
               ENP39S0_IFINDEX,
               client_mac[0], client_mac[1], client_mac[2],
               client_mac[3], client_mac[4], client_mac[5]);

    return bpf_redirect(ENP39S0_IFINDEX, 0);
}

char _license[] SEC("license") = "GPL";