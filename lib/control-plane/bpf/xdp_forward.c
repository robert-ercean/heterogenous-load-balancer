// SPDX-License-Identifier: GPL-2.0

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800

// -------- Counters ---------------------------------------------------------
#define CNT_TOTAL             0
#define CNT_TCP               1
#define CNT_UDP               2
#define CNT_OTHER             3
#define CNT_TOO_SHORT         4
#define CNT_NON_IP            5
#define CNT_VIP_TCP_FORWARDED 6
#define CNT_CT_HIT            7   // forward conntrack lookup hit
#define CNT_CT_MISS_NEW       8   // miss + SYN → new conntrack entry
#define CNT_CT_MISS_ORPHAN    9   // miss + non-SYN → dropped
#define CNT_FIB_FAILED       10
#define CNT_NO_BACKEND       11
#define CNT_CT_INSERT_FAIL   12
#define CNT_MAX              13

__u8 egress_mac[6] = {0xba, 0xc6, 0xbe, 0x41, 0x58, 0xd9};
#define EGRESS_IFINDEX 4

// -------- Data structures --------

struct backend_entry {
    __u32 ip;           // network byte order
    __u16 port;         // network byte order
    __u16 pad1;
    __u32 load_score;
    __u8  mac[6];
    __u16 pad2;
};

// 5-tuple key for conntrack maps.
// All fields in network byte order (matches packet header layout).
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

// Conntrack value: which backend slot serves this flow.
struct ct_value {
    __u32 backend_slot;
};

// -------- Maps ------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} packet_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct backend_entry);
} tcp_pool SEC(".maps");

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

// Forward conntrack: keyed on client-side 5-tuple
// (client_ip, VIP, client_port, VIP_port, TCP)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (1 << 14)); // ~ 16k entries, evicting least recently used ones when full
    __type(key, struct flow_key);
    __type(value, struct ct_value);
} tcp_conntrack_forward SEC(".maps");

// Reverse conntrack: keyed on backend-side 5-tuple
// (backend_ip, client_ip, backend_port, client_port, TCP)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, (1 << 14));
    __type(key, struct flow_key);
    __type(value, struct ct_value);
} tcp_conntrack_reverse SEC(".maps");

// -------- Helpers ----------------------------------------

static __always_inline void inc_counter(__u32 idx) {
    __u64 *count = bpf_map_lookup_elem(&packet_counters, &idx);
    if (count) __sync_fetch_and_add(count, 1);
}

// Incremental checksum update for a 32-bit value change (IP address)
// RFC 1624
static __always_inline __u16 csum_replace_u32(__u16 old_csum, __u32 old_val, __u32 new_val) {
    __u32 sum = (__u16)~old_csum;
    sum += (__u16)~(old_val & 0xFFFF);
    sum += (__u16)~((old_val >> 16) & 0xFFFF);
    sum += (__u16)(new_val & 0xFFFF);
    sum += (__u16)((new_val >> 16) & 0xFFFF);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

// Incremental checksum update for a 16-bit value change (port)
// RFC 1624
static __always_inline __u16 csum_replace_u16(__u16 old_csum, __u16 old_val, __u16 new_val) {
    __u32 sum = (__u16)~old_csum;
    sum += (__u16)~old_val;
    sum += new_val;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

// -------- Main program ----------------------------------------

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

    if (ip->ihl < 5) {
        inc_counter(CNT_TOO_SHORT);
        return XDP_PASS;
    }
    __u32 ip_hdr_len = ip->ihl * 4;

    // Only handle TCP for now (UDP added later)
    if (ip->protocol != IPPROTO_TCP) {
        if (ip->protocol == IPPROTO_UDP) inc_counter(CNT_UDP);
        else inc_counter(CNT_OTHER);
        return XDP_PASS;
    }

    inc_counter(CNT_TCP);

    // VIP filter
    __u32 cfg_key = 0;
    __u32 *vip_ptr = bpf_map_lookup_elem(&vip_map, &cfg_key);
    if (!vip_ptr || ip->daddr != *vip_ptr) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) {
        inc_counter(CNT_TOO_SHORT);
        return XDP_PASS;
    }

    // -------- Conntrack lookup --------
    
    struct flow_key fwd_key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
        .proto    = IPPROTO_TCP,
    };

    __u32 slot;
    struct ct_value *ct = bpf_map_lookup_elem(&tcp_conntrack_forward, &fwd_key);

    if (ct) {
        // Existing flow - use stored backend
        slot = ct->backend_slot;
        inc_counter(CNT_CT_HIT);
        bpf_printk("XDP: conntrack hit for existing flow, backend slot=%d", slot);
    } else {
        // No conntrack entry. Is this the start of a new flow?
        // SYN without ACK = first packet of new connection.
        if (!tcp->syn || tcp->ack) {
            // Mid-flow packet for unknown flow - drop it
            // Allowing it through would forward to a random backend
            // that has no TCP state for this flow.
            // Maybe we should let the kernel handle it? Not sure, since packets are filtered by VIP so I guess not
            inc_counter(CNT_CT_MISS_ORPHAN);
            bpf_printk("XDP: orphan packet with no conntrack entry, dropping");
            return XDP_DROP;
        }

        // New flow - SYN present. Pick a backend using the power of two choice principle
        bpf_printk("XDP: conntrack miss for new flow(got SYN), creating new entry in slot 0 (hardcoded)");
        // Sanity check if there are any active backends in the pool
        __u32 tcp_idx = 0;
        __u32 *active = bpf_map_lookup_elem(&pool_meta, &tcp_idx);
        if (!active || *active == 0) {
            bpf_printk("XDP: no active backends in TCP pool, dropping packet");
            inc_counter(CNT_NO_BACKEND);
            return XDP_PASS;
        }

        __u32 active_count = *active;
        __u32 pick1 = bpf_get_prandom_u32() % active_count;
        __u32 pick2 = bpf_get_prandom_u32() % active_count;
        struct backend_entry *be1 = bpf_map_lookup_elem(&tcp_pool, &pick1);
        struct backend_entry *be2 = bpf_map_lookup_elem(&tcp_pool, &pick2);
        if (!be1 || !be2) {
            inc_counter(CNT_NO_BACKEND);
            bpf_printk("XDP: no active backends found at random picks, letting kernel handle it");
            return XDP_PASS;
        }
        
        slot = (be1->load_score <= be2->load_score) ? pick1 : pick2;
        
        struct backend_entry *backend = bpf_map_lookup_elem(&tcp_pool, &slot);
        if (!backend) {
            inc_counter(CNT_NO_BACKEND);
            bpf_printk("XDP: no backend found at selected slot %d, letting kernel handle it", slot);
            return XDP_PASS;
        }

        // Populate the conntrack map with the new flow entry
        // BPF_ANY  creates a new element  or updates an existing one, which is what we want here
        struct ct_value new_ct = { .backend_slot = slot };
        if (bpf_map_update_elem(&tcp_conntrack_forward, &fwd_key, &new_ct, BPF_ANY) < 0) {
            inc_counter(CNT_CT_INSERT_FAIL);
        }

        // Insert reverse conntrack
        // After rewriting, in tc_return.c the reply will be: src=backend_ip:backend_port
        //                                                    dst=client_ip :client_port
        struct flow_key rev_key = {
            .src_ip   = backend->ip,
            .dst_ip   = ip->saddr,        // original client IP
            .src_port = backend->port,
            .dst_port = tcp->source,      // original client port
            .proto    = IPPROTO_TCP,
        };
        if (bpf_map_update_elem(&tcp_conntrack_reverse, &rev_key, &new_ct, BPF_ANY) < 0) {
            inc_counter(CNT_CT_INSERT_FAIL);
        }

        inc_counter(CNT_CT_MISS_NEW);
    }

    // -------- Forward to backend ---------

    struct backend_entry *backend = bpf_map_lookup_elem(&tcp_pool, &slot);
    if (!backend) {
        inc_counter(CNT_NO_BACKEND);
        return XDP_PASS;
    }

    __be32 old_daddr = ip->daddr;
    __be16 old_dport = tcp->dest;

    // Rewrite L3 and L4 destination
    ip->daddr = backend->ip;
    tcp->dest = backend->port;

    // IP checksum: dst IP changed
    ip->check = csum_replace_u32(ip->check, old_daddr, backend->ip);

    // TCP checksum: dst IP and dst port both changed
    tcp->check = csum_replace_u32(tcp->check, old_daddr, backend->ip);
    tcp->check = csum_replace_u16(tcp->check, old_dport, backend->port);

    // Rewrite Ethernet destination to backend MAC
    __builtin_memcpy(eth->h_source, egress_mac, 6);
    __builtin_memcpy(eth->h_dest, backend->mac, 6);

    inc_counter(CNT_VIP_TCP_FORWARDED);
    bpf_printk("XDP: forwarding packet to backend slot %d at IP %x, port %d", slot, backend->ip, bpf_ntohs(backend->port));
    return bpf_redirect(EGRESS_IFINDEX, 0);
}

char _license[] SEC("license") = "GPL";