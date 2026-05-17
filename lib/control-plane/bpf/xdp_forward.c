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

    // Existing protocol counting logic
    if (ip->protocol == IPPROTO_TCP) {
        inc_counter(CNT_TCP);
    } else if (ip->protocol == IPPROTO_UDP) {
        inc_counter(CNT_UDP);
    } else {
        inc_counter(CNT_OTHER);
    }

    // ─── ACTUAL FORWARDING LOGIC ──────────────────────────────────

    // log pool sizes
    __u32 tcp_idx = 0, udp_idx = 1;
    __u32 *tcp_active = bpf_map_lookup_elem(&pool_meta, &tcp_idx);
    __u32 *udp_active = bpf_map_lookup_elem(&pool_meta, &udp_idx);

    __u32 tcp_count = tcp_active ? *tcp_active : 0;
    __u32 udp_count = udp_active ? *udp_active : 0;

    // Only forward IPv4 TCP/UDP. For other protocols, pass to kernel.
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // Check VIP match. If not destined for our VIP, kernel handles it normally.
    __u32 vip_key = 0;
    __u32 *vip_ptr = bpf_map_lookup_elem(&vip_map, &vip_key);
    if (!vip_ptr || ip->daddr != *vip_ptr) {
        return XDP_PASS;
    }

    // Look up backend in slot 0 of the TCP pool.
    // (UDP support added later; for now we only handle TCP packets to the VIP.)
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    if (!tcp_active || *tcp_active == 0) {
        // No backends registered yet — pass through (client will get RST from kernel)
        bpf_printk("XDP: no active backends in TCP pool, passing to kernel");
        return XDP_PASS;
    }

    __u32 slot = 0;
    struct backend_entry *backend = bpf_map_lookup_elem(&tcp_pool, &slot);
    if (!backend) {
        return XDP_PASS;
    }

    // Parse TCP header for the port we need to rewrite.
    __u32 ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) {
        bpf_printk("XDP: packet too short for TCP header, passing to kernel");
        return XDP_PASS;
    }

    // Save old values for checksum update
    __be32 old_daddr = ip->daddr;
    __be16 old_dport = tcp->dest;

    // Rewrite L3 destination IP
    ip->daddr = backend->ip;

    // Rewrite L4 destination port
    tcp->dest = backend->port;

    // Update IP checksum (incremental, RFC 1624)
    // Only the destination IP changed, so we update with that diff.
    __u32 ip_csum_sum = (__u16)~ip->check;
    ip_csum_sum += (__u16)~(old_daddr & 0xFFFF);
    ip_csum_sum += (__u16)~((old_daddr >> 16) & 0xFFFF);
    ip_csum_sum += (__u16)(backend->ip & 0xFFFF);
    ip_csum_sum += (__u16)((backend->ip >> 16) & 0xFFFF);
    while (ip_csum_sum >> 16) {
        ip_csum_sum = (ip_csum_sum & 0xFFFF) + (ip_csum_sum >> 16);
    }
    ip->check = (__u16)~ip_csum_sum;

    // Update TCP checksum (incremental)
    // The TCP checksum covers the pseudo-header which includes the dst IP,
    // AND the TCP header itself which includes the dst port. Both changed.
    __u32 tcp_csum_sum = (__u16)~tcp->check;
    // Diff for IP change
    tcp_csum_sum += (__u16)~(old_daddr & 0xFFFF);
    tcp_csum_sum += (__u16)~((old_daddr >> 16) & 0xFFFF);
    tcp_csum_sum += (__u16)(backend->ip & 0xFFFF);
    tcp_csum_sum += (__u16)((backend->ip >> 16) & 0xFFFF);
    // Diff for port change
    tcp_csum_sum += (__u16)~old_dport;
    tcp_csum_sum += (__u16)backend->port;
    while (tcp_csum_sum >> 16) {
        tcp_csum_sum = (tcp_csum_sum & 0xFFFF) + (tcp_csum_sum >> 16);
    }
    tcp->check = (__u16)~tcp_csum_sum;

    // Now figure out which interface to send out. The packet is now destined
    // for the backend's IP, which lives on br0 (the bridge). Ask the kernel
    // via bpf_fib_lookup which interface to use and what MACs to put on the frame.
    struct bpf_fib_lookup fib = {};
    fib.family = 2;  // AF_INET
    fib.l4_protocol = ip->protocol;
    fib.tot_len = bpf_ntohs(ip->tot_len);
    fib.ipv4_src = ip->saddr;
    fib.ipv4_dst = ip->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    int fib_ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (fib_ret != BPF_FIB_LKUP_RET_SUCCESS) {
        // Couldn't resolve next hop. Could be no route, no ARP entry, etc.
        // For now, pass to kernel and let it figure things out.
        bpf_printk("XDP fib_lookup failed: ret=%d", fib_ret);
        return XDP_PASS;
    }

    // Rewrite Ethernet MACs to the ones the FIB resolution returned.
    __builtin_memcpy(eth->h_source, fib.smac, 6);
    __builtin_memcpy(eth->h_dest, fib.dmac, 6);

    // Redirect to the egress interface returned by FIB.
    return bpf_redirect(fib.ifindex, 0);

}

char _license[] SEC("license") = "GPL";