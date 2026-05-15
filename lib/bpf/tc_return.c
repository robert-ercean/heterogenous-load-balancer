#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} tc_packet_count SEC(".maps");

SEC("tc")
int tc_return(struct __sk_buff *skb) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&tc_packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return TC_ACT_OK;
}
