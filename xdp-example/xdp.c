#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
clang -O2 -Wall -target bpf -g -c xdp.c -o xdp.o
*/

struct datarec {
	__u64 rx_packets;
};

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, sizeof(struct datarec));
	__uint(max_entries, 1);
} xdp_stats_map SEC(".maps");

SEC("xdp_stats1")
int xdp_stats1_func(struct xdp_md *ctx) {
	struct datarec *rec;
	__u32 key = XDP_PASS;

	if (!rec)
		return XDP_ABORTED;

	lock_xadd(&rec->rx_packets, 1);
	return XDP_PASS;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	return XDP_PASS;
}

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
