#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, __u8);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_blocker(struct xdp_md *ctx) {
	void *data_end	= (void *)(long)(ctx->data_end);
	void *data		= (void *)(long)(ctx->data);

	struct ethhdr *eth = data;
	if ((void*)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ipv4 = (void *)(eth + 1);
		if ((void*)(ipv4 + 1) > data_end)
			return XDP_ABORTED;

		__u32 key = bpf_ntohl(ipv4->saddr);
		__u8 *present = bpf_map_lookup_elem(&blocked_ips, &key);
		if (present) {
			bpf_printk("ddos block %pIp4", &ipv4->saddr);
			return XDP_DROP;
		}
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";