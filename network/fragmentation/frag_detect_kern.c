// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#define __always_inline		inline __attribute__((always_inline))

#define IP_MF		0x2000	// More Fragments
#define IP_OFFSET	0x1FFF	// Fragment offset mask

static __always_inline _Bool ip_is_fragment(const struct iphdr *ip) {
	return (ip->frag_off & __constant_htons(IP_MF | IP_OFFSET)) != 0;
}

SEC("classifier")
int frag_detect(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto == __constant_htons(ETH_P_IP)) {
		struct iphdr *ip = (struct iphdr *)(eth + 1);

		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;

		// IPv4 Fragmentation 확인 (MF 비트 또는 Fragment Offset이 설정된 경우)
		if (ip_is_fragment(ip)) {
			bpf_printk("IPv4 Fragmentation detected: src=%pI4, dst=%pI4\n", &ip->saddr, &ip->daddr);
		}
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";