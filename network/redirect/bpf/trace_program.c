#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_packet.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct endpoint_info);
} endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} test_select SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct trace_info);

} trace SEC(".maps");

// Test Program
// Veth A Host Ingress Hook Attach
SEC("tc/ingress")
int redirect(struct __sk_buff *skb) {
	__u32 key = 0;
	
	struct endpoint_info *info = bpf_map_lookup_elem(&endpoints, &key);
	__u32 *test = bpf_map_lookup_elem(&test_select, &key);

	if (!info || !test) {
		return TC_ACT_OK;
	}
	skb->cb[0] |= A_HOST_NAMESPACE_INGRESS;
	__u32 trace_key = skb->cb[0];
	struct trace_info val = {};

	if (skb->cb[0] & A_PEER_NAMESPACE_EGRESS) {
		val.traversed_path = trace_key;
		val.last_seen = bpf_ktime_get_ns();
		bpf_map_update_elem(&trace, &trace_key, &val, BPF_ANY);

		if (*test == 0) {
			return bpf_redirect(info->ifindex, 0);
		} else {
			bpf_printk("pkt type %d", skb->pkt_type);
			int ret = bpf_skb_change_type(skb, PACKET_HOST);
			if (ret < 0) {
				return TC_ACT_OK;
			}
			return bpf_redirect_peer(info->ifindex, 0);
		}
	}

	return TC_ACT_OK;
}

// Veth A Peer Egress Hook Attach
SEC("tc/egress")
int tr_peer_out(struct __sk_buff *skb) {
	skb->cb[0] |= A_PEER_NAMESPACE_EGRESS;
	__u32 key = skb->cb[0];
	struct trace_info val = {};

	val.traversed_path = key;
	val.last_seen = bpf_ktime_get_ns();
	bpf_map_update_elem(&trace, &key, &val, BPF_ANY);
}

// Veth B Peer Ingress Hook Attach
SEC("tc/ingress")
int tr_peer_in(struct __sk_buff *skb) {
	skb->cb[0] |= B_PEER_NAMESPACE_INGRESS;
	__u32 key = skb->cb[0];
	struct trace_info val = {};

	if (skb->cb[0] & A_PEER_NAMESPACE_EGRESS) {
		val.traversed_path = key;
		val.last_seen = bpf_ktime_get_ns();
		bpf_map_update_elem(&trace, &key, &val, BPF_ANY);
	}

	return TC_ACT_OK;
}

// Veth B Host Ingress Hook Attach
SEC("tc/ingress")
int tr_host_in(struct __sk_buff *skb) {
	__u32 key = 1;

	struct endpoint_info *info = bpf_map_lookup_elem(&endpoints, &key);
	if (!info) {
		return TC_ACT_OK;
	}

	return bpf_redirect(info->ifindex, 0);
}

// Veth B Host Egress Hook Attach
SEC("tc/egress")
int tr_host_out(struct __sk_buff *skb) {
	skb->cb[0] |= B_HOST_NAMESPACE_EGRESS;
	__u32 key = skb->cb[0];
	struct trace_info val = {};

	if (skb->cb[0] & A_PEER_NAMESPACE_EGRESS) {
		val.traversed_path = key;
		val.last_seen = bpf_ktime_get_ns();
		bpf_map_update_elem(&trace, &key, &val, BPF_ANY);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";