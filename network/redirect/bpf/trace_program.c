#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct endpoint_info);
} endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct trace_info);
} trace_root SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} redirect_dir SEC(".maps");

// Test Program
SEC("tc/ingress")
int redirect_test(struct __sk_buff *skb) {
	__u32 key = 0;
	
	struct endpoint_info *info = bpf_map_lookup_elem(&endpoints, &key);
	__u32 *dir = bpf_map_lookup_elem(&redirect_dir, &key);

	if (!info || !dir) {
		return TC_ACT_OK;
	}
	skb->mark |= A_HOST_NAMESPACE_INGRESS;
	__u32 trace_key = skb->mark;
	struct trace_info val = {};

	val.traversed_path = key;
	val.last_seen = bpf_ktime_get_ns();
	bpf_map_update_elem(&trace_root, &key, &val, BPF_ANY);

	return bpf_redirect(info->ifindex, *dir);
}

SEC("tc/ingress")
int redirect_peer_test(struct __sk_buff *skb) {
	__u32 key = 0;

	struct endpoint_info *info = bpf_map_lookup_elem(&endpoints, &key);
	if (!info) {
		return TC_ACT_OK;
	}
	skb->mark |= A_HOST_NAMESPACE_INGRESS;
	__u32 trace_key = skb->mark;
	struct trace_info val = {};

	val.traversed_path = key;
	val.last_seen = bpf_ktime_get_ns();
	bpf_map_update_elem(&trace_root, &key, &val, BPF_ANY);

	return bpf_redirect_peer(info->ifindex, 0);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct trace_info);

} trace_host_ingress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct trace_info);

} trace_peer_ingress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct trace_info);

} trace_host_egress_map SEC(".maps");

SEC("tc/ingress")
int trace_host_ingress(struct __sk_buff *skb) {
	skb->mark |= B_HOST_NAMESPACE_INGRESS;
	__u32 key = skb->mark;
	struct trace_info val = {};

	val.traversed_path = key;
	val.last_seen = bpf_ktime_get_ns();
	bpf_map_update_elem(&trace_host_ingress_map, &key, &val, BPF_ANY);

	return TC_ACT_OK;
}

SEC("tc/ingress")
int trace_peer_ingress(struct __sk_buff *skb) {
	skb->mark |= B_PEER_NAMESPACE_INGRESS;
	__u32 key = skb->mark;
	struct trace_info val = {};

	val.traversed_path = key;
	val.last_seen = bpf_ktime_get_ns();
	bpf_map_update_elem(&trace_peer_ingress_map, &key, &val, BPF_ANY);

	return TC_ACT_OK;
}

SEC("tc/egress")
int trace_host_egress(struct __sk_buff *skb) {
	skb->mark |= B_HOST_NAMESPACE_EGRESS;
	__u32 key = skb->mark;
	struct trace_info val = {};

	val.traversed_path = key;
	val.last_seen = bpf_ktime_get_ns();
	bpf_map_update_elem(&trace_host_egress_map, &key, &val, BPF_ANY);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";