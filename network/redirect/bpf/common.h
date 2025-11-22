#pragma once

#include <linux/bpf.h>

const unsigned int A_PEER_NAMESPACE_EGRESS = 1U << 0;
const unsigned int A_HOST_NAMESPACE_INGRESS	= 1U << 1;
const unsigned int B_HOST_NAMESPACE_EGRESS	= 1U << 2;
const unsigned int B_PEER_NAMESPACE_INGRESS	= 1U << 3;


struct trace_info {
	__u32 traversed_path;
	__u32 pad;
	__u64 last_seen;
} __attribute__((aligned(8)));

struct endpoint_info {
	__u32 ifindex;
	__u32 pad;
};