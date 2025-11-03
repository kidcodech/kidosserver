// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "include/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc")
int tc_mirror(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u32 *ifindex = bpf_map_lookup_elem(&mirror_ifindex, &key);
	if (ifindex) {
		// Clone and redirect copy to monitoring interface
		bpf_clone_redirect(skb, *ifindex, 0);
	}
	return TC_ACT_OK;
}                             
                             