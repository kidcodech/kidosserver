// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "include/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Magic value to detect reinjected packets
#define KIDOS_MAGIC 0x4B494453  // "KIDS" in hex

SEC("xdp")
int xdp_dns_redirect(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;

	if (!parse_eth(&data, &data_end, &eth))
		return XDP_PASS;

	__u16 h_proto = bpf_ntohs(eth->h_proto);
	if (h_proto != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *ip;
	if (!parse_ipv4(&data, &data_end, &ip))
		return XDP_PASS;

	// Check for magic flag in IP identification field
	__u16 magic_check = bpf_htons((__u16)(KIDOS_MAGIC & 0xFFFF));
	if (ip->id == magic_check) {
		// This packet was already processed - pass it through
		return XDP_PASS;
	}

	if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp;
		if (!parse_udp(&data, &data_end, &udp))
			return XDP_PASS;
		if (bpf_ntohs(udp->dest) != DNS_PORT && bpf_ntohs(udp->source) != DNS_PORT)
			return XDP_PASS;
		
		// Redirect DNS UDP packets to userspace for inspection
		return bpf_redirect_map(&xsk_map, 0, 0);
		
	} else if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp;
		if (!parse_tcp(&data, &data_end, &tcp))
			return XDP_PASS;
		if (bpf_ntohs(tcp->dest) != DNS_PORT && bpf_ntohs(tcp->source) != DNS_PORT)
			return XDP_PASS;
		
		return bpf_redirect_map(&xsk_map, 0, 0);
	} else {
		return XDP_PASS;
	}

	return XDP_PASS;
}
