#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DNS_PORT 53
#define ETH_P_IP 0x0800
#define TC_ACT_OK 0

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} xsk_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} mirror_ifindex SEC(".maps");

static __always_inline bool parse_eth(void **data, void **data_end, struct ethhdr **eth)
{
	*eth = *data;
	if ((void *)(*eth + 1) > *data_end) {
		return false;
	}
	*data = *eth + 1;
	return true;
}

static __always_inline bool parse_ipv4(void **data, void **data_end, struct iphdr **ip)
{
	*ip = *data;
	if ((void *)(*ip + 1) > *data_end) {
		return false;
	}
	__u32 off = (__u32)(*ip)->ihl * 4;
	if ((void *)*ip + off > *data_end) {
		return false;
	}
	*data = (void *)*ip + off;
	return true;
}

static __always_inline bool parse_udp(void **data, void **data_end, struct udphdr **udp)
{
	*udp = *data;
	if ((void *)(*udp + 1) > *data_end) {
		return false;
	}
	*data = *udp + 1;
	return true;
}

static __always_inline bool parse_tcp(void **data, void **data_end, struct tcphdr **tcp)
{
	*tcp = *data;
	if ((void *)(*tcp + 1) > *data_end) {
		return false;
	}
	__u32 off = (__u32)(*tcp)->doff * 4;
	if ((void *)*tcp + off > *data_end) {
		return false;
	}
	*data = (void *)*tcp + off;
	return true;
}

#endif
