#pragma once
#include <linux/types.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#define ID_MAX 64

/*
 * Shared structs used by XDP programs.
 */

/* Decision stored by radius parser for the userspace enforcer */
struct station_auth_decision {
	__u16 assigned_vlan;     
	__u8 auth_state;        
	__u8 enforced_flag;     
	__u32 ingress_port_idx;  
	__u64 last_update_ns;    
};

/* Supplicant Identity key */
struct supplicant_id_key {
	char identity[ID_MAX];
};

/* Mapping id <-> mac from supplicant */
struct supplicant_claim {
	__u8 sta_mac[6];
	__u32 ingress_port_idx;
	__u64 claimed_at_ns;
};

/*
 * Shared maps used by XDP programs.
 */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct supplicant_id_key);
	__type(value, struct supplicant_claim);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME); 
} identity_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u8[6]);
	__type(value, struct station_auth_decision);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME); 
} auth_map SEC(".maps");

/*
 * Helper that ensures [ptr, ptr + size) lies within [data, data_end).
 */
static __always_inline bool range_within(const void *ptr,
					 const void *data_end,
					 __u64 size)
{
	const void *limit;

	if (size == 0)
		return true;

	/* Compute end pointer for the region. */
	limit = (const void *)((const char *)ptr + size);

	/* If limit would exceed data_end, region is not safe. */
	if (limit > data_end)
		return false;

	return true;
}
