// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "xdp_common.h"

#define ETHER_TYPE_EAPOL 0x888E
#define EAPOL_PKT_EAP 0
#define EAPOL_PKT_LOGOFF 2

#define EAP_CODE_RESPONSE 2
#define EAP_TYPE_IDENTITY 1

struct eapol_frame_hdr {
	__u8 ver, type;
	__be16 len;
} __attribute__((packed));

struct eap_msg_hdr {
	__u8 code, id;
	__be16 len;
} __attribute__((packed));

struct eap_identity_type {
	__u8 type; /* 1 = Identity */
} __attribute__((packed));

/* ------------------------------------------------------------------------- */
/* Helper functions                                                           */
/* ------------------------------------------------------------------------- */


/* Ensure Ethernet header is present and EtherType is EAPOL */
static __always_inline struct ethhdr *eth_get_eapol(void *data, void *end)
{
	struct ethhdr *eth = data;
	if (!range_within(eth, end, sizeof(*eth)))
		return NULL;

	if (eth->h_proto != bpf_htons(ETHER_TYPE_EAPOL))
		return NULL;

	return eth;
}

/* Handle EAPOL-Logoff: mark station as deauthorized in auth_map */
static __always_inline void process_eapol_logoff(struct ethhdr *eth)
{
	struct station_auth_decision *dec =
	    bpf_map_lookup_elem(&auth_map, eth->h_source);
	if (dec) {
		dec->auth_state = 0;
		dec->last_update_ns = bpf_ktime_get_ns();
		bpf_map_update_elem(&auth_map, eth->h_source, dec, BPF_ANY);
	}
}

/*
 * Try to parse an EAP Identity Response:
 * Returns true if identity extracted into out_id.
 */
static __always_inline bool eap_extract_identity_response(
	void *end, struct eapol_frame_hdr *eol, struct supplicant_id_key *out_id)
{
	if (eol->type != EAPOL_PKT_EAP)
		return false;

	struct eap_msg_hdr *eap = (void *)(eol + 1);
	if (!range_within(eap, end, sizeof(*eap)))
		return false;

	/* Only EAP Response */
	if (eap->code != EAP_CODE_RESPONSE)
		return false;

	struct eap_identity_type *eid = (void *)(eap + 1);
	if (!range_within(eid, end, sizeof(*eid)))
		return false;

	/* Only Identity type */
	if (eid->type != EAP_TYPE_IDENTITY)
		return false;

	__u16 eap_len = bpf_ntohs(eap->len);
	int id_len = (int)eap_len - (int)sizeof(*eap) - 1;
	if (id_len <= 0)
		return false;

	unsigned char *id_ptr = (unsigned char *)(eid + 1);

	/* Bound identity length */
	id_len = id_len >= ID_MAX ? ID_MAX - 1 : id_len;

	struct supplicant_id_key key = {};
	bpf_core_read_str(key.identity, id_len + 1, id_ptr);

	*out_id = key;
	return true;
}

/*
 * Update identity_map
 * Keep first claimant for 10s to avoid rapid flipping across ports.
 */
static __always_inline void identity_claim_update(struct xdp_md *ctx,
						  struct ethhdr *eth,
						  struct supplicant_id_key *id)
{
	__u64 now = bpf_ktime_get_ns();
	__u64 threshold = 10ULL * 1000000000ULL;
	struct supplicant_claim *old = bpf_map_lookup_elem(&identity_map, id);
	if (old) {
		if (now - old->claimed_at_ns < threshold)
			return;
	}

	struct supplicant_claim claim = {};
	claim.ingress_port_idx = (__u32)ctx->ingress_ifindex;
	claim.claimed_at_ns = now;

	/*copy MAC address*/
	for (int i = 0; i < ETH_ALEN; i++) {
		claim.sta_mac[i] = eth->h_source[i];
	}

	bpf_map_update_elem(&identity_map, id, &claim, BPF_ANY);
}

/* ------------------------------------------------------------------------- */
/* XDP entrypoint                                                            */
/* ------------------------------------------------------------------------- */

SEC("xdp")
int xdp_eap_parse(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	/* 1) Parse only EAPOL frames */
	struct ethhdr *eth = eth_get_eapol(data, end);
	if (!eth)
		return XDP_PASS;

	/* 2) Parse EAPOL header */
	struct eapol_frame_hdr *eol = (void *)(eth + 1);
	if (!range_within(eol, end, sizeof(*eol)))
		return XDP_PASS;

	/* 3) Logoff => revoke */
	if (eol->type == EAPOL_PKT_LOGOFF) {
		process_eapol_logoff(eth);
		return XDP_PASS;
	}

	/* 4) Identity Response => cache identity->(mac,ifindex) */
	struct supplicant_id_key id = {};
	if (!eap_extract_identity_response(end, eol, &id))
		return XDP_PASS;

	identity_claim_update(ctx, eth, &id);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
