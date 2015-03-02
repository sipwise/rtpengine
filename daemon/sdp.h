#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>
#include "str.h"
#include "call.h"
#include "media_socket.h"


struct sdp_ng_flags {
	enum call_opmode opmode;
	str received_from_family;
	str received_from_address;
	str media_address;
	str transport_protocol_str;
	str address_family_str;
	const struct transport_protocol *transport_protocol;
	sockaddr_t parsed_received_from;
	sockaddr_t parsed_media_address;
	str direction[2];
	sockfamily_t *address_family;
	int tos;
	int asymmetric:1,
	    trust_address:1,
	    replace_origin:1,
	    replace_sess_conn:1,
	    ice_remove:1,
	    ice_force:1,
	    ice_force_relay:1,
	    rtcp_mux_offer:1,
	    rtcp_mux_demux:1,
	    rtcp_mux_accept:1,
	    rtcp_mux_reject:1,
	    strict_source:1,
	    media_handover:1,
	    dtls_passive:1,
	    dtls_off:1,
	    sdes_off:1,
	    sdes_unencrypted_srtp:1,
	    sdes_unencrypted_srtcp:1,
	    sdes_unauthenticated_srtp:1,
	    sdes_encrypted_srtp:1,
	    sdes_encrypted_srtcp:1,
	    sdes_authenticated_srtp:1;
};

struct sdp_chopper {
	str *input;
	int position;
	GStringChunk *chunk;
	GArray *iov;
	int iov_num;
	int str_len;
};

void sdp_init(void);

int sdp_parse(str *body, GQueue *sessions);
int sdp_streams(const GQueue *sessions, GQueue *streams, struct sdp_ng_flags *);
void sdp_free(GQueue *sessions);
int sdp_replace(struct sdp_chopper *, GQueue *, struct call_monologue *, struct sdp_ng_flags *);

struct sdp_chopper *sdp_chopper_new(str *input);
void sdp_chopper_destroy(struct sdp_chopper *chop);

INLINE int is_trickle_ice_address(const struct endpoint *ep) {
	if (is_addr_unspecified(&ep->address) && ep->port == 9)
		return 1;
	return 0;
}

#endif
