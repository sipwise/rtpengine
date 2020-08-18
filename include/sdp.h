#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>
#include "str.h"
#include "call.h"
#include "media_socket.h"


struct ice_candidate;

struct sdp_chopper {
	str *input;
	size_t position;
	GString *output;
	ssize_t offset; // for post-processing using chopper_replace
};

extern const str rtpe_instance_id;

void sdp_init(void);

int sdp_parse(str *body, GQueue *sessions, const struct sdp_ng_flags *);
int sdp_streams(const GQueue *sessions, GQueue *streams, struct sdp_ng_flags *);
void sdp_streams_free(GQueue *);
void sdp_free(GQueue *sessions);
int sdp_replace(struct sdp_chopper *, GQueue *, struct call_monologue *, struct sdp_ng_flags *);
int sdp_is_duplicate(GQueue *sessions);
int sdp_create(str *out, struct call_monologue *, struct sdp_ng_flags *flags);

int sdp_parse_candidate(struct ice_candidate *cand, const str *s); // returns -1, 0, 1

struct sdp_chopper *sdp_chopper_new(str *input);
void sdp_chopper_destroy(struct sdp_chopper *chop);
void sdp_chopper_destroy_ret(struct sdp_chopper *chop, str *ret);

INLINE int is_trickle_ice_address(const struct endpoint *ep) {
	if (is_addr_unspecified(&ep->address) && ep->port == 9)
		return 1;
	return 0;
}

#endif
