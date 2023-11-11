#ifndef _SDP_H_
#define _SDP_H_


#include <glib.h>
#include "str.h"
#include "call.h"
#include "media_socket.h"

/* A structure for SDP arbitrary manipulations on all levels of SDP:
 * session (global), media (audio/video). Works only on `a=` lines.
 */
struct sdp_manipulations {
	GQueue add_commands;
	GHashTable * rem_commands;
	GHashTable * subst_commands;
};

struct ice_candidate;

struct sdp_chopper {
	str *input;
	size_t position;
	GString *output;
	ssize_t offset; // for post-processing using chopper_replace
};

extern const str rtpe_instance_id;

void sdp_init(void);

int sdp_parse(str *body, GQueue *sessions, const sdp_ng_flags *);
int sdp_streams(const GQueue *sessions, GQueue *streams, sdp_ng_flags *);
void sdp_streams_free(GQueue *);
void sdp_free(GQueue *sessions);
int sdp_replace(struct sdp_chopper *, GQueue *, struct call_monologue *, sdp_ng_flags *,
		bool print_other_attrs);
int sdp_is_duplicate(GQueue *sessions);
int sdp_create(str *out, struct call_monologue *, sdp_ng_flags *flags,
		bool print_other_sess_attrs, bool print_other_media_attrs);
const char *sdp_get_sendrecv(struct call_media *media);

int sdp_parse_candidate(struct ice_candidate *cand, const str *s); // returns -1, 0, 1

struct sdp_chopper *sdp_chopper_new(str *input);
void sdp_chopper_destroy(struct sdp_chopper *chop);
void sdp_chopper_destroy_ret(struct sdp_chopper *chop, str *ret);

void sdp_copy_session_attributes(struct call_monologue * src, struct call_monologue * dst);

INLINE int is_trickle_ice_address(const struct endpoint *ep) {
	if (is_addr_unspecified(&ep->address) && ep->port == 9)
		return 1;
	return 0;
}

#endif
