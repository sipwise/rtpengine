#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>
#include "str.h"
#include "call.h"


struct sdp_ng_flags {
	int desired_family[2];
	str received_from_family;
	str received_from_address;
	str media_address;
	str transport_protocol_str;
	enum transport_protocol transport_protocol;
	struct in6_addr parsed_received_from;
	struct in6_addr parsed_media_address;
	enum stream_direction directions[2];
	int asymmetric:1,
	    symmetric:1,
	    trust_address:1,
	    replace_origin:1,
	    replace_sess_conn:1,
	    ice_remove:1,
	    ice_force:1;
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
int sdp_streams(const GQueue *sessions, GQueue *streams, GHashTable *, struct sdp_ng_flags *);
void sdp_free(GQueue *sessions);
int sdp_replace(struct sdp_chopper *, GQueue *, struct call *, enum call_opmode, struct sdp_ng_flags *, GHashTable *);

struct sdp_chopper *sdp_chopper_new(str *input);
void sdp_chopper_destroy(struct sdp_chopper *chop);

#endif
