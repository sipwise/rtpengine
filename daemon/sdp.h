#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>
#include "str.h"
#include "call.h"


struct sdp_ng_flags {
	int desired_family[2];
	str received_from_family;
	str received_from_address;
	int asymmetric:1,
	    symmetric:1,
	    trust_address:1,
	    replace_origin:1,
	    replace_sess_conn:1;
};

int sdp_parse(str *body, GQueue *sessions);
int sdp_streams(const GQueue *sessions, GQueue *streams);
void sdp_free(GQueue *sessions);
str *sdp_replace(str *body, GQueue *sessions, struct call *call, int num, enum call_opmode, struct sdp_ng_flags *);

#endif
