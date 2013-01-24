#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>
#include "str.h"
#include "call.h"

int sdp_parse(str *body, GQueue *sessions);
int sdp_streams(const GQueue *sessions, GQueue *streams);
void sdp_free(GQueue *sessions);
str *sdp_replace(str *body, GQueue *sessions, struct call *call, int num, int off);

#endif
