#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>
#include "str.h"

int sdp_parse(str *body, GQueue *sessions);
int sdp_streams(const GQueue *sessions, GQueue *streams);
void sdp_free(GQueue *sessions);

#endif
