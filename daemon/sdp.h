#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>

GQueue *sdp_parse(const char *body, int len, GQueue *streams);

#endif
