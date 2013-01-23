#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>

int sdp_parse(const char *body, int len, GQueue *sessions);
void sdp_free(GQueue *sessions);

#endif
