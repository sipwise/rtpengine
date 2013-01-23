#ifndef _SDP_H_
#define _SDP_H_

#include <glib.h>

int sdp_parse(char *body, int len, GQueue *sessions);
int sdp_streams(const GQueue *sessions, GQueue *streams);
void sdp_free(GQueue *sessions);

#endif
