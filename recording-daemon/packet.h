#ifndef _PACKET_H_
#define _PACKET_H_

#include "types.h"

void ssrc_close(ssrc_t *s);
void ssrc_free(void *p);

void packet_process(stream_t *, unsigned char *, unsigned len);

void ssrc_tls_state(ssrc_t *ssrc);

#endif
