#ifndef _PACKET_H_
#define _PACKET_H_

#include "types.h"

void ssrc_free(void *p);

void packet_process(stream_t *, unsigned char *, unsigned len);

#endif
