#ifndef __HOMER_H__
#define __HOMER_H__

#include "socket.h"

#define PROTO_RTCP_JSON     0x05
#define PROTO_NG     0x3d

void homer_sender_init(const endpoint_t *, int, int);
int homer_send(GString *, const str *, const endpoint_t *, const endpoint_t *,
		const struct timeval *, int);
int has_homer(void);

#endif