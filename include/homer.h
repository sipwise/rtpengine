#ifndef __HOMER_H__
#define __HOMER_H__

#include "socket.h"


void homer_sender_init(const endpoint_t *, int, int);
int homer_send(GString *, const str *, const endpoint_t *, const endpoint_t *,
		const struct timeval *tv);
int has_homer();


#endif
