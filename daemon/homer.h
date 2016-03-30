#ifndef __HOMER_H__
#define __HOMER_H__

#include "socket.h"


struct homer_sender;


struct homer_sender *homer_sender_new(const endpoint_t *, int, int);
int homer_send(struct homer_sender *, GString *, const str *, const endpoint_t *, const endpoint_t *,
		const struct timeval *tv);


#endif
