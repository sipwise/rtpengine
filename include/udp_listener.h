#ifndef _UDP_LISTENER_H_
#define _UDP_LISTENER_H_

#include <netinet/in.h>

#include "poller.h"
#include "str.h"
#include "socket.h"
#include "obj.h"
#include "call.h"

#define MAX_UDP_LENGTH 0xffff

struct udp_buffer {
	struct obj obj;
	char buf[MAX_UDP_LENGTH + RTP_BUFFER_TAIL_ROOM + RTP_BUFFER_HEAD_ROOM + 1];
	str str;
	endpoint_t sin;
	sockaddr_t local_addr;
	char addr[64];
	socket_t *listener;
};

typedef void (*udp_listener_callback_t)(struct obj *p, struct udp_buffer *);

int udp_listener_init(socket_t *, const endpoint_t *, udp_listener_callback_t, struct obj *);

#endif
