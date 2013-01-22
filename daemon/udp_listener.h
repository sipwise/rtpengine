#ifndef _UDP_LISTENER_H_
#define _UDP_LISTENER_H_

#include "poller.h"


struct poller;
struct obj;

struct udp_listener {
	int fd;
	struct poller *poller;
};

int udp_listener_init(struct udp_listener *, struct poller *p, struct in6_addr ip, u_int16_t port, poller_func_t, struct obj *);

#endif
