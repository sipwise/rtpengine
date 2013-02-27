#ifndef _UDP_LISTENER_H_
#define _UDP_LISTENER_H_

#include <netinet/in.h>
#include "poller.h"
#include "str.h"


struct poller;
struct obj;

typedef void (*udp_listener_callback_t)(struct obj *p, str *buf, struct sockaddr_in6 *sin, char *addr);

struct udp_listener {
	int fd;
	struct poller *poller;
};

int udp_listener_init(struct udp_listener *, struct poller *p, struct in6_addr ip, u_int16_t port, udp_listener_callback_t, struct obj *);

#endif
