#ifndef _UDP_LISTENER_H_
#define _UDP_LISTENER_H_

#include <netinet/in.h>
#include "poller.h"
#include "str.h"
#include "socket.h"


struct poller;
struct obj;

typedef void (*udp_listener_callback_t)(struct obj *p, str *buf, const endpoint_t *ep, char *addr, socket_t *);

int udp_listener_init(socket_t *, struct poller *p, const endpoint_t *, udp_listener_callback_t, struct obj *);

#endif
