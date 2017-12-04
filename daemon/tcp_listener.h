#ifndef _TCP_LISTENER_H_
#define _TCP_LISTENER_H_

#include "socket.h"
#include "obj.h"


struct poller;
struct obj;

typedef void (*tcp_listener_callback_t)(struct obj *p, socket_t *sock, char *addr, socket_t *);
typedef void (*streambuf_callback_t)(struct obj *p, socket_t *sock, char *addr, socket_t *);

struct streambuf_listener {
	socket_t listener;
	struct poller *poller;
	mutex_t lock;
	GList *streams;
};
struct streambuf_stream {
	struct obj obj;
	socket_t sock;
	struct streambuf *inbuf,
			 *outbuf;

};

int tcp_listener_init(socket_t *, struct poller *p, const endpoint_t *, tcp_listener_callback_t, struct obj *);

#endif
