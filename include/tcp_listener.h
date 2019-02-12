#ifndef _TCP_LISTENER_H_
#define _TCP_LISTENER_H_

#include "socket.h"
#include "obj.h"
#include "aux.h"


struct poller;
struct obj;
struct streambuf_callback;
struct streambuf_stream;

typedef void (*tcp_listener_callback_t)(struct obj *p, socket_t *sock, char *addr, socket_t *);
typedef void (*streambuf_callback_t)(struct streambuf_stream *);

struct streambuf_listener {
	socket_t listener;
	struct poller *poller;
	mutex_t lock;
	GHashTable *streams;
};
struct streambuf_stream {
	struct obj obj;
	socket_t sock;
	struct streambuf_listener *listener;
	struct streambuf_callback *cb;
	struct obj *parent;
	char *addr;
	struct streambuf *inbuf,
			 *outbuf;

};

int tcp_listener_init(socket_t *, struct poller *p, const endpoint_t *, tcp_listener_callback_t, struct obj *);

int streambuf_listener_init(struct streambuf_listener *listener, struct poller *p, const endpoint_t *ep,
		streambuf_callback_t newconn_func,
		streambuf_callback_t newdata_func,
		streambuf_callback_t closed_func,
		streambuf_callback_t timer_func,
		struct obj *obj);

void streambuf_stream_close(struct streambuf_stream *);
void streambuf_stream_shutdown(struct streambuf_stream *);


#endif
