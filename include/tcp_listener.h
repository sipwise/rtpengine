#ifndef _TCP_LISTENER_H_
#define _TCP_LISTENER_H_

#include "socket.h"
#include "obj.h"
#include "helpers.h"
#include "containers.h"

struct obj;
struct streambuf_callback;
struct streambuf_stream;

TYPED_GHASHTABLE_PROTO(tcp_streams_ht, struct streambuf_stream, struct streambuf_stream)


typedef void (*tcp_listener_callback_t)(struct obj *p, socket_t *sock, char *addr, socket_t *);
typedef void (*streambuf_callback_t)(struct streambuf_stream *);

struct streambuf_listener {
	socket_t listener;
	mutex_t lock;
	tcp_streams_ht streams;
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

int streambuf_listener_init(struct streambuf_listener *listener, const endpoint_t *ep,
		streambuf_callback_t newconn_func,
		streambuf_callback_t newdata_func,
		streambuf_callback_t closed_func,
		struct obj *obj);
void streambuf_listener_shutdown(struct streambuf_listener *);

void streambuf_stream_close(struct streambuf_stream *);
void streambuf_stream_shutdown(struct streambuf_stream *);


#endif
