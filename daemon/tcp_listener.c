#include "tcp_listener.h"

#include <errno.h>

#include "poller.h"
#include "obj.h"
#include "socket.h"
#include "aux.h"
#include "log.h"
#include "streambuf.h"

struct tcp_listener_callback {
	struct obj obj;
	tcp_listener_callback_t func;
	socket_t *ul;
	struct obj *p;
};
struct streambuf_callback {
	struct obj obj;
	tcp_listener_callback_t newconn_func;
	streambuf_callback_t newdata_func;
	struct streambuf_listener *listener;
	struct obj *p;
};

static void tcp_listener_incoming(int fd, void *p, uintptr_t x) {
	struct tcp_listener_callback *cb = p;
	int ret;
	char addr[64];
	socket_t *listener;
	socket_t newsock;

	listener = cb->ul;

	for (;;) {
		ret = listener->family->accept(listener, &newsock);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno != EWOULDBLOCK && errno != EAGAIN)
				ilog(LOG_WARNING, "Error accepting TCP connection: %s", strerror(errno));
			return;
		}
		nonblock(newsock.fd);

		endpoint_print(&newsock.remote, addr, sizeof(addr));

		cb->func(cb->p, &newsock, addr, listener);
	}
}

static void tcp_listener_closed(int fd, void *p, uintptr_t u) {
	abort();
}

int tcp_listener_init(socket_t *sock, struct poller *p, const endpoint_t *ep,
		tcp_listener_callback_t func, struct obj *obj)
{
	struct poller_item i;
	struct tcp_listener_callback *cb;

	cb = obj_alloc("tcp_listener_callback", sizeof(*cb), NULL);
	cb->func = func;
	cb->p = obj_get_o(obj);
	cb->ul = sock;

	if (open_socket(sock, SOCK_STREAM, ep->port, &ep->address))
		goto fail;

	ipv6only(sock->fd, 1);

	ZERO(i);
	i.fd = sock->fd;
	i.closed = tcp_listener_closed;
	i.readable = tcp_listener_incoming;
	i.obj = &cb->obj;
	if (poller_add_item(p, &i))
		goto fail;

	return 0;

fail:
	close_socket(sock);
	obj_put_o(obj);
	obj_put(cb);
	return -1;
}

static void streambuf_stream_free(void *p) {
	struct streambuf_stream *s = p;
	close_socket(&s->sock);
	streambuf_destroy(s->inbuf);
	streambuf_destroy(s->outbuf);
}

static void streambuf_stream_closed(int fd, void *p, uintptr_t u) {
	// XXX
}

static void streambuf_stream_timer(int fd, void *p, uintptr_t u) {
	// XXX
}


static void streambuf_stream_readable(int fd, void *p, uintptr_t u) {
	struct streambuf_stream *s = p;
	//char *line;
	//int ret;

	//mutex_lock(&s->lock);

	if (streambuf_readable(s->inbuf))
		goto close;
	// XXX

	//mutex_unlock(&s->lock);
	return;

close:
	//mutex_unlock(&s->lock);
//close_nolock:
	streambuf_stream_closed(fd, s, 0);
}

static void streambuf_stream_writeable(int fd, void *p, uintptr_t u) {
	struct streambuf_stream *s = p;

	if (streambuf_writeable(s->outbuf))
		streambuf_stream_closed(fd, s, 0);
}


static void streambuf_listener_newconn(struct obj *p, socket_t *newsock, char *addr, socket_t *listener_sock) {
	struct streambuf_callback *cb = (void *) p;
	struct streambuf_stream *s;
	struct streambuf_listener *listener;
	struct poller_item i;

	listener = cb->listener;

	s = obj_alloc0("streambuf_stream", sizeof(*s), streambuf_stream_free);
	s->sock = *newsock;
	s->inbuf = streambuf_new(listener->poller, newsock->fd);
	s->outbuf = streambuf_new(listener->poller, newsock->fd);

	if (cb->newconn_func)
		cb->newconn_func(cb->p, newsock, addr, listener_sock);

	mutex_lock(&listener->lock);
	listener->streams = g_list_prepend(listener->streams, s);
	mutex_unlock(&listener->lock);

	ZERO(i);
	i.fd = newsock->fd;
	i.closed = streambuf_stream_closed;
	i.readable = streambuf_stream_readable;
	i.writeable = streambuf_stream_writeable;
	i.timer = streambuf_stream_timer;
	i.obj = &s->obj;

	if (poller_add_item(listener->poller, &i))
		goto fail;

	return;

fail:
	obj_put(s);
}

int streambuf_listener_init(struct streambuf_listener *listener, struct poller *p, const endpoint_t *ep,
		tcp_listener_callback_t newconn_func,
		streambuf_callback_t newdata_func, struct obj *obj)
{
	struct streambuf_callback *cb;

	ZERO(*listener);

	mutex_init(&listener->lock);
	listener->poller = p;

	cb = obj_alloc("streambuf_callback", sizeof(*cb), NULL);
	cb->newconn_func = newconn_func;
	cb->newdata_func = newdata_func;
	cb->p = obj_get_o(obj);
	cb->listener = listener;

	if (tcp_listener_init(&listener->listener, p, ep, streambuf_listener_newconn, &cb->obj))
		goto fail;

	return 0;

fail:
	obj_put(cb);
	return -1;
}
