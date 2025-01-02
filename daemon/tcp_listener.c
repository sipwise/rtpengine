#include "tcp_listener.h"

#include <errno.h>

#include "poller.h"
#include "obj.h"
#include "socket.h"
#include "helpers.h"
#include "log.h"
#include "streambuf.h"
#include "media_socket.h"
#include "log_funcs.h"

struct tcp_listener_callback {
	struct obj obj;
	tcp_listener_callback_t func;
	socket_t *ul;
	struct obj *p;
};
struct streambuf_callback {
	struct obj obj;
	streambuf_callback_t newconn_func;
	streambuf_callback_t newdata_func;
	streambuf_callback_t closed_func;
	struct streambuf_listener *listener;
	struct obj *parent;
};

TYPED_DIRECT_FUNCS(tcp_direct_hash, tcp_direct_eq, struct streambuf_stream)
TYPED_GHASHTABLE_IMPL(tcp_streams_ht, tcp_direct_hash, tcp_direct_eq, NULL, NULL)


static void tcp_listener_incoming(int fd, void *p) {
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

		log_info_reset();
	}
}

static void tcp_listener_closed(int fd, void *p) {
	if (!rtpe_shutdown)
		abort();
}

static void __tlc_free(struct tcp_listener_callback *cb) {
	obj_put_o(cb->p);
}

static int tcp_listener_init(socket_t *sock, const endpoint_t *ep,
		tcp_listener_callback_t func, struct obj *obj)
{
	struct poller_item i;
	struct tcp_listener_callback *cb;

	cb = obj_alloc(struct tcp_listener_callback, __tlc_free);
	cb->func = func;
	cb->p = obj_get_o(obj);
	cb->ul = sock;

	if (open_socket(sock, SOCK_STREAM, ep->port, &ep->address))
		goto fail;
	if (sock->family->listen(sock, 5))
		goto fail;

	ZERO(i);
	i.fd = sock->fd;
	i.closed = tcp_listener_closed;
	i.readable = tcp_listener_incoming;
	i.obj = &cb->obj;
	if (!rtpe_poller_add_item(rtpe_control_poller, &i))
		goto fail;

	obj_put(cb);
	return 0;

fail:
	close_socket(sock);
	obj_put(cb);
	return -1;
}

static void streambuf_stream_free(struct streambuf_stream *s) {
	streambuf_destroy(s->inbuf);
	streambuf_destroy(s->outbuf);
	obj_put(s->cb);
	obj_put_o(s->parent);
	free(s->addr);
}

static void streambuf_stream_closed(int fd, void *p) {
	struct streambuf_stream *s = p;

	if (s->sock.fd == -1)
		return;

	if (s->cb->closed_func)
		s->cb->closed_func(s);

	struct streambuf_listener *l = s->listener;
	mutex_lock(&l->lock);
	bool ret = t_hash_table_remove(l->streams, s);
	mutex_unlock(&l->lock);
	rtpe_poller_del_item(rtpe_control_poller, s->sock.fd);
	reset_socket(&s->sock);
	if (ret)
		obj_put(s);
}

static void streambuf_stream_readable(int fd, void *p) {
	struct streambuf_stream *s = p;

	int ret = streambuf_readable(s->inbuf);
	if (ret == -1)
		goto close;
	s->cb->newdata_func(s);
	if (ret == -2)
		goto close;

	release_closed_sockets();

	return;

close:
	streambuf_stream_closed(fd, s);
}

static void streambuf_stream_writeable(int fd, void *p) {
	struct streambuf_stream *s = p;

	if (streambuf_writeable(s->outbuf))
		streambuf_stream_closed(fd, s);
}


static void streambuf_listener_newconn(struct obj *p, socket_t *newsock, char *addr, socket_t *listener_sock) {
	struct streambuf_callback *cb = (void *) p;
	struct streambuf_stream *s;
	struct streambuf_listener *listener;
	struct poller_item i;

	listener = cb->listener;

	s = obj_alloc0(struct streambuf_stream, streambuf_stream_free);
	s->sock = *newsock;
	s->inbuf = streambuf_new(rtpe_control_poller, newsock->fd);
	s->outbuf = streambuf_new(rtpe_control_poller, newsock->fd);
	s->listener = listener;
	s->cb = obj_get(cb);
	s->parent = obj_get_o(cb->parent);
	s->addr = strdup(addr);

	ZERO(i);
	i.fd = newsock->fd;
	i.closed = streambuf_stream_closed;
	i.readable = streambuf_stream_readable;
	i.writeable = streambuf_stream_writeable;
	i.obj = &s->obj;

	if (cb->newconn_func)
		cb->newconn_func(s);

	obj_hold(s);

	mutex_lock(&listener->lock);
	t_hash_table_insert(listener->streams, s, s); // hand over ref
	mutex_unlock(&listener->lock);

	if (!rtpe_poller_add_item(rtpe_control_poller, &i))
		goto fail;

	obj_put(s);

	return;

fail:
	mutex_lock(&listener->lock);
	bool ret = t_hash_table_remove(listener->streams, s);
	mutex_unlock(&listener->lock);

	if (ret)
		obj_put(s);

	obj_put(s);
}

static void __sb_free(struct streambuf_callback *cb) {
	obj_put_o(cb->parent);
}

int streambuf_listener_init(struct streambuf_listener *listener, const endpoint_t *ep,
		streambuf_callback_t newconn_func,
		streambuf_callback_t newdata_func,
		streambuf_callback_t closed_func,
		struct obj *obj)
{
	struct streambuf_callback *cb;

	ZERO(*listener);

	mutex_init(&listener->lock);
	listener->streams = tcp_streams_ht_new();

	cb = obj_alloc(struct streambuf_callback, __sb_free);
	cb->newconn_func = newconn_func;
	cb->newdata_func = newdata_func;
	cb->closed_func = closed_func;
	cb->parent = obj_get_o(obj);
	cb->listener = listener;

	if (tcp_listener_init(&listener->listener, ep, streambuf_listener_newconn, &cb->obj))
		goto fail;

	obj_put(cb);
	return 0;

fail:
	obj_put(cb);
	return -1;
}
void streambuf_listener_shutdown(struct streambuf_listener *listener) {
	if (!listener)
		return;
	rtpe_poller_del_item(rtpe_control_poller, listener->listener.fd);
	reset_socket(&listener->listener);
	t_hash_table_destroy_ptr(&listener->streams);
}

void streambuf_stream_close(struct streambuf_stream *s) {
	streambuf_stream_closed(s->sock.fd, s);
}
void streambuf_stream_shutdown(struct streambuf_stream *s) {
	shutdown(s->sock.fd, SHUT_WR);
}
