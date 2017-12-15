#include "udp_listener.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "poller.h"
#include "aux.h"
#include "str.h"
#include "log.h"
#include "obj.h"
#include "socket.h"

struct udp_listener_callback {
	struct obj obj;
	udp_listener_callback_t func;
	socket_t *ul;
	struct obj *p;
};

static void udp_listener_closed(int fd, void *p, uintptr_t x) {
	abort();
}

static void udp_listener_incoming(int fd, void *p, uintptr_t x) {
	struct udp_listener_callback *cb = p;
	int len;
	char buf[0x10000];
	char addr[64];
	str str;
	socket_t *listener;
	endpoint_t sin;

	str.s = buf;
	listener = cb->ul;

	for (;;) {
		len = socket_recvfrom(listener, buf, sizeof(buf)-1, &sin);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EWOULDBLOCK && errno != EAGAIN)
				ilog(LOG_WARNING, "Error reading from UDP socket");
			return;
		}

		buf[len] = '\0';
		endpoint_print(&sin, addr, sizeof(addr));

		str.len = len;
		cb->func(cb->p, &str, &sin, addr, listener);
	}
}

int udp_listener_init(socket_t *sock, struct poller *p, const endpoint_t *ep,
		udp_listener_callback_t func, struct obj *obj)
{
	struct poller_item i;
	struct udp_listener_callback *cb;

	cb = obj_alloc("udp_listener_callback", sizeof(*cb), NULL);
	cb->func = func;
	cb->p = obj_get_o(obj);
	cb->ul = sock;

	if (open_socket(sock, SOCK_DGRAM, ep->port, &ep->address))
		goto fail;

	ZERO(i);
	i.fd = sock->fd;
	i.closed = udp_listener_closed;
	i.readable = udp_listener_incoming;
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
